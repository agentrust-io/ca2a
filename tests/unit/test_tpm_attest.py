"""Tests for the TPM collector and for verifying a peer's TPM report.

Two halves:

- the collector's checks and its TPM interaction shape, driven with a fake ESAPI
  context so they run without a TPM. The shapes asserted here are the ones that
  were wrong on real hardware in cmcp: ``pcr_read`` returns a ``TPML_DIGEST`` whose
  digests are iterated once, and ``TPM2_NV_Read`` must be chunked.
- report verification end to end over a synthetic quote and AK chain, including
  that the key-and-nonce binding is what actually gates it.

Synthetic vectors, not hardware. What was validated on hardware is recorded in
docs/testing/hardware-validation.md.
"""

from __future__ import annotations

import hashlib
import struct
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256, SHA384
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import NameOID

from ca2a_runtime.attestation import ChannelOffer, verify_offer
from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.base import AttestationReport
from ca2a_runtime.tee.tpm import (
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    TpmProvider,
    TpmQuote,
    tpm_qualifying_data,
)
from ca2a_runtime.transport import wire
from ca2a_verify.tpm import (
    parse_tpmt_signature,
    tpm_verifier,
    verify_tpm_report,
)
from tests.unit.conftest import make_ec_cert
from tests.unit.test_tpm import build_attest

_ALG_RSASSA = 0x0014
_ALG_ECDSA = 0x0018
_ALG_SHA256 = 0x000B

PUBLIC_KEY = "aa" * 32
NONCE = "deadbeef"


# ── qualifying data: the signed binding ───────────────────────────────────────


def test_qualifying_data_is_32_bytes() -> None:
    assert len(tpm_qualifying_data(PUBLIC_KEY, NONCE)) == 32


def test_qualifying_data_changes_with_either_input() -> None:
    base = tpm_qualifying_data(PUBLIC_KEY, NONCE)
    assert tpm_qualifying_data("bb" * 32, NONCE) != base
    assert tpm_qualifying_data(PUBLIC_KEY, "cafe") != base


@pytest.mark.parametrize(
    ("a", "b"),
    [
        (("ab", "cd"), ("abc", "d")),
        # A delimiter-joined encoding collides here: both sides join to "a|b|c".
        # nonce is an arbitrary caller-supplied string, so this is reachable.
        (("a|b", "c"), ("a", "b|c")),
        (("", "ab"), ("ab", "")),
    ],
)
def test_qualifying_data_is_unambiguous(a: tuple[str, str], b: tuple[str, str]) -> None:
    """No two distinct (key, nonce) pairs may commit the same bytes.

    Otherwise a peer shifts the split and binds a key other than the one it
    appears to be offering.
    """
    assert tpm_qualifying_data(*a) != tpm_qualifying_data(*b)


def test_qualifying_data_is_domain_separated() -> None:
    """A bare sha256 of the same payload must not collide with the binding."""
    naive = hashlib.sha256(PUBLIC_KEY.encode() + b"|" + NONCE.encode()).digest()
    assert tpm_qualifying_data(PUBLIC_KEY, NONCE) != naive


# ── TPMT_SIGNATURE, the format agent-manifest does not model ──────────────────


def _tpmt_ecdsa(signature_der: bytes) -> bytes:
    r, s = decode_dss_signature(signature_der)
    r_b = r.to_bytes(32, "big")
    s_b = s.to_bytes(32, "big")
    return (
        struct.pack(">HH", _ALG_ECDSA, _ALG_SHA256)
        + struct.pack(">H", len(r_b))
        + r_b
        + struct.pack(">H", len(s_b))
        + s_b
    )


def _tpmt_rsassa(signature: bytes) -> bytes:
    return (
        struct.pack(">HH", _ALG_RSASSA, _ALG_SHA256) + struct.pack(">H", len(signature)) + signature
    )


def test_parse_tpmt_signature_round_trips_ecdsa() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    der = key.sign(b"message", ec.ECDSA(SHA256()))
    parsed = parse_tpmt_signature(_tpmt_ecdsa(der))
    assert parsed.sig_alg == _ALG_ECDSA
    # Re-encoded as DER, so cryptography verifies it directly.
    key.public_key().verify(parsed.signature, b"message", ec.ECDSA(SHA256()))


def test_parse_tpmt_signature_round_trips_rsassa() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    sig = key.sign(b"message", padding.PKCS1v15(), SHA256())
    parsed = parse_tpmt_signature(_tpmt_rsassa(sig))
    assert parsed.sig_alg == _ALG_RSASSA
    assert parsed.signature == sig


def test_parse_tpmt_signature_rejects_truncated() -> None:
    key = ec.generate_private_key(ec.SECP256R1())
    blob = _tpmt_ecdsa(key.sign(b"m", ec.ECDSA(SHA256())))
    with pytest.raises(AttestationFailed):
        parse_tpmt_signature(blob[:-4])


def test_parse_tpmt_signature_rejects_unsupported_algorithm() -> None:
    with pytest.raises(AttestationFailed, match="unsupported"):
        parse_tpmt_signature(struct.pack(">HH", 0x0011, _ALG_SHA256) + b"\x00" * 8)


def test_parse_tpmt_signature_rejects_short_blob() -> None:
    with pytest.raises(AttestationFailed):
        parse_tpmt_signature(b"\x00\x14")


# ── synthetic AK chains and reports ───────────────────────────────────────────


def _ec_ak_chain() -> tuple[ec.EllipticCurvePrivateKey, bytes, bytes]:
    """Return (ak_key, chain_pem_leaf_first, root_pem)."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = make_ec_cert("vendor-root", "vendor-root", root_key, root_key)
    ak_key = ec.generate_private_key(ec.SECP256R1())
    ak = make_ec_cert("AK", "vendor-root", ak_key, root_key)
    return (
        ak_key,
        ak.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM),
        (root.public_bytes(Encoding.PEM)),
    )


def _rsa_ak_chain() -> tuple[rsa.RSAPrivateKey, bytes, bytes]:
    """An RSA AK under an EC root: the shape Azure's vTPM actually presents."""
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = make_ec_cert("vendor-root", "vendor-root", root_key, root_key)
    ak_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(UTC)
    ak = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AK")]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "vendor-root")]))
        .public_key(ak_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .sign(root_key, SHA384())
    )
    return (
        ak_key,
        ak.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM),
        (root.public_bytes(Encoding.PEM)),
    )


def _report(
    *,
    public_key: str = PUBLIC_KEY,
    nonce: str = NONCE,
    pcr_digest: bytes = b"\x11" * 32,
    qualifying_data: bytes | None = None,
    measurement: str | None = None,
    rsa_ak: bool = False,
) -> tuple[AttestationReport, bytes]:
    """Build a signed synthetic TPM report. Returns (report, root_pem)."""
    if qualifying_data is None:
        qualifying_data = tpm_qualifying_data(public_key, nonce)
    attest = build_attest(qualifying_data=qualifying_data, pcr_digest=pcr_digest)

    if rsa_ak:
        rsa_key, chain_pem, root_pem = _rsa_ak_chain()
        sig_blob = _tpmt_rsassa(rsa_key.sign(attest, padding.PKCS1v15(), SHA256()))
        ak_pem = rsa_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    else:
        ec_key, chain_pem, root_pem = _ec_ak_chain()
        sig_blob = _tpmt_ecdsa(ec_key.sign(attest, ec.ECDSA(SHA256())))
        ak_pem = ec_key.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)

    report = AttestationReport(
        platform="tpm",
        measurement=measurement or ("sha256:" + pcr_digest.hex()),
        public_key=public_key,
        nonce=nonce,
        raw_evidence=attest,
        quote_signature=sig_blob,
        attestation_key_pem=ak_pem,
        attestation_key_chain_pem=chain_pem,
    )
    return report, root_pem


# ── report verification ───────────────────────────────────────────────────────


def test_valid_report_verifies_and_returns_the_signed_measurement() -> None:
    report, root_pem = _report()
    measurement = verify_tpm_report(report, NONCE, trusted_roots_pem=root_pem)
    assert measurement == "sha256:" + ("11" * 32)


def test_valid_rsa_report_verifies() -> None:
    """RSASSA is what the Azure vTPM signs with, so it must verify too."""
    report, root_pem = _report(rsa_ak=True)
    assert verify_tpm_report(report, NONCE, trusted_roots_pem=root_pem)


def test_substituted_public_key_is_rejected() -> None:
    """The whole point of the binding: editing the offered key breaks the quote.

    Before the key was committed into extraData, this field was an unsigned
    assertion and a peer could swap it after quoting.
    """
    report, root_pem = _report()
    swapped = AttestationReport(**{**report.__dict__, "public_key": "bb" * 32})
    with pytest.raises(AttestationFailed):
        verify_tpm_report(swapped, NONCE, trusted_roots_pem=root_pem)


def test_substituted_nonce_is_rejected() -> None:
    report, root_pem = _report()
    swapped = AttestationReport(**{**report.__dict__, "nonce": "0bad"})
    with pytest.raises(AttestationFailed):
        verify_tpm_report(swapped, "0bad", trusted_roots_pem=root_pem)


def test_stale_nonce_is_rejected() -> None:
    report, root_pem = _report()
    with pytest.raises(AttestationFailed, match="nonce"):
        verify_tpm_report(report, "a-different-nonce", trusted_roots_pem=root_pem)


def test_measurement_disagreeing_with_the_quote_is_rejected() -> None:
    """A report may not claim a measurement the quote does not carry."""
    report, root_pem = _report(measurement="sha256:" + ("99" * 32))
    with pytest.raises(AttestationFailed, match="not the one the TPM signed"):
        verify_tpm_report(report, NONCE, trusted_roots_pem=root_pem)


def test_report_without_evidence_is_rejected() -> None:
    report, root_pem = _report()
    bare = AttestationReport(
        platform="tpm",
        measurement=report.measurement,
        public_key=report.public_key,
        nonce=report.nonce,
    )
    with pytest.raises(AttestationFailed, match="no TPM quote"):
        verify_tpm_report(bare, NONCE, trusted_roots_pem=root_pem)


def test_report_without_a_chain_is_rejected() -> None:
    """A transient-key quote verifies as a signature but proves no provenance."""
    report, root_pem = _report()
    chainless = AttestationReport(**{**report.__dict__, "attestation_key_chain_pem": None})
    with pytest.raises(AttestationFailed, match="chain"):
        verify_tpm_report(chainless, NONCE, trusted_roots_pem=root_pem)


def test_no_trusted_root_is_refused() -> None:
    """Verifying against no anchor would accept any self-consistent chain."""
    report, _ = _report()
    with pytest.raises(AttestationFailed, match="no trusted root"):
        verify_tpm_report(report, NONCE, trusted_roots_pem=b"")


def test_untrusted_root_is_rejected() -> None:
    report, _ = _report()
    stranger_key = ec.generate_private_key(ec.SECP256R1())
    stranger = make_ec_cert("stranger", "stranger", stranger_key, stranger_key)
    with pytest.raises(AttestationFailed):
        verify_tpm_report(report, NONCE, trusted_roots_pem=stranger.public_bytes(Encoding.PEM))


def test_tampered_attest_is_rejected() -> None:
    report, root_pem = _report()
    tampered = bytearray(report.raw_evidence or b"")
    tampered[-1] ^= 0xFF
    bad = AttestationReport(**{**report.__dict__, "raw_evidence": bytes(tampered)})
    with pytest.raises(AttestationFailed):
        verify_tpm_report(bad, NONCE, trusted_roots_pem=root_pem)


# ── the handshake reaches hardware assurance ──────────────────────────────────


def test_tpm_verifier_reaches_hardware_assurance_in_verify_offer() -> None:
    """End to end: a TPM offer gets assurance="hardware", not "none"."""
    report, root_pem = _report()
    offer = ChannelOffer(channel_public_key=PUBLIC_KEY, report=report)
    peer = verify_offer(offer, expected_nonce=NONCE, verifier=tpm_verifier(root_pem))
    assert peer.assurance == "hardware"
    assert peer.public_key == PUBLIC_KEY
    assert peer.measurement == "sha256:" + ("11" * 32)


def test_tpm_offer_without_a_verifier_still_fails_closed() -> None:
    report, _ = _report()
    offer = ChannelOffer(channel_public_key=PUBLIC_KEY, report=report)
    with pytest.raises(AttestationFailed, match="requires a hardware verifier"):
        verify_offer(offer, expected_nonce=NONCE)


def test_tpm_offer_survives_the_reference_transports_wire_codec() -> None:
    """A hardware report must still reach assurance="hardware" after the exact
    round trip the reference HTTP server/client run it through.

    ``wire.serialize_channel_offer``/``parse_channel_offer`` is what
    ``ca2a_runtime.transport.server`` sends on ``GET /.well-known/ca2a/channel``
    and what ``ca2a_runtime.transport.client.handshake`` parses back. Encoding
    only the claim fields (platform/measurement/public_key/nonce) and dropping
    the evidence fields would make every hardware-attested offer unverifiable
    over that transport, even though the provider produced a genuine quote.
    """
    report, root_pem = _report()
    offer = ChannelOffer(channel_public_key=PUBLIC_KEY, report=report)

    wire_body = wire.serialize_channel_offer(offer)
    received = wire.parse_channel_offer(wire_body)

    peer = verify_offer(received, expected_nonce=NONCE, verifier=tpm_verifier(root_pem))
    assert peer.assurance == "hardware"
    assert peer.measurement == "sha256:" + ("11" * 32)


# ── collector checks ──────────────────────────────────────────────────────────


def _quote(qualifying_data: bytes, pcr_digest: bytes, **kw: int) -> TpmQuote:
    return TpmQuote.parse(
        build_attest(qualifying_data=qualifying_data, pcr_digest=pcr_digest, **kw)
    )


def test_check_quote_accepts_a_consistent_quote() -> None:
    qd = tpm_qualifying_data(PUBLIC_KEY, NONCE)
    digest = b"\x22" * 32
    TpmProvider._check_quote(_quote(qd, digest), qd, digest)


def test_check_quote_rejects_a_pcr_selection_mismatch() -> None:
    """The cross-check that stops a report describing PCRs that were not measured."""
    qd = tpm_qualifying_data(PUBLIC_KEY, NONCE)
    with pytest.raises(AttestationFailed, match="does not match the PCRs that were read"):
        TpmProvider._check_quote(_quote(qd, b"\x22" * 32), qd, b"\x33" * 32)


def test_check_quote_rejects_a_binding_mismatch() -> None:
    digest = b"\x22" * 32
    with pytest.raises(AttestationFailed, match="key and nonce binding"):
        TpmProvider._check_quote(_quote(b"other", digest), b"expected", digest)


def test_check_quote_rejects_non_tpm_magic() -> None:
    qd, digest = b"qd", b"\x22" * 32
    with pytest.raises(AttestationFailed, match="not TPM-generated"):
        TpmProvider._check_quote(_quote(qd, digest, magic=0x00000000), qd, digest)


def test_check_quote_rejects_a_non_quote_attestation() -> None:
    qd, digest = b"qd", b"\x22" * 32
    with pytest.raises(AttestationFailed, match="not a quote"):
        TpmProvider._check_quote(_quote(qd, digest, attest_type=0x8017), qd, digest)
    assert TPM_GENERATED_VALUE and TPM_ST_ATTEST_QUOTE  # constants stay exported


# ── the TPM interaction shapes that were wrong on hardware ────────────────────


class _FakeSelection:
    @staticmethod
    def parse(_spec: str) -> str:
        return "selection"


def test_read_pcrs_iterates_the_digest_list_once() -> None:
    """``pcr_read`` returns a TPML_DIGEST: its digests are the PCR values.

    Treating them as banks and descending a second level yields bytes of a
    structure and silently corrupts the measurement, which is the bug this asserts
    against.
    """
    pcrs = [bytes([i]) * 32 for i in range(8)]
    ectx = SimpleNamespace(pcr_read=lambda _sel: (None, None, SimpleNamespace(digests=pcrs)))
    assert TpmProvider._read_pcrs(ectx, _FakeSelection) == hashlib.sha256(b"".join(pcrs)).digest()


def test_read_pcrs_refuses_a_short_read() -> None:
    ectx = SimpleNamespace(
        pcr_read=lambda _sel: (None, None, SimpleNamespace(digests=[b"\x01" * 32] * 3))
    )
    with pytest.raises(AttestationFailed, match="fewer PCRs"):
        TpmProvider._read_pcrs(ectx, _FakeSelection)


def test_read_pcrs_does_not_fall_back_to_sha1() -> None:
    """A report labelled sha256 must measure the SHA-256 bank, or fail."""

    def _boom(_sel: str) -> None:
        raise RuntimeError("no sha256 bank")

    ectx = SimpleNamespace(pcr_read=_boom)
    with pytest.raises(AttestationUnsupported, match="SHA-256 PCR bank"):
        TpmProvider._read_pcrs(ectx, _FakeSelection)


class _FakeNvCtx:
    """An ESAPI stand-in that enforces the real TPM2_NV_Read size bound."""

    def __init__(self, data: bytes, buffer_max: int) -> None:
        self.data = data
        self.buffer_max = buffer_max
        self.reads: list[tuple[int, int]] = []

    def tr_from_tpmpublic(self, index: int) -> str:
        return f"handle-{index:#x}"

    def nv_read_public(self, _handle: str) -> tuple[SimpleNamespace, None]:
        return SimpleNamespace(nvPublic=SimpleNamespace(dataSize=len(self.data))), None

    def get_capability(self, _cap: int, prop: int, _count: int) -> tuple[object, object]:
        props = SimpleNamespace(
            data=SimpleNamespace(
                tpmProperties=[SimpleNamespace(property=prop, value=self.buffer_max)]
            )
        )
        return (None, props)

    def nv_read(self, _handle: str, size: int, offset: int) -> bytes:
        if size > self.buffer_max:
            raise RuntimeError("TPM_RC_VALUE: size exceeds TPM2_PT_NV_BUFFER_MAX")
        self.reads.append((size, offset))
        return self.data[offset : offset + size]


def test_read_nv_chunks_a_certificate_larger_than_the_buffer_max() -> None:
    """A 1596-byte AK certificate cannot be fetched in one TPM2_NV_Read.

    Azure reports TPM2_PT_NV_BUFFER_MAX of 1024, so a single full-size read fails
    with TPM_RC_VALUE even though the index is plainly readable.
    """
    cert = bytes(range(256)) * 6 + b"tail"  # 1540 bytes
    ectx = _FakeNvCtx(cert, buffer_max=1024)
    assert TpmProvider._read_nv(ectx, 0x01C101D0) == cert
    assert len(ectx.reads) > 1
    assert all(size <= 1024 for size, _ in ectx.reads)


def test_read_nv_returns_none_for_an_undefined_index() -> None:
    class _Undefined:
        def tr_from_tpmpublic(self, _index: int) -> str:
            raise RuntimeError("TPM_RC_HANDLE")

    assert TpmProvider._read_nv(_Undefined(), 0x01C00002) is None


# ── detect and attest agree ───────────────────────────────────────────────────


def test_detect_is_false_without_a_tpm(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ca2a_runtime.tee.tpm.sys.platform", "linux")
    monkeypatch.setattr("ca2a_runtime.tee.tpm.Path.exists", lambda _self: False)
    assert TpmProvider.detect() is False


def test_detect_is_false_without_the_bindings(monkeypatch: pytest.MonkeyPatch) -> None:
    """A TPM with no tpm2-pytss cannot attest, so detect must not claim it can."""
    monkeypatch.setattr("ca2a_runtime.tee.tpm.sys.platform", "linux")
    monkeypatch.setattr("ca2a_runtime.tee.tpm.Path.exists", lambda _self: True)
    monkeypatch.setattr("ca2a_runtime.tee.tpm._tpm2_pytss_available", lambda: False)
    assert TpmProvider.detect() is False


def test_detect_is_true_when_attest_can_run(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ca2a_runtime.tee.tpm.sys.platform", "linux")
    monkeypatch.setattr("ca2a_runtime.tee.tpm.Path.exists", lambda _self: True)
    monkeypatch.setattr("ca2a_runtime.tee.tpm._tpm2_pytss_available", lambda: True)
    assert TpmProvider.detect() is True


def test_attest_does_not_claim_a_tpm_is_absent_when_one_is_present(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The misleading error from issue #73: "no TPM present" on a host with a TPM."""
    monkeypatch.setattr("ca2a_runtime.tee.tpm.sys.platform", "linux")
    monkeypatch.setattr("ca2a_runtime.tee.tpm.Path.exists", lambda _self: True)
    monkeypatch.setattr("ca2a_runtime.tee.tpm._tpm2_pytss_available", lambda: False)
    with pytest.raises(AttestationUnsupported) as excinfo:
        TpmProvider().attest(PUBLIC_KEY, NONCE)
    assert "tpm2-pytss" in str(excinfo.value)
    assert "is present" in (excinfo.value.detail or "")


def test_attest_reports_a_missing_device_as_a_missing_device(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("ca2a_runtime.tee.tpm.sys.platform", "linux")
    monkeypatch.setattr("ca2a_runtime.tee.tpm.Path.exists", lambda _self: False)
    with pytest.raises(AttestationUnsupported, match="requires a TPM device"):
        TpmProvider().attest(PUBLIC_KEY, NONCE)
