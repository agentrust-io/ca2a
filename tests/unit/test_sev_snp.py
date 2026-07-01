"""Tests for SEV-SNP report parsing and offline appraisal.

The certificate-chain verification is exercised against the real AMD Milan root
chain (tests/fixtures/sev_snp/amd_milan_cert_chain.pem). The report-signature
path is exercised end to end with a synthetic VCEK chain and a synthetic report,
because a genuine report + VCEK pair requires real SEV-SNP hardware.
"""

from __future__ import annotations

import struct
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA384
from cryptography.x509.oid import NameOID

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.sev_snp import REPORT_SIZE, SIG_OFFSET, SevSnpProvider, SevSnpReport
from ca2a_verify.sev_snp import verify_cert_chain, verify_sev_snp_report

FIXTURE = Path(__file__).parent.parent / "fixtures" / "sev_snp" / "amd_milan_cert_chain.pem"


def _cert(subject: str, issuer: str, subject_key: ec.EllipticCurvePrivateKey,
          issuer_key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    now = datetime.now(UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(issuer_key, SHA384())
    )


def _make_report(vcek_key: ec.EllipticCurvePrivateKey, *, measurement: bytes,
                 report_data: bytes, algo: int = 1) -> bytes:
    body = bytearray(SIG_OFFSET)
    struct.pack_into("<IIQ", body, 0, 2, 1, 0)  # version, guest_svn, policy
    struct.pack_into("<I", body, 0x30, 0)       # vmpl
    struct.pack_into("<I", body, 0x34, algo)    # signature_algo
    body[0x50 : 0x50 + len(report_data)] = report_data
    body[0x90 : 0x90 + len(measurement)] = measurement
    der = vcek_key.sign(bytes(body), ec.ECDSA(SHA384()))
    r, s = decode_dss_signature(der)
    full = bytearray(REPORT_SIZE)
    full[:SIG_OFFSET] = body
    full[SIG_OFFSET : SIG_OFFSET + 72] = r.to_bytes(72, "little")
    full[SIG_OFFSET + 72 : SIG_OFFSET + 144] = s.to_bytes(72, "little")
    return bytes(full)


@pytest.fixture
def synthetic_chain() -> dict[str, object]:
    ark_key = ec.generate_private_key(ec.SECP384R1())
    ask_key = ec.generate_private_key(ec.SECP384R1())
    vcek_key = ec.generate_private_key(ec.SECP384R1())
    ark = _cert("test-ARK", "test-ARK", ark_key, ark_key)
    ask = _cert("test-ASK", "test-ARK", ask_key, ark_key)
    vcek = _cert("test-VCEK", "test-ASK", vcek_key, ask_key)
    return {"vcek_key": vcek_key, "chain": [vcek, ask, ark], "root": ark}


def test_synthetic_report_verifies(synthetic_chain: dict) -> None:
    m = b"\x11" * 48
    rd = b"\x22" * 64
    report = _make_report(synthetic_chain["vcek_key"], measurement=m, report_data=rd)
    parsed = verify_sev_snp_report(
        report, synthetic_chain["chain"], trusted_roots=[synthetic_chain["root"]],
        expected_measurement=m, expected_report_data=rd,
    )
    assert parsed.measurement == m
    assert parsed.report_data == rd


def test_tampered_report_fails(synthetic_chain: dict) -> None:
    report = bytearray(_make_report(synthetic_chain["vcek_key"], measurement=b"\x11" * 48,
                                    report_data=b"\x22" * 64))
    report[0x90] ^= 0xFF  # flip a measurement byte after signing
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(bytes(report), synthetic_chain["chain"],
                              trusted_roots=[synthetic_chain["root"]])


def test_wrong_expected_measurement_fails(synthetic_chain: dict) -> None:
    report = _make_report(synthetic_chain["vcek_key"], measurement=b"\x11" * 48,
                          report_data=b"\x22" * 64)
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(report, synthetic_chain["chain"],
                              trusted_roots=[synthetic_chain["root"]],
                              expected_measurement=b"\x99" * 48)


def test_untrusted_root_fails(synthetic_chain: dict) -> None:
    other_root = _cert("other", "other", ec.generate_private_key(ec.SECP384R1()),
                       ec.generate_private_key(ec.SECP384R1()))
    report = _make_report(synthetic_chain["vcek_key"], measurement=b"\x11" * 48,
                          report_data=b"\x22" * 64)
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(report, synthetic_chain["chain"], trusted_roots=[other_root])


def test_broken_chain_fails(synthetic_chain: dict) -> None:
    # VCEK not issued by the presented intermediate.
    stray_key = ec.generate_private_key(ec.SECP384R1())
    stray = _cert("stray", "stray", stray_key, stray_key)
    report = _make_report(synthetic_chain["vcek_key"], measurement=b"\x11" * 48,
                          report_data=b"\x22" * 64)
    chain = [synthetic_chain["chain"][0], stray, synthetic_chain["root"]]
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(report, chain, trusted_roots=[synthetic_chain["root"]])


def test_short_report_rejected() -> None:
    with pytest.raises(AttestationFailed):
        SevSnpReport.parse(b"\x00" * 100)


def test_unsupported_algo_rejected(synthetic_chain: dict) -> None:
    report = _make_report(synthetic_chain["vcek_key"], measurement=b"\x11" * 48,
                          report_data=b"\x22" * 64, algo=0)
    with pytest.raises(AttestationFailed):
        verify_sev_snp_report(report, synthetic_chain["chain"],
                              trusted_roots=[synthetic_chain["root"]])


def test_real_amd_root_chain_verifies() -> None:
    # Real-vector check: the ASK is validly issued by the self-signed ARK root
    # fetched from AMD KDS. This exercises the chain-verification code against
    # the genuine AMD trust anchor (RSA), not a synthetic one.
    certs = x509.load_pem_x509_certificates(FIXTURE.read_bytes())
    ask = next(c for c in certs if "ASK" in c.subject.rfc4514_string() or "SEV" in c.subject.rfc4514_string())
    ark = next(c for c in certs if c.subject == c.issuer)
    verify_cert_chain([ask, ark], trusted_roots=[ark])


def test_real_amd_untrusted_root_rejected() -> None:
    certs = x509.load_pem_x509_certificates(FIXTURE.read_bytes())
    ark = next(c for c in certs if c.subject == c.issuer)
    ask = next(c for c in certs if c.subject != c.issuer)
    other = _cert("other", "other", ec.generate_private_key(ec.SECP384R1()),
                  ec.generate_private_key(ec.SECP384R1()))
    with pytest.raises(AttestationFailed):
        verify_cert_chain([ask, ark], trusted_roots=[other])


def test_provider_detect_and_attest() -> None:
    assert SevSnpProvider.detect() is False  # no /dev/sev-guest in this environment
    with pytest.raises(AttestationUnsupported):
        SevSnpProvider().attest("deadbeef", "nonce")
