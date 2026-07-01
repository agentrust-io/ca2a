"""Tests for Intel TDX quote parsing and offline appraisal.

The certificate-chain verification is exercised against the real Intel SGX Root
CA (tests/fixtures/tdx/intel_sgx_root_ca.pem). The multi-level signature path
(PCK -> QE report -> attestation key -> quote) is exercised end to end with a
synthetic self-consistent quote, because a genuine quote requires a TDX guest.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.tdx import (
    MRTD_OFFSET,
    QE_REPORT_DATA_OFFSET,
    SIGNED_LEN,
    TdxProvider,
    TdxQuote,
)
from ca2a_verify.sev_snp import verify_cert_chain
from ca2a_verify.tdx import verify_tdx_quote
from tests.unit.conftest import make_ec_cert

FIXTURE = Path(__file__).parent.parent / "fixtures" / "tdx" / "intel_sgx_root_ca.pem"


def _raw_p256(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)[1:]


def _sig_rs(key: ec.EllipticCurvePrivateKey, message: bytes) -> bytes:
    r, s = decode_dss_signature(key.sign(message, ec.ECDSA(SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def build_quote(mrtd: bytes, report_data: bytes, *, root_key, root_name="test-intel-root"):
    """Build a synthetic, self-consistent TDX v4 quote and its trusted root."""
    root = make_ec_cert(root_name, root_name, root_key, root_key)
    pck_key = ec.generate_private_key(ec.SECP256R1())
    pck = make_ec_cert("PCK", root_name, pck_key, root_key)
    att_key = ec.generate_private_key(ec.SECP256R1())
    att_raw = _raw_p256(att_key)

    header = struct.pack("<HHI", 4, 2, 0x81) + b"\x00" * 40  # 48 bytes
    td_report = bytearray(584)
    td_report[MRTD_OFFSET - 48 : MRTD_OFFSET - 48 + 48] = mrtd
    td_report[520:520 + 64] = report_data
    signed = header + bytes(td_report)

    quote_sig = _sig_rs(att_key, signed)

    qe_auth = b"qe-auth"
    qe_report = bytearray(384)
    binding = hashlib.sha256(att_raw + qe_auth).digest()
    qe_report[QE_REPORT_DATA_OFFSET : QE_REPORT_DATA_OFFSET + 32] = binding
    qe_report_sig = _sig_rs(pck_key, bytes(qe_report))

    pem = pck.public_bytes(Encoding.PEM) + root.public_bytes(Encoding.PEM)
    sig = (quote_sig + att_raw + bytes(qe_report) + qe_report_sig
           + struct.pack("<H", len(qe_auth)) + qe_auth
           + struct.pack("<HI", 5, len(pem)) + pem)
    quote = signed + struct.pack("<I", len(sig)) + sig
    return quote, root


@pytest.fixture
def quote_and_root():
    root_key = ec.generate_private_key(ec.SECP256R1())
    mrtd = b"\x11" * 48
    rd = b"\x22" * 64
    quote, root = build_quote(mrtd, rd, root_key=root_key)
    return {"quote": quote, "root": root, "mrtd": mrtd, "rd": rd}


def test_valid_quote_verifies(quote_and_root) -> None:
    q = verify_tdx_quote(
        quote_and_root["quote"], trusted_roots=[quote_and_root["root"]],
        expected_mrtd=quote_and_root["mrtd"], expected_report_data=quote_and_root["rd"],
    )
    assert q.measurement == quote_and_root["mrtd"]
    assert q.tee_type == 0x81


def test_tampered_mrtd_fails(quote_and_root) -> None:
    q = bytearray(quote_and_root["quote"])
    q[MRTD_OFFSET] ^= 0xFF  # flip an MRTD byte after signing -> quote sig breaks
    with pytest.raises(AttestationFailed):
        verify_tdx_quote(bytes(q), trusted_roots=[quote_and_root["root"]])


def test_wrong_expected_mrtd_fails(quote_and_root) -> None:
    with pytest.raises(AttestationFailed):
        verify_tdx_quote(quote_and_root["quote"], trusted_roots=[quote_and_root["root"]],
                         expected_mrtd=b"\x99" * 48)


def test_untrusted_root_fails(quote_and_root) -> None:
    stranger = make_ec_cert("x", "x", ec.generate_private_key(ec.SECP256R1()),
                            ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(AttestationFailed):
        verify_tdx_quote(quote_and_root["quote"], trusted_roots=[stranger])


def test_qe_report_tampered_fails(quote_and_root) -> None:
    # Corrupt the attestation-key binding in the QE report data.
    q = bytearray(quote_and_root["quote"])
    # Locate the QE report data: signed body + 4 + quote_sig(64) + att_key(64) + qe_report.
    base = SIGNED_LEN + 4 + 64 + 64
    q[base + QE_REPORT_DATA_OFFSET] ^= 0xFF
    with pytest.raises(AttestationFailed):
        verify_tdx_quote(bytes(q), trusted_roots=[quote_and_root["root"]])


def test_non_tdx_tee_type_rejected(quote_and_root) -> None:
    q = bytearray(quote_and_root["quote"])
    struct.pack_into("<I", q, 4, 0x00)  # tee_type = SGX, not TDX
    with pytest.raises(AttestationFailed):
        verify_tdx_quote(bytes(q), trusted_roots=[quote_and_root["root"]])


def test_short_quote_rejected() -> None:
    with pytest.raises(AttestationFailed):
        TdxQuote.parse(b"\x00" * 100)


def test_real_intel_root_accepted_and_stranger_rejected() -> None:
    intel_root = x509.load_pem_x509_certificates(FIXTURE.read_bytes())[0]
    # The genuine, self-signed Intel SGX Root CA is accepted as its own trust anchor.
    verify_cert_chain([intel_root], trusted_roots=[intel_root])
    stranger = make_ec_cert("x", "x", ec.generate_private_key(ec.SECP256R1()),
                            ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(AttestationFailed):
        verify_cert_chain([intel_root], trusted_roots=[stranger])


def test_provider_detect_and_attest() -> None:
    assert TdxProvider.detect() is False
    with pytest.raises(AttestationUnsupported):
        TdxProvider().attest("deadbeef", "nonce")
