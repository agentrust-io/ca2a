"""Tests for TPM 2.0 quote parsing and offline appraisal.

TPM attestation keys chain to per-vendor EK roots, so there is no single real
root to validate against; these tests build a synthetic self-consistent quote
and AK chain. The parsing follows the TPMS_ATTEST layout.
"""

from __future__ import annotations

import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.tpm import (
    TPM_GENERATED_VALUE,
    TPM_ST_ATTEST_QUOTE,
    TpmProvider,
    TpmQuote,
)
from ca2a_verify.tpm import verify_tpm_quote
from tests.unit.conftest import make_ec_cert


def build_attest(*, qualifying_data: bytes, pcr_digest: bytes,
                 magic: int = TPM_GENERATED_VALUE, attest_type: int = TPM_ST_ATTEST_QUOTE) -> bytes:
    out = bytearray()
    out += struct.pack(">I", magic)
    out += struct.pack(">H", attest_type)
    out += struct.pack(">H", 0)  # qualifiedSigner TPM2B_NAME, empty
    out += struct.pack(">H", len(qualifying_data)) + qualifying_data  # extraData
    out += b"\x00" * 17  # clockInfo
    out += b"\x00" * 8   # firmwareVersion
    # TPML_PCR_SELECTION: 1 selection, SHA-256, 3 select bytes
    out += struct.pack(">I", 1) + struct.pack(">H", 0x000B) + bytes([3]) + b"\x03\x00\x00"
    out += struct.pack(">H", len(pcr_digest)) + pcr_digest
    return bytes(out)


def _ak_chain():
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = make_ec_cert("vendor-root", "vendor-root", root_key, root_key)
    ak_key = ec.generate_private_key(ec.SECP256R1())
    ak = make_ec_cert("AK", "vendor-root", ak_key, root_key)
    return ak_key, [ak, root], root


def _signed(ak_key: ec.EllipticCurvePrivateKey, attest: bytes) -> bytes:
    return ak_key.sign(attest, ec.ECDSA(SHA256()))


def test_valid_quote_verifies() -> None:
    ak_key, chain, root = _ak_chain()
    nonce, pcr = b"nonce-1234", b"\x11" * 32
    attest = build_attest(qualifying_data=nonce, pcr_digest=pcr)
    q = verify_tpm_quote(attest, _signed(ak_key, attest), chain, trusted_roots=[root],
                         expected_pcr_digest=pcr, expected_qualifying_data=nonce)
    assert q.pcr_digest == pcr
    assert q.qualifying_data == nonce


def test_wrong_pcr_digest_fails() -> None:
    ak_key, chain, root = _ak_chain()
    attest = build_attest(qualifying_data=b"n", pcr_digest=b"\x11" * 32)
    with pytest.raises(AttestationFailed):
        verify_tpm_quote(attest, _signed(ak_key, attest), chain, trusted_roots=[root],
                         expected_pcr_digest=b"\x99" * 32)


def test_wrong_nonce_fails() -> None:
    ak_key, chain, root = _ak_chain()
    attest = build_attest(qualifying_data=b"real", pcr_digest=b"\x11" * 32)
    with pytest.raises(AttestationFailed):
        verify_tpm_quote(attest, _signed(ak_key, attest), chain, trusted_roots=[root],
                         expected_qualifying_data=b"expected")


def test_tampered_attest_fails() -> None:
    ak_key, chain, root = _ak_chain()
    attest = bytearray(build_attest(qualifying_data=b"n", pcr_digest=b"\x11" * 32))
    sig = _signed(ak_key, bytes(attest))
    attest[-1] ^= 0xFF  # change PCR digest after signing
    with pytest.raises(AttestationFailed):
        verify_tpm_quote(bytes(attest), sig, chain, trusted_roots=[root])


def test_untrusted_root_fails() -> None:
    ak_key, chain, _ = _ak_chain()
    attest = build_attest(qualifying_data=b"n", pcr_digest=b"\x11" * 32)
    stranger = make_ec_cert("s", "s", ec.generate_private_key(ec.SECP256R1()),
                            ec.generate_private_key(ec.SECP256R1()))
    with pytest.raises(AttestationFailed):
        verify_tpm_quote(attest, _signed(ak_key, attest), chain, trusted_roots=[stranger])


def test_bad_magic_rejected() -> None:
    ak_key, chain, root = _ak_chain()
    attest = build_attest(qualifying_data=b"n", pcr_digest=b"\x11" * 32, magic=0x00000000)
    with pytest.raises(AttestationFailed):
        verify_tpm_quote(attest, _signed(ak_key, attest), chain, trusted_roots=[root])


def test_wrong_attest_type_rejected() -> None:
    ak_key, chain, root = _ak_chain()
    attest = build_attest(qualifying_data=b"n", pcr_digest=b"\x11" * 32, attest_type=0x8017)
    with pytest.raises(AttestationFailed):
        verify_tpm_quote(attest, _signed(ak_key, attest), chain, trusted_roots=[root])


def test_short_quote_rejected() -> None:
    with pytest.raises(AttestationFailed):
        TpmQuote.parse(b"\x00\x00")


def test_provider_detect_and_attest() -> None:
    assert TpmProvider.detect() is False
    with pytest.raises(AttestationUnsupported):
        TpmProvider().attest("deadbeef", "nonce")
