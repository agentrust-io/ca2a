"""Offline appraisal of an Intel TDX quote (DCAP, ECDSA-256).

Appraisal chains four fail-closed checks:

1. Certificate chain: the PCK is verified up to a trusted Intel root.
2. Quoting Enclave report: the QE report is signed by the PCK.
3. Attestation key binding: the QE report data commits to the attestation key
   (SHA-256 of the attestation key and the QE auth data), so the key that signs
   the quote is the one the QE vouched for.
4. Quote signature: the attestation key signs the quote body, and the launch
   measurement (MRTD) and report data match expected values.

Any missing or mismatched step raises AttestationFailed. The verifier needs no
hardware. Byte offsets follow the Intel DCAP Quote v4 layout; end-to-end
validation against a real hardware quote requires a TDX guest and remains open.
"""

from __future__ import annotations

import hashlib

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256

from ca2a_runtime.errors import AttestationFailed
from ca2a_runtime.tee.tdx import (
    QE_REPORT_DATA_OFFSET,
    TEE_TYPE_TDX,
    TdxQuote,
)
from ca2a_verify.sev_snp import verify_cert_chain

__all__ = ["verify_tdx_quote"]


def _p256_key(raw_xy: bytes) -> ec.EllipticCurvePublicKey:
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw_xy)


def _verify_ecdsa(public_key: ec.EllipticCurvePublicKey, sig_rs: bytes, message: bytes) -> None:
    r = int.from_bytes(sig_rs[:32], "big")
    s = int.from_bytes(sig_rs[32:64], "big")
    public_key.verify(encode_dss_signature(r, s), message, ec.ECDSA(SHA256()))


def verify_tdx_quote(
    quote_bytes: bytes,
    *,
    trusted_roots: list[x509.Certificate],
    expected_mrtd: bytes | None = None,
    expected_report_data: bytes | None = None,
) -> TdxQuote:
    """Appraise a TDX quote offline. Raises AttestationFailed on any failure."""
    quote = TdxQuote.parse(quote_bytes)

    if quote.tee_type != TEE_TYPE_TDX:
        raise AttestationFailed(
            "quote is not a TDX quote", detail=f"tee_type={quote.tee_type:#x}"
        )

    # 1. PCK chain to a trusted Intel root.
    verify_cert_chain(quote.pck_chain, trusted_roots)

    pck_key = quote.pck_chain[0].public_key()
    if not isinstance(pck_key, ec.EllipticCurvePublicKey):
        raise AttestationFailed("PCK does not carry an elliptic-curve public key")

    # 2. QE report signed by the PCK.
    try:
        _verify_ecdsa(pck_key, quote.qe_report_signature, quote.qe_report)
    except (InvalidSignature, ValueError) as exc:
        raise AttestationFailed("QE report signature failed to verify") from exc

    # 3. Attestation key binding: the QE report data commits to the attestation key.
    expected_binding = hashlib.sha256(quote.attestation_key + quote.qe_auth_data).digest()
    qe_report_data = quote.qe_report[QE_REPORT_DATA_OFFSET : QE_REPORT_DATA_OFFSET + 64]
    if qe_report_data[:32] != expected_binding:
        raise AttestationFailed("attestation key is not the one the QE report vouched for")

    # 4. Quote signature by the attestation key, over the quote body.
    try:
        _verify_ecdsa(_p256_key(quote.attestation_key), quote.quote_signature, quote.signed_body)
    except (InvalidSignature, ValueError) as exc:
        raise AttestationFailed("TDX quote signature failed to verify") from exc

    if expected_mrtd is not None and quote.measurement != expected_mrtd:
        raise AttestationFailed(
            "MRTD does not match the expected value", detail=f"got {quote.measurement.hex()}"
        )
    if expected_report_data is not None and quote.report_data != expected_report_data:
        raise AttestationFailed("report data does not match the expected binding")

    return quote
