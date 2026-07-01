"""Offline appraisal of a TPM 2.0 quote.

Appraisal is fail-closed:

1. The AK certificate chain is verified up to a trusted (vendor-supplied) root.
2. The AK signature over the ``TPMS_ATTEST`` blob is verified (ECDSA or RSA).
3. The structure is confirmed to be a TPM-generated quote (magic and type).
4. The qualifying data (the verifier's nonce) and the PCR digest (the platform
   measurement) are checked against expected values.

There is no single published TPM root; the caller supplies the vendor roots it
trusts. TPM AK signature schemes vary; this verifier supports ECDSA (over
SHA-256) and RSA PKCS#1 v1.5 (SHA-256) attestation keys.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.hashes import SHA256

from ca2a_runtime.errors import AttestationFailed
from ca2a_runtime.tee.tpm import TPM_GENERATED_VALUE, TPM_ST_ATTEST_QUOTE, TpmQuote
from ca2a_verify.sev_snp import verify_cert_chain

__all__ = ["verify_tpm_quote"]


def _verify_ak_signature(ak: x509.Certificate, signature: bytes, message: bytes) -> None:
    key = ak.public_key()
    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, message, padding.PKCS1v15(), SHA256())
        else:
            raise AttestationFailed("unsupported AK public-key type for TPM quote")
    except InvalidSignature as exc:
        raise AttestationFailed("TPM quote signature failed to verify") from exc


def verify_tpm_quote(
    attest: bytes,
    signature: bytes,
    ak_chain: list[x509.Certificate],
    *,
    trusted_roots: list[x509.Certificate],
    expected_pcr_digest: bytes | None = None,
    expected_qualifying_data: bytes | None = None,
) -> TpmQuote:
    """Appraise a TPM 2.0 quote offline. Raises AttestationFailed on any failure."""
    quote = TpmQuote.parse(attest)

    if quote.magic != TPM_GENERATED_VALUE:
        raise AttestationFailed(
            "TPMS_ATTEST magic is not TPM_GENERATED", detail=f"magic={quote.magic:#x}"
        )
    if quote.attest_type != TPM_ST_ATTEST_QUOTE:
        raise AttestationFailed(
            "attestation is not a quote", detail=f"type={quote.attest_type:#x}"
        )

    verify_cert_chain(ak_chain, trusted_roots)
    _verify_ak_signature(ak_chain[0], signature, attest)

    if expected_qualifying_data is not None and quote.qualifying_data != expected_qualifying_data:
        raise AttestationFailed("qualifying data (nonce) does not match the expected value")
    if expected_pcr_digest is not None and quote.pcr_digest != expected_pcr_digest:
        raise AttestationFailed("PCR digest does not match the expected measurement")

    return quote
