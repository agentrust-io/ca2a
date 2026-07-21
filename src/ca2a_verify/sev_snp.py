"""Offline appraisal of an AMD SEV-SNP attestation report.

Appraisal has three parts, all fail-closed:

1. Certificate chain: the VCEK is verified up to a trusted AMD root (ARK) via
   ARK (self-signed) -> ASK -> VCEK. The chain-verification path is exercised
   against the real AMD root chain in the test suite.
2. Report signature: the ECDSA-P384 report signature is verified against the
   VCEK public key over the report body.
3. Binding: the launch measurement and the report data (which carries the
   runtime key and nonce) are checked against expected values.

Any missing or mismatched step raises AttestationFailed. The verifier needs no
hardware.
"""

from __future__ import annotations

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA384

from ca2a_runtime.errors import AttestationFailed
from ca2a_runtime.tee.sev_snp import SEV_GUEST_DEVICE, SIG_ALGO_ECDSA_P384_SHA384, SevSnpReport

__all__ = ["SEV_GUEST_DEVICE", "verify_cert_chain", "verify_sev_snp_report"]


def verify_cert_chain(
    chain: list[x509.Certificate], trusted_roots: list[x509.Certificate]
) -> None:
    """Verify a leaf-to-root certificate chain against a set of trusted roots.

    ``chain`` is ordered leaf first (VCEK), root last (ARK). Delegates to
    agent-manifest's shared, algorithm-agnostic cert-chain verifier (one
    implementation across the org, consumed via PyPI) and re-raises its failure
    as AttestationFailed to preserve ca2a's error contract. Used for the SEV-SNP
    VCEK chain, the TDX PCK chain, and the TPM AK chain alike. Raises
    AttestationFailed on any failure.
    """
    from agent_manifest import CertChainError
    from agent_manifest import verify_cert_chain as _shared_verify_cert_chain

    try:
        _shared_verify_cert_chain(chain, trusted_roots)
    except CertChainError as exc:
        raise AttestationFailed(
            "certificate chain verification failed", detail=str(exc)
        ) from exc


def verify_sev_snp_report(
    report_bytes: bytes,
    vcek_chain: list[x509.Certificate],
    *,
    trusted_roots: list[x509.Certificate],
    expected_measurement: bytes | None = None,
    expected_report_data: bytes | None = None,
) -> SevSnpReport:
    """Appraise a SEV-SNP report offline. Raises AttestationFailed on any failure.

    ``vcek_chain`` is ordered leaf (VCEK) first, root (ARK) last.
    """
    report = SevSnpReport.parse(report_bytes)

    if report.signature_algo != SIG_ALGO_ECDSA_P384_SHA384:
        raise AttestationFailed(
            "unsupported report signature algorithm",
            detail=f"algo={report.signature_algo}, expected {SIG_ALGO_ECDSA_P384_SHA384}",
        )

    verify_cert_chain(vcek_chain, trusted_roots)

    vcek_key = vcek_chain[0].public_key()
    if not isinstance(vcek_key, ec.EllipticCurvePublicKey):
        raise AttestationFailed("VCEK does not carry an elliptic-curve public key")

    r, s = report.signature_rs
    der_sig = encode_dss_signature(r, s)
    try:
        vcek_key.verify(der_sig, report.signed_body, ec.ECDSA(SHA384()))
    except InvalidSignature as exc:
        raise AttestationFailed("SEV-SNP report signature failed to verify") from exc

    if expected_measurement is not None and report.measurement != expected_measurement:
        raise AttestationFailed(
            "measurement does not match the expected value",
            detail=f"got {report.measurement.hex()}",
        )
    if expected_report_data is not None and report.report_data != expected_report_data:
        raise AttestationFailed("report data does not match the expected binding")

    return report
