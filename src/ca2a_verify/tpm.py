"""Offline appraisal of a TPM 2.0 quote.

Appraisal is fail-closed:

1. The AK certificate chain is verified up to a trusted (caller-supplied) root.
2. The AK signature over the ``TPMS_ATTEST`` blob is verified (ECDSA or RSA).
3. The structure is confirmed to be a TPM-generated quote (magic and type).
4. The qualifying data (the key-and-nonce binding) and the PCR digest (the
   platform measurement) are checked against expected values.

The cryptography is **not** implemented here. Steps 1, 2 and 4 are delegated to
``agent_manifest.verify_tpm_quote``, which cA2A already depends on and which is
hardware-validated. Three divergent copies of one TPM verifier is the problem
being retired; see cmcp#447.

``TPMT_SIGNATURE`` used to be unwrapped here too, because agent-manifest did not
model it. It does as of 0.8, so :func:`parse_tpmt_signature` is now a thin
delegation that keeps cA2A's error contract (:class:`AttestationFailed`) while the
wire format itself lives in one place. cmcp carried a byte-identical copy of the
same parse; both are retired.

There is no single published TPM root, so the caller supplies the vendor roots it
trusts. :mod:`ca2a_verify.tpm_roots` carries the one root validated on hardware as
an opt-in constant. Verifying against no root at all is refused.
"""

from __future__ import annotations

from agent_manifest import ParsedSignature as _AmParsedSignature
from agent_manifest import TpmVerificationError
from agent_manifest import parse_tpmt_signature as _am_parse_tpmt_signature
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

from ca2a_runtime.attestation import Verifier
from ca2a_runtime.errors import AttestationFailed
from ca2a_runtime.tee.base import AttestationReport
from ca2a_runtime.tee.tpm import TpmQuote, tpm_qualifying_data

__all__ = [
    "ParsedSignature",
    "parse_tpmt_signature",
    "tpm_verifier",
    "verify_tpm_quote",
    "verify_tpm_report",
]

ParsedSignature = _AmParsedSignature
"""A parsed ``TPMT_SIGNATURE``. Re-exported from agent-manifest, which owns the
layout; the fields (``sig_alg``, ``hash_alg``, ``signature``) are unchanged."""


def parse_tpmt_signature(blob: bytes) -> ParsedSignature:
    """Unwrap a ``TPMT_SIGNATURE`` into a bare signature.

    Delegates the layout to ``agent_manifest.parse_tpmt_signature`` and translates
    its error into cA2A's, so callers keep catching :class:`AttestationFailed`.
    The parse handles RSASSA/RSAPSS (a size-prefixed ``TPM2B_PUBLIC_KEY_RSA``) and
    ECDSA (R and S as size-prefixed integers, re-encoded as a DER sequence).

    The upstream reason is passed through as the message rather than collapsed
    into a generic one: "unsupported algorithm" and "truncated" are different
    faults and a caller that cannot tell them apart cannot report usefully.
    """
    try:
        return _am_parse_tpmt_signature(blob)
    except TpmVerificationError as exc:
        raise AttestationFailed(str(exc)) from exc


def _delegate(
    attest: bytes,
    signature: bytes,
    ak_chain_pem: bytes,
    trusted_roots_pem: bytes,
    expected_qualifying_data: bytes | None,
    expected_pcr_digest: bytes | None,
) -> None:
    """Run agent-manifest's verifier, translating its outcome into cA2A errors."""
    try:
        from agent_manifest import verify_tpm_quote as _verify
    except ImportError as exc:  # pragma: no cover - a declared dependency
        raise AttestationFailed(
            "agent-manifest is required to verify a TPM quote", detail=str(exc)
        ) from exc

    try:
        ok = _verify(
            attest,
            signature,
            ak_chain_pem,
            trusted_roots_pem=trusted_roots_pem,
            expected_qualifying_data=expected_qualifying_data,
            expected_pcr_digest=expected_pcr_digest,
        )
    except Exception as exc:  # noqa: BLE001 - raises on a malformed quote or broken chain
        raise AttestationFailed(
            "TPM quote verification failed", detail=f"{type(exc).__name__}: {exc}"
        ) from exc
    if not ok:
        raise AttestationFailed(
            "TPM quote verification failed",
            detail="the AK signature or an expected binding did not match",
        )


def verify_tpm_quote(
    attest: bytes,
    signature: bytes,
    ak_chain: list[x509.Certificate],
    *,
    trusted_roots: list[x509.Certificate],
    expected_pcr_digest: bytes | None = None,
    expected_qualifying_data: bytes | None = None,
) -> TpmQuote:
    """Appraise a TPM 2.0 quote offline. Raises AttestationFailed on any failure.

    ``signature`` is the bare AK signature. For a marshalled ``TPMT_SIGNATURE``
    (what real tooling emits), unwrap it with :func:`parse_tpmt_signature` first,
    or use :func:`verify_tpm_report`, which does that for you.
    """
    if not ak_chain:
        raise AttestationFailed("no AK certificate chain was supplied")
    if not trusted_roots:
        raise AttestationFailed(
            "no trusted root was supplied",
            detail="a chain validated against no anchor would accept any chain",
        )

    quote = TpmQuote.parse(attest)
    _delegate(
        attest,
        signature,
        b"".join(c.public_bytes(Encoding.PEM) for c in ak_chain),
        b"".join(c.public_bytes(Encoding.PEM) for c in trusted_roots),
        expected_qualifying_data,
        expected_pcr_digest,
    )
    return quote


def verify_tpm_report(
    report: AttestationReport, expected_nonce: str, *, trusted_roots_pem: bytes
) -> str:
    """Verify a peer's TPM report and return the measurement it proves.

    This is the function that turns a report's ``public_key`` and ``nonce`` from
    assertions into signed facts. The expected qualifying data is re-derived from
    the report's own fields with :func:`~ca2a_runtime.tee.tpm.tpm_qualifying_data`
    and required to equal what the TPM committed in ``extraData``, so a report
    whose key or nonce was edited after the quote was taken is rejected.

    The returned measurement is read out of the signed quote, not copied from the
    report's ``measurement`` field, so what the caller acts on is the value the TPM
    signed. A mismatch between the two is itself a failure.
    """
    if report.nonce != expected_nonce:
        raise AttestationFailed(
            "the report nonce does not match the expected nonce",
            detail="stale or replayed attestation report",
        )
    if report.raw_evidence is None or report.quote_signature is None:
        raise AttestationFailed(
            "the report carries no TPM quote to verify",
            detail=(
                "a report claiming the 'tpm' platform must ship raw_evidence and "
                "quote_signature; without them there is nothing to appraise"
            ),
        )
    if not report.attestation_key_chain_pem:
        raise AttestationFailed(
            "the report carries no attestation key certificate chain",
            detail=(
                "the quote may be signed by a transient key, which proves a signature "
                "but not that the key lives in a TPM"
            ),
        )
    if not trusted_roots_pem:
        raise AttestationFailed(
            "no trusted root was supplied",
            detail="a chain validated against no anchor would accept any chain",
        )

    expected_qualifying_data = tpm_qualifying_data(report.public_key, report.nonce)
    parsed = parse_tpmt_signature(report.quote_signature)

    quote = TpmQuote.parse(report.raw_evidence)
    _delegate(
        report.raw_evidence,
        parsed.signature,
        report.attestation_key_chain_pem,
        trusted_roots_pem,
        expected_qualifying_data,
        None,
    )

    measurement = "sha256:" + quote.pcr_digest.hex()
    if report.measurement != measurement:
        raise AttestationFailed(
            "the reported measurement is not the one the TPM signed",
            detail=f"report={report.measurement} quote={measurement}",
        )
    return measurement


def tpm_verifier(trusted_roots_pem: bytes) -> Verifier:
    """Return a :data:`~ca2a_runtime.attestation.Verifier` bound to these roots.

    Lets :func:`~ca2a_runtime.attestation.verify_offer` reach
    ``assurance="hardware"`` on a TPM peer:

        peer = verify_offer(offer, expected_nonce=n,
                            verifier=tpm_verifier(AZURE_VTPM_ROOT_2023_PEM))
    """

    def _verifier(report: AttestationReport, expected_nonce: str) -> str:
        return verify_tpm_report(report, expected_nonce, trusted_roots_pem=trusted_roots_pem)

    return _verifier
