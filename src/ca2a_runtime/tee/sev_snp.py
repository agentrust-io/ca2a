"""AMD SEV-SNP attestation report parsing and the SEV-SNP provider.

This module exposes the SEV-SNP ``ATTESTATION_REPORT`` fields the cA2A verifier
appraises: the launch measurement, the report data (which binds the runtime key
and nonce), and the ECDSA-P384 signature over the report body. The verification
and certificate chain appraisal live in :mod:`ca2a_verify.sev_snp`.

The layout itself is **not** defined here. Offsets and parsing come from
``agent_manifest`` (>=0.10), which cmcp also consumes; between them the org
carried four mirrors of one ABI table, two inside cmcp alone. :class:`SevSnpReport`
stays as cA2A's surface, keeping its error contract and the ``signature_rs``
helper, but the bytes are read by the shared parser.

Producing a report requires a real SEV-SNP guest (``/dev/sev-guest``), so
:meth:`SevSnpProvider.attest` fails closed off hardware. The verifier does not
need hardware and is exercised against the real AMD root certificate chain plus
synthetic report vectors in the test suite.
"""

from __future__ import annotations

from dataclasses import dataclass

from agent_manifest import SNP_OFFSETS, SNP_REPORT_LEN, SnpVerificationError, parse_snp_report

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.base import AttestationReport, BaseProvider

# Layout of the SEV-SNP ATTESTATION_REPORT, re-exported from agent-manifest's
# shared ABI table so cA2A and cmcp cannot disagree about where a field sits.
REPORT_SIZE = SNP_REPORT_LEN
SIG_OFFSET = SNP_OFFSETS["signature"]  # signature covers report[:SIG_OFFSET]
REPORT_DATA_OFFSET = SNP_OFFSETS["report_data"]
REPORT_DATA_LEN = 64
MEASUREMENT_OFFSET = SNP_OFFSETS["measurement"]
MEASUREMENT_LEN = 48
# ECDSA-P384 signature: r then s, each in a 72-byte little-endian field.
SIG_COMPONENT_LEN = 72
SIG_ALGO_ECDSA_P384_SHA384 = 1

SEV_GUEST_DEVICE = "/dev/sev-guest"


@dataclass(frozen=True)
class SevSnpReport:
    """The parsed subset of a SEV-SNP attestation report cA2A appraises."""

    version: int
    guest_svn: int
    policy: int
    vmpl: int
    signature_algo: int
    measurement: bytes
    report_data: bytes
    raw: bytes

    @property
    def signed_body(self) -> bytes:
        """The bytes the report signature is computed over."""
        return self.raw[:SIG_OFFSET]

    @property
    def signature_rs(self) -> tuple[int, int]:
        """The (r, s) ECDSA signature components, decoded from little-endian."""
        r = int.from_bytes(self.raw[SIG_OFFSET : SIG_OFFSET + SIG_COMPONENT_LEN], "little")
        s = int.from_bytes(
            self.raw[SIG_OFFSET + SIG_COMPONENT_LEN : SIG_OFFSET + 2 * SIG_COMPONENT_LEN],
            "little",
        )
        return r, s

    @classmethod
    def parse(cls, blob: bytes) -> SevSnpReport:
        """Parse a raw report, raising AttestationFailed on any malformed input.

        The bytes are read by ``agent_manifest.parse_snp_report``; this keeps
        cA2A's error contract so callers still catch :class:`AttestationFailed`.
        """
        try:
            shared = parse_snp_report(blob)
        except SnpVerificationError as exc:
            raise AttestationFailed("SEV-SNP report is malformed", detail=str(exc)) from exc
        return cls(
            version=shared.version,
            guest_svn=shared.guest_svn,
            policy=shared.policy,
            vmpl=shared.vmpl,
            signature_algo=shared.signature_algo,
            measurement=shared.measurement,
            report_data=shared.report_data,
            raw=shared.raw,
        )


class SevSnpProvider(BaseProvider):
    """AMD SEV-SNP provider. Report generation requires a real SEV-SNP guest."""

    platform = "sev-snp"

    @classmethod
    def detect(cls) -> bool:
        import os

        return os.path.exists(SEV_GUEST_DEVICE)

    def attest(self, public_key: str, nonce: str) -> AttestationReport:
        raise AttestationUnsupported(
            "SEV-SNP report generation requires a real SEV-SNP guest",
            detail=f"{SEV_GUEST_DEVICE} not present; run on an AMD SEV-SNP confidential VM",
        )
