"""AMD SEV-SNP attestation report parsing and the SEV-SNP provider.

This module parses the SEV-SNP ``ATTESTATION_REPORT`` structure (1184 bytes,
AMD SEV-SNP ABI) and exposes the fields the cA2A verifier appraises: the launch
measurement, the report data (which binds the runtime key and nonce), and the
ECDSA-P384 signature over the report body. The verification and certificate
chain appraisal live in :mod:`ca2a_verify.sev_snp`.

Producing a report requires a real SEV-SNP guest (``/dev/sev-guest``), so
:meth:`SevSnpProvider.attest` fails closed off hardware. The verifier does not
need hardware and is exercised against the real AMD root certificate chain plus
synthetic report vectors in the test suite.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.base import AttestationReport, BaseProvider

# Layout of the SEV-SNP ATTESTATION_REPORT (offsets in bytes).
REPORT_SIZE = 0x4A0  # 1184
SIG_OFFSET = 0x2A0  # signature covers report[:SIG_OFFSET]
REPORT_DATA_OFFSET = 0x50
REPORT_DATA_LEN = 64
MEASUREMENT_OFFSET = 0x90
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
        """Parse a raw report, raising AttestationFailed on any malformed input."""
        if len(blob) < REPORT_SIZE:
            raise AttestationFailed(
                "SEV-SNP report too short",
                detail=f"got {len(blob)} bytes, need at least {REPORT_SIZE}",
            )
        version, guest_svn, policy = struct.unpack_from("<IIQ", blob, 0)
        (vmpl,) = struct.unpack_from("<I", blob, 0x30)
        (signature_algo,) = struct.unpack_from("<I", blob, 0x34)
        report_data = blob[REPORT_DATA_OFFSET : REPORT_DATA_OFFSET + REPORT_DATA_LEN]
        measurement = blob[MEASUREMENT_OFFSET : MEASUREMENT_OFFSET + MEASUREMENT_LEN]
        return cls(
            version=version,
            guest_svn=guest_svn,
            policy=policy,
            vmpl=vmpl,
            signature_algo=signature_algo,
            measurement=measurement,
            report_data=report_data,
            raw=bytes(blob[:REPORT_SIZE]),
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
