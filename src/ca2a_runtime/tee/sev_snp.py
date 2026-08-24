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

:meth:`SevSnpProvider.attest` produces a real report through the kernel
configfs-TSM interface (see :mod:`ca2a_runtime.tee.tsm`), on the guests where
that is possible: a non-paravisor SNP guest whose ``sev-guest`` driver has
registered a TSM provider. What it binds is the point. ``REPORT_DATA`` commits
:func:`snp_report_data`, a digest over *both* the channel public key and the
caller's nonce, so a caller sealing to the key in a verified report is sealing to
a key the AMD PSP signed for.

Azure confidential VMs are deliberately not this provider. Azure runs SNP behind
a Hyper-V paravisor, so the guest sees no ``/dev/sev-guest``, registers no TSM
provider, and cannot set ``REPORT_DATA`` at all: the paravisor binds the vTPM
attestation key there instead. That path reads the report from a vTPM NV index
and roots the channel key through a TPM quote, which is
:class:`~ca2a_runtime.tee.tpm.TpmProvider`'s shape rather than this one. Saying
so is why :meth:`detect` returns False there instead of selecting a provider that
would then fail.

The verifier does not need hardware and is exercised against the real AMD root
certificate chain plus synthetic report vectors in the test suite.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from agent_manifest import SNP_OFFSETS, SNP_REPORT_LEN, SnpVerificationError, parse_snp_report

from ca2a_runtime.errors import AttestationFailed, AttestationUnsupported
from ca2a_runtime.tee.base import AttestationReport, BaseProvider
from ca2a_runtime.tee.binding import SNP_PREFIX, derive_binding, pad_report_data
from ca2a_runtime.tee.tsm import (
    PROVIDER_SEV_GUEST,
    collect_report,
    require_tsm,
    tsm_available,
)
from ca2a_runtime.tee.tsm import (
    REPORT_DATA_LEN as TSM_REPORT_DATA_LEN,
)

# Layout of the SEV-SNP ATTESTATION_REPORT, re-exported from agent-manifest's
# shared ABI table so cA2A and cmcp cannot disagree about where a field sits.
REPORT_SIZE = SNP_REPORT_LEN
SIG_OFFSET = SNP_OFFSETS["signature"]  # signature covers report[:SIG_OFFSET]
REPORT_DATA_OFFSET = SNP_OFFSETS["report_data"]
REPORT_DATA_LEN = 64
MEASUREMENT_OFFSET = SNP_OFFSETS["measurement"]
MEASUREMENT_LEN = 48
PLATFORM_INFO_OFFSET = SNP_OFFSETS["platform_info"]
PLATFORM_INFO_LEN = 8
# ECDSA-P384 signature: r then s, each in a 72-byte little-endian field.
SIG_COMPONENT_LEN = 72
SIG_ALGO_ECDSA_P384_SHA384 = 1

SEV_GUEST_DEVICE = "/dev/sev-guest"

# The measurement is a 48-byte launch digest, so it is labelled as SHA-384 for
# the same reason the TPM report labels its PCR digest: a bare hex string does
# not say what produced it.
MEASUREMENT_DIGEST_LABEL = "sha384"


def snp_report_data(public_key: str, nonce: str) -> bytes:
    """Return the 64 bytes a cA2A SEV-SNP report commits in ``REPORT_DATA``.

    The 32-byte binding digest, zero-padded to the field width. See
    :mod:`ca2a_runtime.tee.binding` and ``docs/spec/attestation.md``.
    """
    return pad_report_data(derive_binding(SNP_PREFIX, public_key, nonce), TSM_REPORT_DATA_LEN)


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
    def platform_info(self) -> int:
        """The raw PLATFORM_INFO bitfield, as a little-endian u64.

        This says what kind of machine signed the report: whether SMT is on,
        whether ECC is enabled, whether the firmware finished its boot-time DRAM
        alias check. None of the four checks in :func:`verify_sev_snp_report`
        look at it, which is deliberate: a signature, a chain and a measurement
        establish *which workload* ran, not *what the host was doing while it
        ran*. Decode it with ``agent_manifest.parse_platform_info`` and appraise
        it against an explicit policy.
        """
        return int.from_bytes(
            self.raw[PLATFORM_INFO_OFFSET : PLATFORM_INFO_OFFSET + PLATFORM_INFO_LEN],
            "little",
        )

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
    """AMD SEV-SNP provider. Produces a real report via configfs-TSM.

    ``detect`` reports True only where ``attest`` can actually run: Linux, the
    configfs-TSM interface, and the ``sev-guest`` device node whose driver
    registers the TSM provider. Both signals are required because the provider
    name is only readable from inside an entry, which needs root, so the device
    node stands in for "this is an SNP guest" at detection time and ``attest``
    confirms it against the kernel before returning any bytes.
    """

    platform = "sev-snp"

    @classmethod
    def detect(cls) -> bool:
        if not tsm_available():
            return False
        return Path(SEV_GUEST_DEVICE).exists()

    def attest(self, public_key: str, nonce: str) -> AttestationReport:
        """Request an SNP report committing ``public_key`` and ``nonce``.

        Raises :class:`AttestationUnsupported` when this host cannot produce a
        report at all, and :class:`AttestationFailed` when it can but the attempt
        did not yield verifiable evidence.
        """
        self._require_host()

        expected = snp_report_data(public_key, nonce)
        # auxblob carries AMD's certificate table (VCEK/ASK/ARK as GUID-tagged DER
        # blobs), not PEM. Passing it through as attestation_key_chain_pem would
        # assert a format this collector has never seen from real hardware, so it
        # is dropped rather than guessed at; a verifier fetches the VCEK from the
        # AMD KDS. Parsing it is what would make SNP appraisal fully offline.
        outblob, _auxblob = collect_report(expected, expect_provider=PROVIDER_SEV_GUEST)
        report = SevSnpReport.parse(outblob)

        # The PSP signed whatever it was given. Confirming the round trip here
        # means a report that reached the wire commits the key this call offered,
        # rather than one a concurrent caller wrote into a shared entry.
        if report.report_data != expected:
            raise AttestationFailed(
                "the report does not commit the requested key and nonce binding",
                detail="REPORT_DATA does not match the derived binding",
            )

        return AttestationReport(
            platform=self.platform,
            measurement=f"{MEASUREMENT_DIGEST_LABEL}:{report.measurement.hex()}",
            public_key=public_key,
            nonce=nonce,
            raw_evidence=report.raw,
            # The SNP signature is carried inside the report body rather than
            # alongside it, so this is a slice of raw_evidence, not a second blob.
            quote_signature=report.raw[SIG_OFFSET : SIG_OFFSET + 2 * SIG_COMPONENT_LEN],
        )

    @classmethod
    def _require_host(cls) -> None:
        """Fail with the actual reason, never a generic "no SEV-SNP guest"."""
        require_tsm("SEV-SNP")
        if not Path(SEV_GUEST_DEVICE).exists():
            raise AttestationUnsupported(
                "SEV-SNP report generation requires a non-paravisor SNP guest",
                detail=(
                    f"configfs-TSM is present but {SEV_GUEST_DEVICE} is not. On an Azure "
                    "confidential VM this is expected: SNP runs behind a Hyper-V "
                    "paravisor, the guest cannot set REPORT_DATA, and the report is read "
                    "from a vTPM NV index instead. Use the tpm provider there."
                ),
            )
