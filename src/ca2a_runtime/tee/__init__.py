"""TEE provider abstraction for peer attestation.

cA2A reuses the pluggable provider model from cmcp: a provider produces an
attestation report that binds a public key to a hardware measurement.

:class:`~ca2a_runtime.tee.tpm.TpmProvider` collects a real quote. The SEV-SNP and
TDX collectors are Tier 3 (see ROADMAP.md) and fail closed until implemented,
though their verifiers appraise genuine hardware evidence.
"""

from ca2a_runtime.tee.base import AttestationReport, BaseProvider
from ca2a_runtime.tee.sev_snp import SevSnpProvider, SevSnpReport
from ca2a_runtime.tee.tdx import TdxProvider, TdxQuote
from ca2a_runtime.tee.tpm import TpmProvider, TpmQuote

__all__ = [
    "AttestationReport",
    "BaseProvider",
    "SevSnpProvider",
    "SevSnpReport",
    "TdxProvider",
    "TdxQuote",
    "TpmProvider",
    "TpmQuote",
]
