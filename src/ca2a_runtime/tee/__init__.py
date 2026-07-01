"""TEE provider abstraction for peer attestation.

cA2A reuses the pluggable provider model from cmcp: a provider produces an
attestation report that binds a public key to a hardware measurement. Real
hardware backends are Tier 3 (see ROADMAP.md) and fail closed until implemented.
"""

from ca2a_runtime.tee.base import AttestationReport, BaseProvider

__all__ = ["AttestationReport", "BaseProvider"]
