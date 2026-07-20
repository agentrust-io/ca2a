"""Software-only attestation provider: NO hardware guarantee.

This provider produces an attestation report that binds a public key under a
nonce but carries no hardware signature. It exists so the peer path is runnable
off confidential-computing hardware (development, CI, and software-mode
deployments), which is what lets the live transport run on ordinary compute such
as a container platform. A key obtained through this provider is marked
``assurance="none"`` by :func:`ca2a_runtime.attestation.verify_offer`.

It is never selected by auto-detection: :meth:`detect` returns ``False``, so a
no-guarantee posture is always a deliberate, explicit choice (config provider
``software-only``), never a silent fallback.
"""

from __future__ import annotations

from ca2a_runtime.tee.base import AttestationReport, BaseProvider

SOFTWARE_MEASUREMENT = "software-only-no-hardware-guarantee"


class SoftwareProvider(BaseProvider):
    """A no-hardware provider for development and software-mode deployments."""

    platform = "software-only"

    @classmethod
    def detect(cls) -> bool:
        # Never auto-selected: a no-guarantee posture must be chosen explicitly.
        return False

    def attest(self, public_key: str, nonce: str) -> AttestationReport:
        return AttestationReport(
            platform=self.platform,
            measurement=SOFTWARE_MEASUREMENT,
            public_key=public_key,
            nonce=nonce,
        )
