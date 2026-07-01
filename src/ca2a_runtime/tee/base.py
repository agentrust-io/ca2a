"""Base TEE provider interface and attestation report model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass(frozen=True)
class AttestationReport:
    """An attestation report binding a public key to a hardware measurement."""

    platform: str
    measurement: str
    public_key: str  # raw hex of the key bound to this measurement
    nonce: str


class BaseProvider(ABC):
    """Normalized interface every TEE provider implements.

    Real hardware providers (TPM, SEV-SNP, TDX, OPAQUE) are Tier 3 and are not
    implemented in this release; ``detect`` returns False for them so they are
    never selected automatically.
    """

    platform: str = "base"

    @classmethod
    @abstractmethod
    def detect(cls) -> bool:
        """Return True if this provider is available on the current host."""

    @abstractmethod
    def attest(self, public_key: str, nonce: str) -> AttestationReport:
        """Produce an attestation report binding ``public_key`` under ``nonce``."""
