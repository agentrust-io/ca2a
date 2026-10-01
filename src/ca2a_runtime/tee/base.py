"""Base TEE provider interface and attestation report model."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass

from ca2a_runtime.tee.binding import ROLE_CALLEE


@dataclass(frozen=True)
class AttestationReport:
    """An attestation report binding a public key to a hardware measurement.

    The first four fields are what the report *claims*. On their own they are an
    assertion: any peer can populate them with any values. The evidence fields
    are what makes them checkable, so a relying party can reach
    ``assurance="hardware"`` (see :mod:`ca2a_runtime.attestation`).

    Evidence field names match cmcp's report model so evidence is portable
    between the two runtimes rather than needing a translation layer.
    """

    platform: str
    measurement: str
    public_key: str  # raw hex of the key bound to this measurement
    nonce: str
    # Signed evidence. All absent on the software-only provider, which has none
    # by construction. A report claiming a hardware platform with no evidence
    # cannot verify, so it fails closed rather than being trusted.
    raw_evidence: bytes | None = None  # the raw blob the hardware signed
    quote_signature: bytes | None = None  # the signature over raw_evidence
    attestation_key_pem: bytes | None = None  # the key that produced it
    attestation_key_chain_pem: bytes | None = None  # leaf-first chain for that key
    # Which role the offer was minted for (``ROLE_CALLEE`` or ``ROLE_CALLER``).
    # On hardware it selects the binding prefix, so it is covered by the quote
    # signature: editing it changes the bytes a verifier recomputes. Last, with a
    # default, so positional construction of a callee report is unchanged.
    role: str = ROLE_CALLEE


class BaseProvider(ABC):
    """Normalized interface every TEE provider implements.

    ``detect`` and ``attest`` must agree: a provider returns True from ``detect``
    only where ``attest`` can actually produce evidence on that host. Returning
    True and then raising is the one combination to avoid, because the provider
    gets selected and then fails.

    All three hardware providers implement ``attest``: TPM 2.0 through
    tpm2-pytss, SEV-SNP and TDX through the kernel configfs-TSM interface. Each
    ``detect`` therefore probes what its ``attest`` actually needs, and where a
    host cannot collect at all, ``attest`` raises
    :class:`~ca2a_runtime.errors.AttestationUnsupported` naming the missing piece
    rather than reporting a generic absence of the platform.
    """

    platform: str = "base"

    @classmethod
    @abstractmethod
    def detect(cls) -> bool:
        """Return True if this provider is available on the current host."""

    @abstractmethod
    def attest(self, public_key: str, nonce: str, *, role: str = ROLE_CALLEE) -> AttestationReport:
        """Produce an attestation report binding ``public_key`` under ``nonce``.

        ``role`` selects the domain-separated binding (see
        :mod:`ca2a_runtime.tee.binding`) and is recorded on the report. Only a
        node's own outbound call mints ``ROLE_CALLER``; the handshake endpoint
        always attests as ``ROLE_CALLEE``.
        """
