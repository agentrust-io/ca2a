"""Sealed peer channel interface (Tier 2, not yet implemented).

The sealed channel binds a symmetric payload key to a peer's attested
measurement so the task payload decrypts only inside the peer's verified
enclave. Until the enclave-sealing backend lands, these operations fail closed
rather than silently sending plaintext.
"""

from __future__ import annotations

from ca2a_runtime.errors import SealedChannelError


class SealedChannel:
    """Placeholder for the measurement-bound peer channel.

    Instantiation is allowed so the runtime can be wired against the interface;
    the sealing operations fail closed until Tier 2 lands (see LIMITATIONS.md).
    """

    def __init__(self, peer_measurement: str) -> None:
        self.peer_measurement = peer_measurement

    def seal(self, payload: bytes) -> bytes:
        raise SealedChannelError(
            "sealed peer channel not implemented",
            detail="Tier 2 on the roadmap; do not send confidential payloads yet",
        )

    def open(self, sealed: bytes) -> bytes:
        raise SealedChannelError(
            "sealed peer channel not implemented",
            detail="Tier 2 on the roadmap",
        )
