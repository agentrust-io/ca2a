"""Sealed peer channel: seal a task payload to a peer's attested key.

HPKE-style X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305. Only the holder of the
private key bound to the peer's attested measurement can open a sealed payload.
See docs/spec/sealed-channel.md.
"""

from ca2a_runtime.channel.sealed import (
    SealedChannel,
    generate_channel_keypair,
    open_sealed,
)

__all__ = ["SealedChannel", "generate_channel_keypair", "open_sealed"]
