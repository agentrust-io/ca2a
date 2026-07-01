"""Claim 4: sealed-payload confidentiality.

A payload sealed to a peer's attested key decrypts only with the private key
bound to that peer's enclave. Validated here at the cryptographic layer: the
sealed blob hides the plaintext, only the peer's private key opens it, and any
tampering fails closed. The guarantee that the private key never leaves the
enclave is what attestation establishes on real hardware; that end-to-end
binding on a live call remains runtime wiring (see ROADMAP.md).
"""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed
from ca2a_runtime.errors import SealedChannelError


def test_payload_decrypts_only_with_peer_private_key() -> None:
    peer_priv, peer_pub = generate_channel_keypair()
    payload = b"confidential task payload"

    sealed = SealedChannel(peer_pub).seal(payload)
    assert payload not in sealed  # the transport sees ciphertext

    # The peer (holder of the enclave-bound private key) recovers it.
    assert open_sealed(sealed, peer_priv) == payload

    # Anyone else, including another attested peer, cannot.
    other_priv = X25519PrivateKey.generate()
    with pytest.raises(SealedChannelError):
        open_sealed(sealed, other_priv)


def test_tampered_sealed_payload_fails_closed() -> None:
    peer_priv, peer_pub = generate_channel_keypair()
    sealed = bytearray(SealedChannel(peer_pub).seal(b"confidential task payload"))
    sealed[-1] ^= 0xFF
    with pytest.raises(SealedChannelError):
        open_sealed(bytes(sealed), peer_priv)
