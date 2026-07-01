"""Tests for the sealed peer channel (X25519 -> HKDF -> ChaCha20-Poly1305)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed
from ca2a_runtime.errors import SealedChannelError


def test_seal_open_roundtrip() -> None:
    priv, pub = generate_channel_keypair()
    payload = b"transfer 250000 to account 12345"
    sealed = SealedChannel(pub).seal(payload)
    assert open_sealed(sealed, priv) == payload


def test_sealed_blob_hides_plaintext() -> None:
    priv, pub = generate_channel_keypair()
    payload = b"MNPI: acquisition closes Friday"
    sealed = SealedChannel(pub).seal(payload)
    assert payload not in sealed  # the path sees ciphertext, not the payload


def test_wrong_key_cannot_open() -> None:
    _, pub = generate_channel_keypair()
    sealed = SealedChannel(pub).seal(b"secret")
    attacker_key = X25519PrivateKey.generate()
    with pytest.raises(SealedChannelError):
        open_sealed(sealed, attacker_key)


def test_tampered_ciphertext_fails_closed() -> None:
    priv, pub = generate_channel_keypair()
    sealed = bytearray(SealedChannel(pub).seal(b"secret"))
    sealed[-1] ^= 0xFF  # flip a ciphertext/tag byte
    with pytest.raises(SealedChannelError):
        open_sealed(bytes(sealed), priv)


def test_aad_must_match() -> None:
    priv, pub = generate_channel_keypair()
    sealed = SealedChannel(pub).seal(b"secret", aad=b"session-A")
    assert open_sealed(sealed, priv, aad=b"session-A") == b"secret"
    with pytest.raises(SealedChannelError):
        open_sealed(sealed, priv, aad=b"session-B")


def test_malformed_blob_rejected() -> None:
    priv, _ = generate_channel_keypair()
    with pytest.raises(SealedChannelError):
        open_sealed(b"too short", priv)
    with pytest.raises(SealedChannelError):
        open_sealed(b"\x02" + b"\x00" * 60, priv)  # unsupported version


def test_invalid_peer_key_rejected() -> None:
    with pytest.raises(SealedChannelError):
        SealedChannel("not-hex-zz")
