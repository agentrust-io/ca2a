"""Sealed peer channel: seal a task payload to a peer's attested key.

The channel binds a payload to the X25519 public key that a peer's attestation
report vouches for (see docs/spec/attestation.md). The scheme is HPKE-style:
an ephemeral X25519 ECDH to the peer key, HKDF-SHA256 to derive a symmetric
key, and ChaCha20-Poly1305 AEAD over the payload. Only the holder of the
private key can open the result.

Confidentiality of the payload rests on that private key. On real hardware the
key is generated and held inside the peer's enclave and never leaves it, so the
payload decrypts only inside the attested measurement. This module implements
the cryptography; the guarantee that the private key is enclave-bound is what
attestation establishes, and driving the seal off a verified report on a live
call is tracked as runtime wiring (see ROADMAP.md).
"""

from __future__ import annotations

import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ca2a_runtime.errors import SealedChannelError

_VERSION = 1
_HKDF_INFO = b"ca2a/sealed-channel/v1"
_EPH_LEN = 32
_NONCE_LEN = 12
_HEADER_LEN = 1 + _EPH_LEN + _NONCE_LEN


def generate_channel_keypair() -> tuple[X25519PrivateKey, str]:
    """Return an enclave channel keypair and its public key as raw hex.

    On hardware this runs inside the peer's enclave and the public key is bound
    into the attestation report; the private key never leaves the enclave.
    """
    priv = X25519PrivateKey.generate()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    return priv, pub_hex


def _derive_key(shared: bytes, eph_pub: bytes, peer_pub: bytes) -> bytes:
    return HKDF(algorithm=SHA256(), length=32, salt=None, info=_HKDF_INFO).derive(
        eph_pub + peer_pub + shared
    )


class SealedChannel:
    """Sender side: seals payloads to a peer's attested X25519 public key."""

    def __init__(self, peer_public_key: str) -> None:
        try:
            self._peer_pub = X25519PublicKey.from_public_bytes(bytes.fromhex(peer_public_key))
        except ValueError as exc:
            raise SealedChannelError("invalid peer public key", detail=str(exc)) from exc
        self.peer_public_key = peer_public_key

    def seal(self, payload: bytes, *, aad: bytes = b"") -> bytes:
        """Seal ``payload`` to the peer key. The result is opaque to anyone
        without the peer's private key; ``aad`` is authenticated, not encrypted."""
        eph_priv = X25519PrivateKey.generate()
        eph_pub = eph_priv.public_key().public_bytes_raw()
        peer_pub_raw = self._peer_pub.public_bytes_raw()
        shared = eph_priv.exchange(self._peer_pub)
        key = _derive_key(shared, eph_pub, peer_pub_raw)
        nonce = os.urandom(_NONCE_LEN)
        ct = ChaCha20Poly1305(key).encrypt(nonce, payload, aad)
        return bytes([_VERSION]) + eph_pub + nonce + ct


def open_sealed(blob: bytes, private_key: X25519PrivateKey, *, aad: bytes = b"") -> bytes:
    """Open a sealed payload with the enclave-bound private key.

    Fails closed with SealedChannelError on a malformed blob, a wrong key, or a
    tampered ciphertext (AEAD authentication failure); it never returns
    unauthenticated plaintext.
    """
    if len(blob) < _HEADER_LEN or blob[0] != _VERSION:
        raise SealedChannelError("malformed or unsupported sealed payload")
    eph_pub = blob[1 : 1 + _EPH_LEN]
    nonce = blob[1 + _EPH_LEN : _HEADER_LEN]
    ct = blob[_HEADER_LEN:]
    try:
        peer_pub_raw = private_key.public_key().public_bytes_raw()
        shared = private_key.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        key = _derive_key(shared, eph_pub, peer_pub_raw)
        return ChaCha20Poly1305(key).decrypt(nonce, ct, aad)
    except (InvalidTag, ValueError) as exc:
        raise SealedChannelError("sealed payload failed to open", detail=str(exc)) from exc
