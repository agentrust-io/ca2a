#!/usr/bin/env python3
"""Claim 4: a task payload sealed to a peer's attested key decrypts only with
the private key bound to that peer's enclave.

Validated experiment (no hardware) at the cryptographic layer: the sealed blob
hides the plaintext, only the peer's private key opens it, another party cannot,
and tampering fails closed. The guarantee that the private key never leaves the
enclave is what attestation establishes on real hardware; that end-to-end
binding on a live call is runtime wiring (see ROADMAP.md).
"""
# ruff: noqa: T201
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # noqa: E402

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed  # noqa: E402
from ca2a_runtime.errors import SealedChannelError  # noqa: E402

SECRET = b"confidential task payload: transfer 5000 to account 12345"


def main() -> int:
    # The peer generates its channel keypair (inside the enclave, on hardware).
    peer_priv, peer_pub = generate_channel_keypair()
    print("Claim 4: sealed-payload confidentiality")

    sealed = SealedChannel(peer_pub).seal(SECRET)
    checks = 0
    passed = 0

    # 1. The transport sees ciphertext, not the payload.
    checks += 1
    hidden = SECRET not in sealed
    passed += hidden
    print(f"  [1] plaintext hidden in sealed blob: {'YES' if hidden else 'NO'}  "
          f"({len(sealed)} bytes) {'OK' if hidden else 'FAIL'}")

    # 2. The peer (holder of the enclave-bound private key) recovers it.
    checks += 1
    recovered = open_sealed(sealed, peer_priv) == SECRET
    passed += recovered
    print(f"  [2] peer opens with its private key: {'OK' if recovered else 'FAIL'}")

    # 3. Another party (different key) cannot open it.
    checks += 1
    try:
        open_sealed(sealed, X25519PrivateKey.generate())
        blocked = False
    except SealedChannelError:
        blocked = True
    passed += blocked
    print(f"  [3] other party cannot open: {'OK' if blocked else 'FAIL'}")

    # 4. Tampering fails closed (AEAD authentication).
    checks += 1
    tampered = bytearray(sealed)
    tampered[-1] ^= 0xFF
    try:
        open_sealed(bytes(tampered), peer_priv)
        tamper_caught = False
    except SealedChannelError:
        tamper_caught = True
    passed += tamper_caught
    print(f"  [4] tampered payload fails closed: {'OK' if tamper_caught else 'FAIL'}")

    if passed == checks:
        print(f"KEY RESULT: {passed}/{checks} sealed to the attested key; only the "
              "enclave-bound private key opens it; path sees ciphertext; tamper fails closed")
        return 0
    print(f"KEY RESULT: FAIL ({passed}/{checks} passed)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
