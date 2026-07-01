# Sealed Peer Channel

The sealed channel binds a task payload to the key a peer's attestation vouches for, so it decrypts only with the private key held inside that peer's verified enclave. The channel is implemented; the guarantee that the private key is enclave-bound is what attestation establishes, and driving the seal off a verified report on a live call is runtime wiring still to come.

## Threat it addresses

When A sends B a task payload, that payload crosses a network and lands in B's memory. If B is in another trust domain, mTLS protects the pipe but not the endpoint: the operator hosting B, or a connectivity provider between them, can read plaintext. Sealing the payload to the key bound to B's measurement means only a B that booted the expected, measured code holds the private key that can open it.

## Scheme

HPKE-style, using only primitives from the `cryptography` library:

1. The peer generates an X25519 channel keypair (inside its enclave on hardware) and vouches for the public key through its attestation report.
2. The sender does an ephemeral X25519 ECDH to that public key, derives a 32-byte key with HKDF-SHA256, and encrypts the payload with ChaCha20-Poly1305.
3. The sealed blob is `version || ephemeral_public_key || nonce || ciphertext`. Only the holder of the peer's private key can reconstruct the shared secret and decrypt.

## Interface

```python
from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed

peer_priv, peer_pub = generate_channel_keypair()   # peer side, in the enclave on hardware
sealed = SealedChannel(peer_pub).seal(payload, aad=b"session-id")  # sender side
opened = open_sealed(sealed, peer_priv, aad=b"session-id")         # only the peer's key opens it
```

`open_sealed` fails closed with `SEALED_CHANNEL_ERROR` on a malformed blob, a wrong key, or a tampered ciphertext (AEAD authentication failure); it never returns unauthenticated plaintext. `aad` binds context (for example a session id) into the authentication tag.

## What rests on hardware

The cryptographic confidentiality of the payload to the attested key is implemented and tested here. The stronger property, that the payload decrypts *only inside the attested measurement*, holds because the private key is generated in and never leaves the peer's enclave; that is a hardware property established by [attestation](attestation.md), not by this module. Binding the seal to a verified report on a live inbound call is tracked on the [roadmap](../../ROADMAP.md). The connectivity path sees ciphertext; the only thing that leaves the enclave in the clear is the signed TRACE record.
