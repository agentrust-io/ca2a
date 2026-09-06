# Sealed Peer Channel

The sealed channel encrypts a task to a peer's X25519 public key. Only the matching private key can open it. The reference runtime connects this encryption to channel-offer appraisal; software mode exercises the same encryption without proving hardware isolation.

## Scheme

The module uses X25519 key agreement, HKDF-SHA256, and ChaCha20-Poly1305 from `cryptography`. The sealed blob contains a version, ephemeral public key, nonce, and authenticated ciphertext. This is an HPKE-style construction, not a claim of RFC 9180 interoperability.

## Try the cryptographic layer

Run this after installing the source checkout as shown in the [quick start](../quickstart.md):

```python
from ca2a_runtime.channel import SealedChannel, generate_channel_keypair, open_sealed
from ca2a_runtime.errors import SealedChannelError

peer_private, peer_public = generate_channel_keypair()
payload = b"reconcile this ledger"
sealed = SealedChannel(peer_public).seal(payload, aad=b"session-1")
assert open_sealed(sealed, peer_private, aad=b"session-1") == payload

wrong_private, _ = generate_channel_keypair()
try:
    open_sealed(sealed, wrong_private, aad=b"session-1")
except SealedChannelError:
    print("wrong key rejected")
else:
    raise AssertionError("wrong key accepted")
```

Malformed blobs, changed ciphertext, wrong keys, or mismatched additional authenticated data raise `SEALED_CHANNEL_ERROR`; no unauthenticated plaintext is returned. Both sides must supply the same `aad` when using that low-level option.

## Attestation and key custody

In a live call, the sender appraises the recipient's channel offer before sealing to it. The recipient performs its inbound checks before opening the payload. See [inbound peer-call decision](call-graph.md).

Encryption to a key does not by itself prove where the private key lives. Protection against the recipient's host operator depends on accepted hardware evidence binding the key to the expected measured environment, and on that environment retaining the private key. This example generates its keys in ordinary process memory and demonstrates no such protection.

The encrypted payload does not hide all transport metadata, offers, or evidence records. See [attestation](attestation.md), [hardware validation](../hardware-validation.md), and [limitations](../../LIMITATIONS.md) for the deployment-specific assurance boundary.
