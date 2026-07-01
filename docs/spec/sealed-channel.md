# Sealed Peer Channel

The sealed channel binds a task payload to a peer's attested measurement so it decrypts only inside the peer's verified enclave. This is Tier 2 on the roadmap and is not yet implemented; the interface is defined so the runtime can be written against it.

## Threat it addresses

When A sends B a task payload, that payload crosses a network and lands in B's memory. If B is in another trust domain, mTLS protects the pipe but not the endpoint: the operator hosting B, or a connectivity provider between them, can read plaintext. Sealing the payload to B's measurement means only a B that booted the expected, measured code can open it.

## Interface

```python
from ca2a_runtime.channel import SealedChannel

ch = SealedChannel(peer_measurement="sha256:...")
sealed = ch.seal(payload)   # to the peer's measurement
opened = ch.open(sealed)    # only inside the attested peer
```

Until the enclave-sealing backend lands, `seal` and `open` fail closed with `SEALED_CHANNEL_ERROR` rather than silently transmitting plaintext. Do not send confidential task payloads across a trust boundary and assume they are protected. See [LIMITATIONS.md](../../LIMITATIONS.md).

## Construction

The channel key is bound to the measurement in the attestation report (see [attestation](attestation.md)), extending the attestation-gated key pattern that cmcp uses for agent-to-gateway to the peer-to-peer case. The connectivity path sees ciphertext; the only thing that leaves the enclave in the clear is the signed TRACE record.
