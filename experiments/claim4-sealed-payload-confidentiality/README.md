# Experiment: Sealed-Payload Confidentiality

**Claim:** A task payload sealed to a peer's attested key decrypts only with the private key bound to that peer's enclave (cA2A Claim 4).

**Status: validated (cryptographic layer).**

`ca2a_runtime.channel` implements an HPKE-style sealed channel: an ephemeral X25519 ECDH to the peer's public key, HKDF-SHA256 to derive a key, and ChaCha20-Poly1305 AEAD over the payload. The peer generates its channel keypair (inside the enclave, on real hardware) and vouches for the public key through its attestation report; a sender seals to that key with `SealedChannel(peer_pub).seal(payload)`, and only the holder of the private key opens it with `open_sealed(blob, private_key)`.

**What it proves:**

1. The sealed blob does not contain the plaintext; the transport sees ciphertext.
2. Only the peer's private key opens the payload; another party with a different key cannot.
3. Any tampering with the sealed blob fails closed (AEAD authentication), so a modified payload never decrypts.

**What rests on hardware (not proven here):** the guarantee that the private key never leaves the peer's enclave, so the payload decrypts *only inside the attested measurement*. That is what attestation establishes (see the SEV-SNP verifier and [attestation.md](../../docs/spec/attestation.md)). Driving the seal off a verified report on a live inbound call is runtime wiring, tracked on the roadmap. The cryptographic confidentiality of the payload to the attested key is what this experiment validates.

## Running

```bash
# From repo root, with the package installed editable (pip install -e ".[dev]")
python experiments/claim4-sealed-payload-confidentiality/run.py
```

## Expected output

```
Claim 4: sealed-payload confidentiality
  [1] plaintext hidden in sealed blob: YES  (... bytes) OK
  [2] peer opens with its private key: OK
  [3] other party cannot open: OK
  [4] tampered payload fails closed: OK
KEY RESULT: 4/4 sealed to the attested key; only the enclave-bound private key opens it; path sees ciphertext; tamper fails closed
```
