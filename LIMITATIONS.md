# Limitations

cA2A is a pre-release profile in active design. This document states plainly what is built, what is stubbed, and what is out of scope, so no claim in the documentation runs ahead of the code. This is a deliberate discipline: proof, not promises.

## What is built

- The delegation credential model and the offline chain verifier skeleton: signature checks, scope attenuation (a child grant must be a provable subset of its parent), depth limits, and cross-chain replay rejection. The hardest of these semantics is reused from [agent-manifest](https://github.com/agentrust-io/agent-manifest), where it is implemented and tested.
- Configuration, error registry, and the CLI surface.
- A reference HTTP transport and the attestation handshake, in software mode. `ca2a_runtime.transport.server` and `ca2a_runtime.transport.client` (standard library only) run a live inbound A2A-profile call end to end: the caller fetches the callee's attested channel key, seals a payload to it, and sends a delegated task; the callee parses the A2A metadata with the adapter, runs verify + policy + enforce + open-sealed + provenance, and replies. `ca2a_runtime.attestation` gates the seal on a verified channel key. This is a **reference** transport, not part of the profile: the profile mandates no wire protocol (see Out of scope), and in software mode the peer key is accepted at `assurance="none"`.

## What is stubbed or not yet implemented

- **Hardware-attested live binding.** The live transport and handshake run today in **software mode only** (the reference server/client above, `assurance="none"`). The remaining gap is hardware: driving the `verifier` seam in `ca2a_runtime.attestation` off a real SEV-SNP, TDX, or TPM quote (wrapping `ca2a_verify`) so the peer's channel key is bound to a hardware-verified enclave measurement, and relying on the enclave to hold the channel private key. There is also no CLI listener (`ca2a start`); serving is via `ca2a_runtime.transport.server.serve`. A software-mode live call is Tier 2 progress, not a claim that cA2A is attested across trust domains.
- **Sealed peer channel (hardware property).** The channel is implemented: a payload is sealed to the peer's attested X25519 key (X25519 ECDH, HKDF-SHA256, ChaCha20-Poly1305), and only the holder of the peer's private key can open it. On a live call the handshake now gates the seal on a channel key the caller has appraised, but in software mode that appraisal is `assurance="none"`. Until the seal is bound to a hardware-verified measurement (above), do not assume a payload is confined to a specific attested measurement. Adapter-decoded `sealed_payload` bytes are opaque ciphertext only.
- **Real hardware attestation.** The **SEV-SNP and Intel TDX verifiers now appraise genuine hardware evidence end to end**: a real Azure CVM SEV-SNP report (VCEK chain to the AMD ARK-Milan root, ECDSA-P384 report signature, measurement binding) and a real GCP C3 DCAP v4 TDX quote (PCK chain to the Intel SGX Root CA, QE binding, quote signature, MRTD binding), both fail-closed and both rejecting a tampered copy. Runs are recorded in [docs/hardware-validation.md](docs/hardware-validation.md). The **TPM 2.0 verifier** (AK chain to a caller-supplied vendor root, AK signature, magic/type, qualifying-data and PCR-digest binding) is implemented but synthetic-vector validated only. Quote *generation* still requires the respective hardware for all three. This validates the verifier, not a running attested peer: until the `verifier` seam in `ca2a_runtime.attestation` is driven off a live quote on a confidential VM, cA2A must not be described as attested across trust domains.

## Out of scope

- A normative or production A2A transport. cA2A is a profile on A2A, not a replacement for it, and mandates no wire protocol. A reference HTTP transport ships (`ca2a_runtime.transport.server`/`client`) so the peer path is runnable on ordinary compute, but it is a convenience, not part of the profile: any A2A server can drive the adapter and a `PeerNode` instead, and cA2A makes no claim about the reference transport's production hardening.
- Agent identity issuance beyond delegation.
- AI model governance beyond delegation and provenance.
- Hardware TEE platform SDKs and firmware.

## Dependencies on sibling projects

cA2A composes primitives from [agent-manifest](https://github.com/agentrust-io/agent-manifest), [cmcp](https://github.com/agentrust-io/cmcp), and [trace-spec](https://github.com/agentrust-io/trace-spec). Version skew across those repos can change cA2A behavior; pin compatible versions before relying on cross-repo guarantees.
