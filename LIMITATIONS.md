# Limitations

cA2A is a pre-release profile in active design. This document states plainly what is built, what is stubbed, and what is out of scope, so no claim in the documentation runs ahead of the code. This is a deliberate discipline: proof, not promises.

## What is built

- The delegation credential model and the offline chain verifier skeleton: signature checks, scope attenuation (a child grant must be a provable subset of its parent), depth limits, and cross-chain replay rejection. The hardest of these semantics is reused from [agent-manifest](https://github.com/agentrust-io/agent-manifest), where it is implemented and tested.
- Configuration, error registry, and the CLI surface.

## What is stubbed or not yet implemented

- **Live A2A transport serving.** An A2A metadata adapter (`ca2a_runtime.transport`) parses/attaches cA2A extension fields into a `PeerRequest`, and `ca2a start` serves JSON-RPC `message/send` end to end through `handle_peer_request` (verify chain → intersect policy → open sealed payload when a key is configured → emit a provenance record), fail-closed. There is still **no** attestation handshake on the live call, and the seal is **not** bound to a verified measurement: any enclave key is software-configured. Live serving is Tier 2 transport progress, not a claim that cA2A is attested across trust domains.
- **Sealed peer channel (live binding).** The channel is implemented: a payload is sealed to the peer's attested X25519 key (X25519 ECDH, HKDF-SHA256, ChaCha20-Poly1305), and only the holder of the peer's private key can open it. The live listener can open with a configured key. The remaining gap is the hardware property that the private key never leaves the peer's enclave (established by attestation), and wiring the seal to a verified report on a live inbound call. Until that end-to-end binding lands on hardware, do not assume a payload is confined to a specific attested measurement. Adapter-decoded `sealed_payload` bytes are opaque ciphertext only.
- **Real hardware attestation.** The **SEV-SNP verifier is implemented**: report parsing, VCEK certificate chain verification, ECDSA-P384 report-signature verification, and measurement/report-data binding, all fail-closed. The chain path is validated against the genuine AMD Milan root chain; the report-signature path is validated with synthetic vectors, since a real report plus VCEK pair needs SEV-SNP hardware. Report generation (`SevSnpProvider.attest`) still requires a real SEV-SNP guest. The **Intel TDX verifier** (DCAP Quote v4: PCK chain to the genuine Intel SGX Root CA, QE report, attestation-key binding, quote signature, MRTD binding) and the **TPM 2.0 verifier** (AK chain to a caller-supplied vendor root, AK signature, magic/type, qualifying-data and PCR-digest binding) are also implemented and synthetic-vector validated; quote generation needs the respective hardware. Until a backend verifies a real quote end to end against a golden measurement on hardware, cA2A must not be described as fully attested across trust domains.

## Out of scope

- The A2A transport itself. cA2A is a profile on A2A, not a replacement for it.
- Agent identity issuance beyond delegation.
- AI model governance beyond delegation and provenance.
- Hardware TEE platform SDKs and firmware.

## Dependencies on sibling projects

cA2A composes primitives from [agent-manifest](https://github.com/agentrust-io/agent-manifest), [cmcp](https://github.com/agentrust-io/cmcp), and [trace-spec](https://github.com/agentrust-io/trace-spec). Version skew across those repos can change cA2A behavior; pin compatible versions before relying on cross-repo guarantees.
