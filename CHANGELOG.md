# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial cA2A profile draft: attested, attenuated agent-to-agent delegation on top of A2A
- `ca2a-verify`: offline delegation-chain verification skeleton (scope attenuation, signature, depth, replay checks)
- `ca2a-runtime`: config, error registry, and delegation credential model
- `ca2a_runtime.provenance`: linked delegation-record DAG with tamper and reparent detection, bound to authority via `cross_check_chain`
- `experiments/`: reproducible claim suite C1-C6. C1 (attenuation), C2 (cross-chain replay), and C5 (provenance DAG) are fully reproducible; C3, C4, C6 SKIP until their Tier 2/3 dependency lands. Each claim has a CI test.
- SEV-SNP attestation backend (Tier 3): `ca2a_runtime.tee.sev_snp` (report parsing, `SevSnpProvider`) and `ca2a_verify.sev_snp` (VCEK chain verification, ECDSA-P384 report-signature verification, measurement/report-data binding), all fail-closed. Chain path validated against the real AMD Milan root; report-signature path validated with synthetic vectors. Report generation requires a real SEV-SNP guest.
- Peer-call enforcement decision core (Tier 2): `ca2a_runtime.policy.LocalPolicy` and `ca2a_runtime.peer` (`effective_scope`, `enforce_peer_call`). Effective permission is the delegated leaf scope intersected with the callee's local policy; a granted call emits a linked provenance record. New error `SCOPE_NOT_PERMITTED`. Claim C3 (scope-policy intersection) is now a validated experiment. Cedar-engine binding of the local policy and live A2A transport wiring remain open.
- Sealed peer channel (Tier 2): `ca2a_runtime.channel` (`SealedChannel`, `generate_channel_keypair`, `open_sealed`). HPKE-style X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305 sealing a payload to the peer's attested key; only the peer's private key opens it, and a wrong key or tampered ciphertext fails closed. Claim C4 (sealed-payload confidentiality) is now a validated experiment at the cryptographic layer. The enclave-binding of the private key (a hardware property) and live-path wiring remain open.
- Cross-operator attestation (Claim C6) validated in software: a two-operator harness composing the SEV-SNP verifier, measurement pinning, and the sealed channel demonstrates independent keys, mutual attestation, confidential cross-operator delegation, and binary-swap detection. Synthetic report vectors (a genuine report needs SEV-SNP hardware); real hardware end to end remains open. **All six claims (C1-C6) are now validated experiments.**
- Transport-agnostic inbound peer request handler: `ca2a_runtime.peer.handle_peer_request` with `PeerRequest` / `PeerResult`. Composes the full pipeline (verify chain, intersect scope and enforce, open a sealed payload with the enclave key, emit a linked provenance record) fail-closed. A transport parses its wire format into a `PeerRequest`; cA2A does not define the transport (profile, not protocol).
- RFC 8785 (JSON Canonicalization Scheme) canonicalization: `ca2a_runtime.canonical.canonicalize`. Credential and provenance bodies are now signed over the JCS encoding (UTF-16 key ordering, JCS string escaping, literal non-ASCII, shortest-decimal integers), so cA2A signatures are cross-verifiable with agent-manifest. ASCII credentials are byte-identical to the previous encoding, so existing signatures still verify.
- Repository scaffold: governance, CI/CD, docs framework, and packaging at parity with the agentrust-io house standard

### Not yet implemented

- Live A2A transport wiring for the peer-enforcement decision core, including binding the seal to a verified attestation report (Tier 2)
- Cedar policy engine binding for the local policy (Tier 2)
- Intel TDX and TPM attestation backends (Tier 3); end-to-end SEV-SNP validation against real hardware vectors

[Unreleased]: https://github.com/agentrust-io/ca2a/commits/main
