# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- A2A transport adapter (`ca2a_runtime.transport`): parse/attach cA2A extension
  metadata on A2A `SendMessage`-shaped messages into `PeerRequest` (and the
  reverse). Extension URI `https://agentrust.io/extensions/ca2a/v0.1`. Fail closed
  on malformed cA2A metadata; absence of all cA2A keys returns `None` (ordinary
  A2A). The adapter itself adds no HTTP serving or seal-to-verified-measurement
  binding; the reference transport below adds serving, and hardware measurement
  binding is still pending. New error `TRANSPORT_ERROR`. See issue #47.
- Reference HTTP transport and attestation handshake, software mode (Tier 2):
  `ca2a_runtime.transport.server`/`client` (standard library only) run a live
  inbound A2A-profile call end to end over HTTP, `ca2a_runtime.node.PeerNode`
  composes the provider, policy, adapter, and `handle_peer_request`, and
  `ca2a_runtime.attestation` (offer/verify/seal) gates the seal on a channel key
  the caller appraises under a fresh nonce. `ca2a_runtime.tee.software.SoftwareProvider`
  supplies the no-hardware provider (never auto-selected). This is a **reference**
  transport, not part of the profile: the profile mandates no wire protocol. In
  software mode the peer key is `assurance="none"`; binding the seal to a
  hardware-verified measurement (the `verifier` seam wrapping `ca2a_verify`) is
  the remaining hardware step. Exercised end to end by `tests/unit/test_live_call.py`.

## [0.1.0a1] - 2026-07-09

First public alpha. Everything in this release is verifiable offline or in
software today. cA2A is a profile in active design: the delegation semantics and
the TEE verifiers are implemented and tested, but the profile is not yet attested
across trust domains on real hardware and there is no live A2A transport. That
milestone gates the first non-alpha release. See LIMITATIONS.md for the exact
built/stubbed boundary.

### What this release provides

- Initial cA2A profile draft: attested, attenuated agent-to-agent delegation on top of A2A
- `ca2a-verify`: offline delegation-chain verification skeleton (scope attenuation, signature, depth, replay checks)
- `ca2a-runtime`: config, error registry, and delegation credential model
- `ca2a_runtime.provenance`: linked delegation-record DAG with tamper and reparent detection, bound to authority via `cross_check_chain`
- `experiments/`: reproducible claim suite C1-C6. C1 (attenuation), C2 (cross-chain replay), and C5 (provenance DAG) are fully reproducible; C3, C4, C6 SKIP until their Tier 2/3 dependency lands. Each claim has a CI test.
- SEV-SNP attestation backend (Tier 3): `ca2a_runtime.tee.sev_snp` (report parsing, `SevSnpProvider`) and `ca2a_verify.sev_snp` (VCEK chain verification, ECDSA-P384 report-signature verification, measurement/report-data binding), all fail-closed. Chain path validated against the real AMD Milan root; report-signature path validated with synthetic vectors. Report generation requires a real SEV-SNP guest.
- Peer-call enforcement decision core (Tier 2): `ca2a_runtime.policy.LocalPolicy` and `ca2a_runtime.peer` (`effective_scope`, `enforce_peer_call`). Effective permission is the delegated leaf scope intersected with the callee's local policy; a granted call emits a linked provenance record. New error `SCOPE_NOT_PERMITTED`. Claim C3 (scope-policy intersection) is now a validated experiment. Cedar-engine binding of the local policy and live A2A transport wiring remain open.
- Sealed peer channel (Tier 2): `ca2a_runtime.channel` (`SealedChannel`, `generate_channel_keypair`, `open_sealed`). HPKE-style X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305 sealing a payload to the peer's attested key; only the peer's private key opens it, and a wrong key or tampered ciphertext fails closed. Claim C4 (sealed-payload confidentiality) is now a validated experiment at the cryptographic layer. The enclave-binding of the private key (a hardware property) and live-path wiring remain open.
- Cross-operator attestation (Claim C6) validated in software: a two-operator harness composing the SEV-SNP verifier, measurement pinning, and the sealed channel demonstrates independent keys, mutual attestation, confidential cross-operator delegation, and binary-swap detection. Synthetic report vectors (a genuine report needs SEV-SNP hardware); real hardware end to end remains open. **All six claims (C1-C6) are now validated experiments.**
- cA2A-compatible conformance suite: `tests/conformance/` with a normative README (stable MUST/SHOULD test IDs across delegation, scope-policy, attestation, sealed channel, provenance, and the inbound pipeline) and runnable checks that exercise every MUST-level requirement. Wired into CI and documented at `docs/spec/conformance.md`; ties to the CHARTER trademark language.
- TPM 2.0 attestation backend: `ca2a_runtime.tee.tpm` (TPMS_ATTEST parsing, `TpmProvider`) and `ca2a_verify.tpm.verify_tpm_quote` (AK chain to a caller-supplied vendor root, AK signature over the attest blob (ECDSA or RSA), magic/type checks, and qualifying-data/PCR-digest binding), all fail-closed. Synthetic-vector validated; TPM AK roots are per-vendor so the caller supplies its trusted roots. Quote generation requires a real TPM.
- Intel TDX attestation backend: `ca2a_runtime.tee.tdx` (DCAP Quote v4 parsing, `TdxProvider`) and `ca2a_verify.tdx.verify_tdx_quote` (PCK chain to a trusted Intel root, QE report signature, attestation-key binding, quote signature, and MRTD/report-data binding), all fail-closed. Chain path validated against the genuine Intel SGX Root CA; multi-level signature path validated with a synthetic self-consistent quote. Quote generation requires a real TDX guest.
- AGT governance gate is now **blocking** (was advisory): CI installs `agent-governance-toolkit[full]`, so the OWASP ASI 2026 coverage modules load and `agt verify` reports 10/10 coverage with 6/6 runtime checks (COMPLETE). The enforcement descriptor now declares cA2A's `governed_capabilities`, reported as the registered-tools inventory. A governance or coverage regression now fails CI.
- Real Cedar policy engine binding: `ca2a_runtime.cedar.CedarPolicy` (backed by `cedarpy`, the engine cMCP runs) evaluates each capability as a Cedar authorization request. A new `ca2a_runtime.policy.Policy` protocol makes `LocalPolicy` (allow set) and `CedarPolicy` interchangeable in the peer path. Adds the `cedarpy` dependency.
- Transport-agnostic inbound peer request handler: `ca2a_runtime.peer.handle_peer_request` with `PeerRequest` / `PeerResult`. Composes the full pipeline (verify chain, intersect scope and enforce, open a sealed payload with the enclave key, emit a linked provenance record) fail-closed. A transport parses its wire format into a `PeerRequest`; cA2A does not define the transport (profile, not protocol).
- TRACE binding for the delegation DAG (Tier 2): `ca2a_runtime.trace_binding` lifts each delegation hop into a signed TRACE Trust Record carrying the A2A profile `delegation` block (`build_trace_record`, `sign_trace_record`, `emit_dag`, `trace_record_hash`, `HopContext`). Records are produced and signed with `agentrust-trace` (Ed25519 over RFC 8785), so TRACE canonicalization and signing are reused, not reimplemented. `ca2a_verify.verify_trace_dag` verifies a signed root-to-leaf DAG offline (structural validity, trusted-key signature, unbroken parent links over the full signed parent record) and `cross_check_trace_dag` ties it to the delegation chain; new error `TRACE_RECORD_INVALID`. Software-mode records are Level 0 (platform `software-only`); a hardware TEE run is what lifts them to Level 1. Adds the `agentrust-trace` dependency (and `agentrust-trace-tests` for dev). See `examples/trace-dag/`.
- RFC 8785 (JSON Canonicalization Scheme) canonicalization: `ca2a_runtime.canonical.canonicalize`. Credential and provenance bodies are now signed over the JCS encoding (UTF-16 key ordering, JCS string escaping, literal non-ASCII, shortest-decimal integers), so cA2A signatures are cross-verifiable with agent-manifest. ASCII credentials are byte-identical to the previous encoding, so existing signatures still verify.
- Repository scaffold: governance, CI/CD, docs framework, and packaging at parity with the agentrust-io house standard

### What this release does NOT yet claim

- Not attested or confidential across trust domains on real hardware: all attestation validation is software / synthetic-vector. No real SEV-SNP, TDX, or TPM quote has been verified end to end against a golden measurement on a confidential VM.
- No live A2A transport: the peer-enforcement decision core and sealed channel run in-process. Nothing parses real A2A wire messages into a `PeerRequest` yet, and the seal is not bound to a verified attestation report on a live inbound call.
- The sealed channel does not by itself establish the enclave-held-private-key property; that is a hardware attestation guarantee that lands with real-hardware validation.
- Alpha schemas: the delegation credential and TRACE link schemas are not yet stable or versioned, and peer attestation evidence is not yet RATS/EAT conformant.

[Unreleased]: https://github.com/agentrust-io/ca2a/compare/v0.1.0a1...main
[0.1.0a1]: https://github.com/agentrust-io/ca2a/releases/tag/v0.1.0a1
