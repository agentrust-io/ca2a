# cA2A Roadmap

cA2A is an extension of the agentrust-io stack, not a rewrite. The build tiers below track how much each piece leans on primitives that already exist in [agent-manifest](https://github.com/agentrust-io/agent-manifest), [cmcp](https://github.com/agentrust-io/cmcp), and [trace-spec](https://github.com/agentrust-io/trace-spec).

## Reused as-is (Tier 0)

Already implemented and tested elsewhere; cA2A depends on it rather than reimplementing it.

- Capability attenuation with scope narrowing: signed delegation chain, child scope cannot exceed parent, depth limits, cross-manifest replay protection, HITL approval signing (agent-manifest)
- Pluggable TEE provider abstraction with measurement-bound keys (cmcp)
- Attestation-gated SPIFFE mTLS (cmcp)
- Audit chain with external signed evidence references (cmcp)
- Cedar policy engine (cmcp)
- Ed25519 + RFC 8785 canonicalization (all three repos; cA2A now ships a JCS canonicalizer in `ca2a_runtime.canonical`)

## v0.1: Profile and offline verifier

- cA2A profile specification published as an A2A binding (`docs/SPEC.md`)
- TRACE A2A profile: optional delegation-link block (parent record hash + delegation credential id) and its validation (Tier 1, coordinated in trace-spec)
- `ca2a-verify`: offline verification of a delegation chain and the delegation DAG, reusing the agent-manifest verifier
- Wire the agent-manifest delegation verifier as a check the runtime can call on an inbound peer request (Tier 1)

## v0.2: Runtime enforcement and sealed channel

- Runtime peer-delegation enforcement: **decision core landed** (`ca2a_runtime.peer.enforce_peer_call`: verify chain, intersect delegated scope with local policy, enforce, emit provenance record; claim C3 validated). Remaining: bind a Cedar policy engine as the local policy, and wire the decision core to a live A2A transport (Tier 2)
- Sealed peer channel: **landed** (`ca2a_runtime.channel`: HPKE-style X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305 sealing to the peer's attested key; claim C4 validated). Remaining: bind the seal to a verified attestation report on a live call, and rely on the enclave to hold the private key (hardware property)
- Linked runtime evidence: each hop's TRACE record references the parent record hash and delegation credential id, producing a verifiable delegation DAG (Tier 2)

## Critical path, sequenced first (Tier 3)

Real hardware attestation verification (SEV-SNP VCEK chain, Intel TDX quote via QVL/PCS, TPM AK cert + checkquote). This is a dependency for any cross-operator trust claim, single-agent or multi-agent, and is shared with cmcp. At least one real hardware backend must land before cA2A is marketed as attested across trust domains, so the demo matches the claim.

- **SEV-SNP verifier: landed.** Report parsing, VCEK chain verification (validated against the real AMD Milan root), ECDSA-P384 report-signature verification, and measurement/report-data binding, all fail-closed. Report generation still requires a real SEV-SNP guest. See `ca2a_verify.sev_snp` and [docs/spec/attestation.md](docs/spec/attestation.md).
- **TDX verifier: landed.** DCAP Quote v4 parsing, PCK chain to the genuine Intel SGX Root CA, QE report signature, attestation-key binding, quote signature, and MRTD binding, all fail-closed. Quote generation requires a real TDX guest. See `ca2a_verify.tdx`.
- **TPM 2.0 verifier: landed.** TPMS_ATTEST parsing, AK chain to a caller-supplied vendor root, AK signature (ECDSA or RSA), magic/type checks, and qualifying-data/PCR-digest binding, all fail-closed. Quote generation requires a real TPM. See `ca2a_verify.tpm`.
- **Cross-operator attestation (C6): validated in software.** A two-operator harness (SEV-SNP verifier + measurement pinning + sealed channel) shows independent keys, mutual attestation, confidential cross-operator delegation, and binary-swap detection. All six claims (C1-C6) are now validated experiments.
- **Pending:** end-to-end validation of the SEV-SNP, TDX, and TPM signature paths against real hardware quotes on a confidential VM; and a transport that parses real A2A wire messages into a `PeerRequest`.

## v1.0: Stable profile

- Stable delegation credential and TRACE link schema with documented versioning guarantees
- Full RATS/EAT conformance for peer attestation evidence
- Conformance suite for "cA2A-compatible" claims: **landed** (`tests/conformance/`, normative README + runnable MUST-level checks, in CI). A production run on confidential-computing hardware is the remaining step for a hardware-attested claim.
- OWASP liaison on the multi-agent threat mapping; ITI conversation on conformance
