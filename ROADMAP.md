# cA2A Roadmap

cA2A is an extension of the agentrust-io stack, not a rewrite. The build tiers below track how much each piece leans on primitives that already exist in [agent-manifest](https://github.com/agentrust-io/agent-manifest), [cmcp](https://github.com/agentrust-io/cmcp), and [trace-spec](https://github.com/agentrust-io/trace-spec).

## Reused as-is (Tier 0)

Already implemented and tested elsewhere; cA2A depends on it rather than reimplementing it.

- Capability attenuation with scope narrowing: signed delegation chain, child scope cannot exceed parent, depth limits, cross-manifest replay protection, HITL approval signing (agent-manifest)
- Pluggable TEE provider abstraction with measurement-bound keys (cmcp)
- Attestation-gated SPIFFE mTLS (cmcp)
- Audit chain with external signed evidence references (cmcp)
- Cedar policy engine (cmcp)
- Ed25519 + RFC 8785 canonicalization (all three repos)

## v0.1: Profile and offline verifier

- cA2A profile specification published as an A2A binding (`docs/SPEC.md`)
- TRACE A2A profile: optional delegation-link block (parent record hash + delegation credential id) and its validation (Tier 1, coordinated in trace-spec)
- `ca2a-verify`: offline verification of a delegation chain and the delegation DAG, reusing the agent-manifest verifier
- Wire the agent-manifest delegation verifier as a check the runtime can call on an inbound peer request (Tier 1)

## v0.2: Runtime enforcement and sealed channel

- Runtime peer-delegation enforcement: accept a delegation credential on an inbound peer call, verify chain and attenuation, intersect delegated scope with local Cedar policy, enforce (Tier 2)
- Sealed peer channel: extend the attestation-gated key pattern to peer-to-peer, so the task payload decrypts only inside the peer's verified enclave (Tier 2)
- Linked runtime evidence: each hop's TRACE record references the parent record hash and delegation credential id, producing a verifiable delegation DAG (Tier 2)

## Critical path, sequenced first (Tier 3)

Real hardware attestation verification (SEV-SNP VCEK chain, Intel TDX quote via QVL/PCS, TPM AK cert + checkquote). This is a dependency for any cross-operator trust claim, single-agent or multi-agent, and is shared with cmcp. At least one real hardware backend must land before cA2A is marketed as attested across trust domains, so the demo matches the claim.

## v1.0: Stable profile

- Stable delegation credential and TRACE link schema with documented versioning guarantees
- Full RATS/EAT conformance for peer attestation evidence
- Conformance suite for "cA2A-compatible" claims
- OWASP liaison on the multi-agent threat mapping; ITI conversation on conformance
