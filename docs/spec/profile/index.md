# A2A Profile Binding

cA2A binds to A2A v1.x as an overlay. This page states normatively what the profile adds and where it attaches, without modifying A2A itself.

## Requirements language

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document and the other pages under `docs/spec/` are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) ([RFC 2119](https://www.rfc-editor.org/rfc/rfc2119), [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174)) when, and only when, they appear in all capitals.

A requirement stated here that this implementation does not yet meet is marked inline. The profile states the requirement; it does not describe the implementation as conformant where it is not. See [LIMITATIONS.md](https://ca2a.agentrust-io.com/LIMITATIONS/index.md).

## Scope of this profile

This profile defines how a delegated A2A task carries verifiable authority, confidentiality, and provenance. It does not define a transport, a message framing, an identity issuance scheme, or a policy language.

## What A2A provides

A2A moves tasks and context between agents and authenticates a peer's domain via the Signed Agent Card. cA2A treats the Agent Card as the identity anchor and adds a trust envelope around each delegated task.

## What cA2A adds

| A2A element  | cA2A addition                                                                          |
| ------------ | -------------------------------------------------------------------------------------- |
| Agent Card   | An attestation measurement expectation for the peer, checked before a task is accepted |
| Task message | A delegation credential naming issuer, subject, scope, depth, and parent link          |
| Task payload | Sealing to the peer's attested measurement                                             |
| (none)       | A TRACE record per hop linking to the parent, forming the delegation DAG               |

## Normative requirements

### P-1 Overlay

A cA2A implementation MUST NOT change A2A wire formats, routing, or endpoints. Removing every cA2A field from a message MUST leave a valid A2A task. cA2A data MUST travel in A2A extension fields as defined in [transport](https://ca2a.agentrust-io.com/docs/spec/transport/index.md).

### P-2 Extension declaration

An agent supporting this profile MUST declare the extension URI in its Agent Card, and a client opting in MUST signal it per the A2A extension mechanism (the `A2A-Extensions` header for HTTP and JSON-RPC bindings, or the equivalent binding metadata). The extension URI for this version is given in [transport](https://ca2a.agentrust-io.com/docs/spec/transport/index.md).

### P-3 Ignore versus enforce

A peer that does not implement this profile MUST ignore the cA2A extension fields and handle the task as ordinary A2A. A peer that does implement it:

- MUST treat a message carrying no cA2A keys as ordinary A2A input, and MUST NOT synthesize a partial trust state from their absence;
- MUST fail closed when any cA2A key is present but the cA2A metadata is malformed or incomplete;
- MUST run the inbound enforcement pipeline (P-4 through P-8) on a well-formed cA2A message before acting on the task.

### P-4 Attenuated delegation

A callee MUST verify the presented delegation chain before acting: every credential's signature, the continuity of each parent link, and the attenuation rule that a child's scope is a subset of its parent's. A callee MUST reject a chain whose depth exceeds its configured maximum, and MUST reject a credential replayed from a different chain. Verification MUST be possible offline, without contacting the issuer.

### P-4a Holder binding

A callee MUST NOT act on a delegation chain until the presenter has proved it controls the private key of the leaf credential's `subject`. The callee MUST issue the challenge the proof answers, and MUST reject a proof that does not commit to the callee's own identity, that challenge, the leaf `credential_id` and `subject`, the requested capability, the `record_id`, the sealed payload if one is present, and the caller's own offered channel key if one is present. A chain presented without such a proof MUST be refused with `HOLDER_PROOF_INVALID`.

Holder binding MUST be evaluated after chain verification, so the subject is a key someone was genuinely delegated rather than one the caller asserted, and before the effective scope is computed under P-5, so a caller that has proved nothing never reaches policy evaluation and never elicits a signed denial record.

**This is not P-6.** Appraising a caller establishes what it is *running*; holder binding establishes *whose authority it holds*. The two are independent and neither implies the other: a caller can present a flawless `caller_offer`, appraise at hardware assurance, and still be exercising a chain issued to somebody else, because an attested runtime is not a claim to anyone's delegated authority. Without P-4a a chain is a bearer credential, and chains are published deliberately — handed to auditors for offline verification under P-8, embedded in provenance DAGs, and shipped as fixtures.

The binding key is already in the credential and needs no new trust root: `subject` is an Ed25519 public key whose private half the delegate must hold in order to issue child credentials, and before this it was only ever compared as a string for continuity. The proof commits to the caller's offered channel key so that, when both mechanisms are in play, the attested runtime and the delegated principal are provably the same party — which neither mechanism establishes alone. This is the RFC 7800 `cnf` pattern, matching what the TRACE layer already applies to provenance records.

A callee MAY accept a chain without a proof only for offline replay of recorded evidence, where no live caller exists to answer a challenge. It MUST NOT do so on a live peer path.

A callee SHOULD honour each proof at most once. `ca2a_runtime.challenge` is stateless by design and so cannot be consumed, which means single-use has to come from remembering the proof rather than the challenge; `ProofReplayCache` does that, and `PeerNode` uses one by default with a TTL matching its own challenge TTL. A callee that remembers nothing degrades to at-most-once-per-window, where a captured proof stays usable until its challenge expires.

Where a proof is remembered, it MUST be recorded only after it has verified. Recording earlier would let a party that holds none of the keys fill the store, or insert a signature to lock the real delegate out of its own proof.

> The cache is bounded, and the bound is honest: past its capacity the oldest entry is evicted, so a flood of distinct valid proofs can push an earlier one out and let it be replayed inside its window. Refusing new calls instead would turn the same flood into an outage. So the property is exactly-once up to capacity, degrading to the challenge window under flood. A deployment across several instances wants a shared store or sticky routing, the same caveat the challenge secret already carries.

### P-5 Effective scope

A callee MUST compute the effective scope as the leaf credential's delegated scope intersected with the callee's own local policy, and MUST refuse any requested capability outside that intersection. A capability the local policy permits but the chain did not delegate MUST be refused. Neither input alone is sufficient authority.

### P-6 Peer attestation

Before accepting a delegated task across a trust boundary, a peer SHOULD be required to present attestation evidence binding its channel key to a measured runtime, and the caller MUST appraise that evidence against its expected measurement before sealing anything to that key. A caller that cannot appraise the evidence MUST NOT treat the peer as attested.

> Met one-directionally as of 2026-07-27. Driven off a live SEV-SNP quote on a running confidential VM, `verify_offer` returned `assurance="hardware"` and a payload was sealed to a channel key that a hardware-verified measurement vouches for. A cross-operator, cross-TEE run followed: an Azure SEV-SNP peer calling a GCP Intel TDX peer.
>
> Two limits remain, and P-6 is not fully met until both close. **On hardware the appraisal is still one-directional**: in the recorded runs the caller appraised the callee and not the reverse, so neither side has yet proven itself to a peer that is simultaneously proving itself back. The protocol no longer is: as of 2026-08-09 a callee issues a challenge and appraises the caller's offer before opening the sealed payload, off by default and in software mode only ([mutual-attestation](https://ca2a.agentrust-io.com/docs/spec/mutual-attestation/index.md)). Making the protocol mutual does not make the recorded hardware run mutual, and it does not make the exchange simultaneous — the caller still commits a sealed payload before the callee has appraised it. And the committed harness in `examples/` still runs software-attested against synthetic vectors, because genuine evidence embeds per-CPU identifiers and is not shippable as a fixture. See [attestation](https://ca2a.agentrust-io.com/docs/spec/attestation/index.md) and [hardware-validation](https://ca2a.agentrust-io.com/docs/hardware-validation/index.md).

### P-7 Sealed payload

When a caller seals a task payload, the payload MUST be readable only by the holder of the peer key appraised under P-6, and the sealed bytes on the wire MUST be opaque ciphertext. An implementation MUST NOT describe a payload as confined to a measurement unless the key it was sealed to was bound to a hardware-verified measurement.

### P-8 Provenance

Every hop MUST emit a provenance record naming the credential it acted under and linking to its parent record by hash, so that tampering with any record breaks its child's link. A refusal MUST also emit a record, stating the capability requested and the effective scope it fell outside; a refused hop MUST be terminal, and a verifier MUST reject a chain that continues past one. The resulting DAG MUST be verifiable offline by a party that trusts neither operator.

### P-9 Honest assurance

A record produced without hardware attestation MUST NOT claim a hardware assurance level. Software-mode records are Level 0.

## Attachment points

cA2A does not change A2A wire formats. The delegation credential and the sealing metadata travel in A2A extension fields, so an A2A implementation that does not understand cA2A ignores them and a cA2A-aware peer enforces them. This is what keeps the profile an overlay rather than a fork.

## Conformance

An implementation claiming conformance MUST satisfy every MUST in this document. [conformance.md](https://ca2a.agentrust-io.com/docs/spec/conformance/index.md) maps these requirements onto the runnable checks in `tests/conformance/`, which is what a "cA2A-compatible" claim is measured against.

## Stability

This binding targets A2A v1.x extension points. Confirming that those extension points are stable enough to bind to is a precondition on the roadmap; see [ROADMAP.md](https://ca2a.agentrust-io.com/ROADMAP/index.md).
