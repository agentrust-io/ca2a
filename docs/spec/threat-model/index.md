# Threat Model

cA2A defends the delegation path between agents. This page states the adversary, the assets, and what is and is not in scope.

## Adversary

A capable adversary who may:

- Operate a peer agent in a trust domain cA2A does not control.
- Present a valid A2A Signed Agent Card while running tampered or unmeasured code.
- Sit on the network between two agents, or operate the host a peer runs on.
- Attempt to widen a delegated grant, replay a credential into another chain, or reparent a provenance record.
- Obtain a copy of a delegation chain issued to somebody else — from an audit bundle, a log, a published provenance DAG, or the wire — and present it as its own, including while honestly attesting its own runtime.

Out of adversary scope: breaking the underlying cryptographic primitives (Ed25519, the hash function), or compromising TEE firmware or hardware microcode. Those are the trust anchors.

## Assets

| Asset                                                             | Protected by                                                                                                   |
| ----------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| Bounded authority (a delegate must not exceed its grant)          | Scope attenuation in the [delegation chain](https://ca2a.agentrust-io.com/docs/spec/delegation-chain/index.md) |
| Peer integrity (only measured code is trusted)                    | Peer [attestation](https://ca2a.agentrust-io.com/docs/spec/attestation/index.md)                               |
| Task confidentiality (payload readable only by the intended peer) | [Sealed channel](https://ca2a.agentrust-io.com/docs/spec/sealed-channel/index.md)                              |
| Provenance (an unforgeable record of who delegated what)          | [TRACE A2A profile](https://ca2a.agentrust-io.com/docs/spec/trace-a2a-profile/index.md) delegation DAG         |

## Attacks and defenses

| Attack                                                                | Defense                                                                                                                                                                                                                                         |
| --------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Confused deputy: B acts with authority A never granted                | Attenuation: B's scope must be a subset of A's grant, checked per hop                                                                                                                                                                           |
| Tampered peer wearing a valid Agent Card                              | Attestation: measurement must match an expected value before a task is accepted                                                                                                                                                                 |
| Operator or network reads the task payload                            | Sealing to the peer's measurement; the path sees ciphertext                                                                                                                                                                                     |
| Credential replayed into another workflow                             | Unique `credential_id` and parent-link checks in chain verification                                                                                                                                                                             |
| A compromised delegate keeps using a grant inside its validity window | Revocation by the grant's issuer or an issuer above it, checked against a revocation snapshot the verifier supplies. Only as current as that snapshot; see residual risks                                                                       |
| A copied chain presented by a party it was not issued to              | Holder binding: the presenter must answer a callee-issued challenge with a signature under the leaf `subject` key (profile P-4a). Appraising the caller does not cover this: an attested runtime is not a claim to anyone's delegated authority |
| Attacker mints a self-consistent chain from its own root              | Callee pins locally trusted root issuer keys before policy evaluation                                                                                                                                                                           |
| Reparented or forged provenance                                       | Linked TRACE records; the DAG is verified offline against the chain. A hop cannot be reparented in flight either: the holder proof commits to `parent_record_hash`, so altering it invalidates the proof before a record is emitted             |

## Residual risks in this release

Because attestation and sealing are not yet implemented (Tier 2/3), this release defends bounded authority and provenance-of-intent (via signed chains) but does not yet defend peer integrity or task confidentiality at runtime. Do not rely on cA2A for confidentiality across a trust boundary until the sealed channel and a real attestation backend land. See [LIMITATIONS.md](https://ca2a.agentrust-io.com/LIMITATIONS/index.md).

**Holder binding is at-most-once per challenge window, not exactly-once.** The challenge in [profile](https://ca2a.agentrust-io.com/docs/spec/profile/index.md) P-4a is stateless by design and so cannot be consumed, which means a proof captured in flight stays usable until its challenge expires. The window is the challenge TTL, 60 seconds by default. Inside it, an adversary on the path can replay a complete request once more; the proof commits to the audience, capability, `record_id`, `parent_record_hash` and payload digest, so what can be replayed is that exact call rather than a new one. Outside it, the proof is dead.

Closing the window entirely needs state, and the place for it is the challenge rather than the proof, so that the profile carries one such decision instead of two. A deployment that requires exactly-once should supply a stateful challenge and accept the shared-store or sticky-routing cost that comes with it.

**Revocation is only as current as the verifier's data.** The issuer of a credential, or any issuer above it in the chain, can withdraw it before `not_after` by signing a revocation statement that names the credential by digest (see [delegation chain](https://ca2a.agentrust-io.com/docs/spec/delegation-chain/#ca2a-delegation-revocation)). A verifier given a revocation snapshot refuses a chain containing a revoked hop with `CREDENTIAL_REVOKED`, and every grant beneath that hop falls with it. A delegate cannot revoke its delegator, and a statement from any key outside that line of issuers has no effect.

P-4 still requires verification to work offline, so a verifier that has no snapshot still verifies, and it still cannot learn that a credential was revoked. What changed is that it is told so: the verification result reports revocation as `not_checked` rather than leaving the caller to assume. A verifier that has a snapshot knows what the snapshot held at its `as_of` time and nothing later. Whoever supplies snapshots can withhold a statement, though not forge one, since each statement is signed by its revoker. A verifier can set `max_revocation_staleness` to refuse to decide without a snapshot of bounded age; that bounds the window between a revocation being issued and a verifier acting on it, but does not close it. Getting statements to verifiers is the deployment's job, and cA2A defines no distribution protocol. The validity window remains the backstop for a verifier that never receives the statement.
