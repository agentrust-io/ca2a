# Threat Model

cA2A defends the delegation path between agents. This page states the adversary, the assets, and what is and is not in scope.

## Adversary

A capable adversary who may:

- Operate a peer agent in a trust domain cA2A does not control.
- Present a valid A2A Signed Agent Card while running tampered or unmeasured code.
- Sit on the network between two agents, or operate the host a peer runs on.
- Attempt to widen a delegated grant, replay a credential into another chain, or reparent a provenance record.

Out of adversary scope: breaking the underlying cryptographic primitives (Ed25519, the hash function), or compromising TEE firmware or hardware microcode. Those are the trust anchors.

## Assets

| Asset | Protected by |
|---|---|
| Bounded authority (a delegate must not exceed its grant) | Scope attenuation in the [delegation chain](delegation-chain.md) |
| Peer integrity (only measured code is trusted) | Peer [attestation](attestation.md) |
| Task confidentiality (payload readable only by the intended peer) | [Sealed channel](sealed-channel.md) |
| Provenance (an unforgeable record of who delegated what) | [TRACE A2A profile](trace-a2a-profile.md) delegation DAG |

## Attacks and defenses

| Attack | Defense |
|---|---|
| Confused deputy: B acts with authority A never granted | Attenuation: B's scope must be a subset of A's grant, checked per hop |
| Tampered peer wearing a valid Agent Card | Attestation: measurement must match an expected value before a task is accepted |
| Operator or network reads the task payload | Sealing to the peer's measurement; the path sees ciphertext |
| Credential replayed into another workflow | Unique `credential_id` and parent-link checks in chain verification |
| Reparented or forged provenance | Linked TRACE records; the DAG is verified offline against the chain |

## Residual risks in this release

Because attestation and sealing are not yet implemented (Tier 2/3), this release defends bounded authority and provenance-of-intent (via signed chains) but does **not** yet defend peer integrity or task confidentiality at runtime. Do not rely on cA2A for confidentiality across a trust boundary until the sealed channel and a real attestation backend land. See [LIMITATIONS.md](../../LIMITATIONS.md).
