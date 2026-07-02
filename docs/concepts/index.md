# How It Works

cA2A is a trust profile layered on A2A. It does not move tasks or replace the transport. It adds the trust guarantees A2A's Signed Agent Card leaves out, by composing four primitives.

## The gap cA2A closes

A2A's Signed Agent Card answers one question: did the domain owner issue this card. It does not establish that a peer runs attested code, that a delegating agent actually holds the authority it passes on, that the task payload is confidential to the peer, or that there is an unbroken record of who delegated what to whom. See [the threat model](https://ca2a.agentrust-io.com/docs/spec/threat-model/index.md) for the adversary this admits.

## The four primitives

### 1. Attenuated delegation

Each hop carries a signed delegation credential. The scope granted at a hop must be a provable subset of its parent's scope. Depth is bounded, and a credential cannot be replayed into another chain. This is the hardest primitive to get right, and it is already implemented and tested in [agent-manifest](https://github.com/agentrust-io/agent-manifest); cA2A reuses those semantics. See [delegation chain](https://ca2a.agentrust-io.com/docs/spec/delegation-chain/index.md).

### 2. Runtime attestation

Before a peer is trusted with a delegated task, it proves it is running attested, measured code. cA2A reuses the pluggable TEE provider abstraction from cmcp: a provider produces an attestation report binding a public key to a hardware measurement. See [attestation](https://ca2a.agentrust-io.com/docs/spec/attestation/index.md).

### 3. Sealed peer channel

The task payload is sealed to the peer's attested measurement, so it decrypts only inside the peer's verified enclave. A connectivity provider or a peer in another trust domain sees ciphertext. See [sealed channel](https://ca2a.agentrust-io.com/docs/spec/sealed-channel/index.md).

### 4. Provenance record

Each hop emits a TRACE record that references its parent record's hash and the delegation credential id. Across A to B to C this produces a delegation DAG that any verifier can check offline, without trusting an operator. See [the TRACE A2A profile](https://ca2a.agentrust-io.com/docs/spec/trace-a2a-profile/index.md).

## How they compose on a peer call

```
Agent A --(delegation cred, scope S_A)--> Agent B --(scope S_B ⊆ S_A)--> Agent C
```

1. A issues B a child credential with `S_B ⊆ S_A`, signed over the canonical form of the grant.
1. Before B accepts, the cA2A runtime verifies the chain, verifies B's attestation measurement, and intersects `S_B` with B's local Cedar policy.
1. The payload is sealed to B's measurement.
1. B emits a TRACE record linking to A's record.

## Profile, not protocol

cA2A binds to A2A the way TRACE binds to IETF RATS, EAT, and SCITT: it is an overlay, not a competitor. This keeps it neutral across org, cloud, and TEE-vendor boundaries, which is the claim a vendor-anchored verifier cannot make.
