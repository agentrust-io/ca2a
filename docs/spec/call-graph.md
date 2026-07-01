# Inbound Peer-Call Decision

When a cA2A peer receives an inbound A2A task, it runs a fixed sequence of checks before it acts on the task and after it acts. The order is not arbitrary: cheap, offline, deterministic checks run first, and each step fails closed so a later step never runs against unverified input. This page states the full intended enforcement order and marks, for each step, what the code does today versus what is design.

Only step 1 (chain verification) and the provenance-emission half of step 5 exist today. Steps 2, 3, and 4, and the cross-chain binding half of step 5, are Tier 2 or Tier 3 and are not yet implemented. See [LIMITATIONS.md](../../LIMITATIONS.md) and [ROADMAP.md](../../ROADMAP.md).

## Decision flow

```
inbound A2A task
      |
      v
1. verify delegation chain      verify_chain(chain, max_depth)   [IMPLEMENTED]
      |  signature, continuity, attenuation, depth, replay
      v
2. verify peer attestation      provider.attest / expected measurement   [PENDING, Tier 3]
      |  measurement must match an expected value
      v
3. intersect scope with policy  leaf scope AND local Cedar policy   [PENDING, Tier 2]
      |  the effective grant is the intersection
      v
4. seal payload to measurement  SealedChannel.seal(...)   [PENDING, Tier 2]
      |  payload readable only inside the peer's enclave
      v
5. emit linked provenance       record_for(...) -> verify_dag / cross_check_chain
      |  DelegationRecord chained to the parent record   [record model IMPLEMENTED]
      v
   accept and act on the task
```

If any step raises, the call is denied. Absence of evidence is denial, not a warning (see the fail-closed tenet in [SPEC.md](../SPEC.md)).

## Status

| Step | What it enforces | Function / type | Status |
|---|---|---|---|
| 1. Chain verification | Signature, continuity, attenuation, depth bound, anti-replay | `verify_chain` | Implemented |
| 2. Peer attestation | Peer measurement matches an expected value | `BaseProvider.attest`, `AttestationReport.measurement` | Pending, Tier 3 |
| 3. Scope intersection | Delegated scope intersected with local Cedar policy | (design) | Pending, Tier 2 |
| 4. Payload sealing | Payload sealed to the peer measurement | `SealedChannel.seal` | Pending, Tier 2 (fails closed) |
| 5a. Provenance record | A `DelegationRecord` linked to its parent by hash | `record_for`, `verify_dag`, `cross_check_chain` | Implemented (record model) |
| 5b. Runtime emission on the live path | The peer emits the record on the inbound path and binds it to the chain | (design) | Pending, Tier 2 |

## Step 1: verify the delegation chain (implemented)

The inbound credential is verified as the leaf of a root-to-leaf chain. `verify_chain` raises the specific error for the first invariant that fails: signature (`INVALID_CREDENTIAL`), continuity and depth-step (`BROKEN_DELEGATION_LINK`), depth bound (`DELEGATION_DEPTH_EXCEEDED`), attenuation (`SCOPE_ESCALATION`), and anti-replay (`CREDENTIAL_REPLAY`). See [delegation-chain.md](delegation-chain.md) and [error-codes.md](error-codes.md).

```python
from ca2a_runtime.delegation import DelegationCredential, verify_chain

# chain is the root-to-leaf list carried with the inbound task.
verify_chain(chain, max_depth=8)  # raises on the first violation
leaf = chain[-1]
delegated_scope = leaf.scope  # frozenset[str], the authority to enforce below
```

`max_depth` comes from `Ca2aConfig.max_delegation_depth` (default 8). This step is deterministic and offline: it contacts no operator and depends only on the signed bytes. It is the only step that gates an inbound call in this release.

## Step 2: verify peer attestation (pending, Tier 3)

The runtime is intended to confirm the peer is running attested, measured code before it is trusted with the task, by checking the peer's `AttestationReport.measurement` against an expected value under a fresh nonce. Today no hardware backend verifies a quote: `BaseProvider.detect` returns `False` for all hardware providers, so they are never selected, and verification fails closed when evidence is absent. Do not treat this step as active. See [attestation.md](attestation.md).

## Step 3: intersect scope with local Cedar policy (pending, Tier 2)

The effective authority for the task is intended to be the intersection of the delegated leaf scope (from step 1) with what the peer's own local Cedar policy permits. Delegation can only narrow authority, never widen it, so the peer's policy is an independent second bound on top of attenuation. This intersection is not implemented; the runtime does not yet consult a Cedar policy on the inbound path. `Ca2aConfig.policy_bundle_path` reserves the configuration surface. See [cedar-policy.md](cedar-policy.md).

## Step 4: seal the payload to the peer measurement (pending, Tier 2)

Once the peer measurement is verified (step 2), the task payload is intended to be sealed to that measurement so it decrypts only inside the peer's verified enclave. Today `SealedChannel.seal` and `SealedChannel.open` raise `SEALED_CHANNEL_ERROR` rather than send plaintext. Do not send confidential payloads across a trust boundary and assume they are protected. See [sealed-channel.md](sealed-channel.md).

## Step 5: emit a linked provenance record (record model implemented; live emission pending)

After the task is accepted, the hop emits a `DelegationRecord` that references its parent record by hash and names the credential it acted under. The record model, the offline DAG verifier, and the binding to the delegation chain exist today:

```python
from ca2a_runtime.provenance import record_for, verify_dag, cross_check_chain

# Build this hop's record, linked to the parent record's hash.
record = record_for(leaf, record_id="rec-c", parent_record_hash=parent_hash)

# Offline: parent links match recomputed hashes, no record_id repeats.
verify_dag(records)                # raises PROVENANCE_LINK_BROKEN on tampering
cross_check_chain(records, chain)  # record i must match credential i (id + subject)
```

`verify_dag` raises `PROVENANCE_LINK_BROKEN` if a record was tampered with or reparented, because the stored `parent_record_hash` no longer matches the recomputed hash of the preceding record. `cross_check_chain` ties provenance to authority. What is not yet wired is emission on the live inbound path: the runtime does not yet produce and link these records automatically as part of accepting a peer call. The record format and DAG semantics are the runtime-evidence side of the profile; see [trace-a2a-profile.md](trace-a2a-profile.md) and [provenance-dag.md](provenance-dag.md).

## Why this order

Each step is a precondition for the next, so ordering is a safety property:

- Chain verification (1) runs first because it is offline and deterministic and establishes the delegated scope every later step reasons about.
- Attestation (2) precedes sealing (4) because the payload is sealed to the measurement attestation produces; sealing to an unverified measurement would be meaningless.
- Scope intersection (3) precedes acting on the task because the effective grant, not the raw delegated scope, is what the peer is allowed to exercise.
- Provenance emission (5) runs after the task is accepted so the record reflects what was actually done, and it links to the parent record so the workflow forms a verifiable DAG.

Because steps 2, 3, and 4 are not yet implemented, this release enforces bounded authority (step 1) and can produce and verify provenance records offline (step 5 model), but it does not yet enforce peer integrity, local policy, or payload confidentiality on the live path. See the residual-risks section of the [threat-model.md](threat-model.md).
