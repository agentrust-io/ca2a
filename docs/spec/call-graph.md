# Inbound Peer-Call Decision

When a cA2A peer receives an inbound A2A task, it runs a fixed sequence of checks before it acts on the task and after it acts. The order is not arbitrary: cheap, offline, deterministic checks run first, and each step fails closed so a later step never runs against unverified input. This page states the full intended enforcement order and marks, for each step, what the code does today versus what is design.

Steps 1 (chain verification), 3 (scope intersection), 4 (opening a sealed payload), and 5 (provenance emission) are composed into one transport-agnostic handler, `ca2a_runtime.peer.handle_peer_request`, which takes a parsed `PeerRequest` and runs the pipeline fail-closed. Step 2 has a SEV-SNP verifier (`ca2a_verify.sev_snp`), used counterparty-side to seal to a peer before sending (see the cross-operator flow), but is not part of the callee handler and needs real hardware to produce a report. What remains for a live deployment is a transport that parses actual A2A wire messages into a `PeerRequest`; cA2A leaves that to implementers by design (profile, not protocol). See [LIMITATIONS.md](../../LIMITATIONS.md) and [ROADMAP.md](../../ROADMAP.md).

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
3. intersect scope with policy  effective_scope(chain, local_policy)   [IMPLEMENTED (decision core)]
      |  the effective grant is delegated scope AND local policy
      v
4. seal payload to measurement  SealedChannel(peer_pub).seal(...)   [IMPLEMENTED (crypto); attestation binding pending]
      |  payload readable only with the peer's enclave-bound key
      v
5. emit linked provenance       enforce_peer_call(...) -> DelegationRecord
      |  DelegationRecord chained to the parent record   [IMPLEMENTED]
      v
   accept and act on the task
```

If any step raises, the call is denied. Absence of evidence is denial, not a warning (see the fail-closed tenet in [SPEC.md](../SPEC.md)).

## Status

| Step | What it enforces | Function / type | Status |
|---|---|---|---|
| 1. Chain verification | Signature, continuity, attenuation, depth bound, anti-replay | `verify_chain` | Implemented |
| 2. Peer attestation | Peer measurement matches an expected value | `ca2a_verify.sev_snp.verify_sev_snp_report` | SEV-SNP verifier implemented; not yet wired into the call path; report needs hardware |
| 3. Scope intersection | Delegated scope intersected with local policy | `ca2a_runtime.peer.effective_scope`, `enforce_peer_call` | Implemented (decision core); Cedar engine binding pending (#10) |
| 4. Payload sealing | Payload sealed to the peer's attested key | `SealedChannel.seal`, `open_sealed` | Implemented (crypto); binding to a verified report on the live path pending |
| 5. Provenance record | A `DelegationRecord` emitted and linked to its parent | `enforce_peer_call`, `record_for`, `verify_dag` | Implemented (emitted by the decision core) |
| Inbound pipeline handler | Verify, enforce, open sealed payload, emit record off a parsed request | `handle_peer_request`, `PeerRequest` | Implemented (transport-agnostic) |
| A2A wire parsing into a `PeerRequest` | Parse actual A2A extension fields into the handler's input | (implementer/transport) | Left to implementers by design |

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

The runtime confirms the peer is running attested, measured code before it is trusted with the task, by checking the peer's report measurement against an expected value under a fresh nonce. A SEV-SNP verifier exists (`ca2a_verify.sev_snp.verify_sev_snp_report`: VCEK chain, report-signature, measurement binding), but it is not yet wired into this call path, producing a report requires real SEV-SNP hardware, and TDX/TPM backends are not implemented. Verification fails closed when evidence is absent. Do not treat this step as active on the live path yet. See [attestation.md](attestation.md).

## Step 3: intersect scope with local policy (implemented as a decision core)

The effective authority for the task is the intersection of the delegated leaf scope (from step 1) with what the peer's own local policy permits. Delegation can only narrow authority, never widen it, so the peer's policy is an independent second bound on top of attenuation. This is implemented in `ca2a_runtime.peer`:

```python
from ca2a_runtime.peer import effective_scope, enforce_peer_call
from ca2a_runtime.policy import LocalPolicy

policy = LocalPolicy.of(["read", "audit"])
effective_scope(chain, policy)                       # delegated leaf scope AND policy allow
enforce_peer_call(chain, "read", policy=policy, record_id="rec-c")  # raises SCOPE_NOT_PERMITTED if not in the effective scope
```

A capability is granted only when it is both delegated down the chain and allowed by the local policy; a capability in one but not the other is denied with `SCOPE_NOT_PERMITTED`. The `LocalPolicy` here is a capability allow set; binding a full Cedar policy engine (as cMCP does) is tracked separately (#10). What is not yet wired is the live inbound transport: `enforce_peer_call` is the decision the runtime makes, not yet driven off an actual A2A request. See [cedar-policy.md](cedar-policy.md).

## Step 4: seal the payload to the peer's attested key (crypto implemented)

Once the peer's attested public key is known (from its report, step 2), the task payload is sealed to it so only the holder of the peer's private key can open it. The channel is implemented (`SealedChannel(peer_pub).seal(...)` and `open_sealed(...)`, an HPKE-style X25519 -> HKDF-SHA256 -> ChaCha20-Poly1305 scheme). `open_sealed` fails closed with `SEALED_CHANNEL_ERROR` on a wrong key or tampered ciphertext. The property that the payload decrypts *only inside the attested measurement* rests on the private key being enclave-bound (a hardware property from attestation), and binding the seal to a verified report on the live path is still to be wired. See [sealed-channel.md](sealed-channel.md).

## Step 5: emit a linked provenance record (implemented)

After the task is accepted, `enforce_peer_call` emits a `DelegationRecord` that references its parent record by hash and names the credential it acted under. The record model, the offline DAG verifier, and the binding to the delegation chain exist today:

```python
from ca2a_runtime.provenance import record_for, verify_dag, cross_check_chain

# Build this hop's record, linked to the parent record's hash.
record = record_for(leaf, record_id="rec-c", parent_record_hash=parent_hash)

# Offline: parent links match recomputed hashes, no record_id repeats.
verify_dag(records)                # raises PROVENANCE_LINK_BROKEN on tampering
cross_check_chain(records, chain)  # record i must match credential i (id + subject)
```

`enforce_peer_call` produces this record for the accepted hop, linked to the parent by hash. `verify_dag` raises `PROVENANCE_LINK_BROKEN` if a record was tampered with or reparented, because the stored `parent_record_hash` no longer matches the recomputed hash of the preceding record, and `cross_check_chain` ties provenance to authority. What remains is driving emission off a live inbound A2A request rather than a direct `enforce_peer_call`. The record format and DAG semantics are the runtime-evidence side of the profile; see [trace-a2a-profile.md](trace-a2a-profile.md) and [provenance-dag.md](provenance-dag.md).

## Why this order

Each step is a precondition for the next, so ordering is a safety property:

- Chain verification (1) runs first because it is offline and deterministic and establishes the delegated scope every later step reasons about.
- Attestation (2) precedes sealing (4) because the payload is sealed to the measurement attestation produces; sealing to an unverified measurement would be meaningless.
- Scope intersection (3) precedes acting on the task because the effective grant, not the raw delegated scope, is what the peer is allowed to exercise.
- Provenance emission (5) runs after the task is accepted so the record reflects what was actually done, and it links to the parent record so the workflow forms a verifiable DAG.

This release enforces bounded authority and local-policy intersection (steps 1 and 3) and emits and verifies linked provenance records (step 5) through the `enforce_peer_call` decision core. It does not yet enforce peer integrity or payload confidentiality (steps 2 and 4), and the decision core is not yet wired to a live A2A transport. See the residual-risks section of the [threat-model.md](threat-model.md).
