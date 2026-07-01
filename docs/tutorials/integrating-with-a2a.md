# Integrating with A2A

This tutorial walks through how cA2A attaches to an existing A2A deployment: where the delegation credential and sealing metadata ride, the order a peer enforces them on an inbound call, and, most important, the line between what an integrator can do today and what is still design.

Read this as a design tutorial with a working core. The offline half (build and verify chains, emit and verify provenance) runs against the shipped API right now. The live runtime peer path that reads these fields off the wire and enforces them on an inbound call is Tier 2 and is not yet built. See [LIMITATIONS.md](../../LIMITATIONS.md) and [ROADMAP.md](../../ROADMAP.md). Nothing below asks you to deploy unbuilt enforcement.

## What cA2A adds to A2A, and what it does not

A2A moves tasks between agents and authenticates a peer's domain with the Signed Agent Card. cA2A does not replace any of that. It rides inside A2A as an overlay and adds a trust envelope around a delegated task. Removing every cA2A field leaves a valid A2A task. For the full binding, see [transport.md](../spec/transport.md).

Two pieces of cA2A data travel with a task, carried in A2A extension fields:

- The **delegation credential**, or the chain root-to-leaf, naming issuer, subject, scope, depth, and parent link. See [delegation-chain.md](../spec/delegation-chain.md).
- The **sealing metadata**, binding the task payload to the peer's attested measurement. Sealing itself is Tier 2 and fails closed today. See [sealed-channel.md](../spec/sealed-channel.md).

A non-cA2A peer does not understand the extension fields and ignores them, handling the task as a plain A2A task. A cA2A peer reads them and enforces them before accepting. That asymmetry is what lets a cA2A deployment interoperate with A2A peers that have never heard of cA2A.

## The intended inbound enforcement order

When a cA2A peer receives an inbound task, the design calls for a fixed sequence. Cheap, offline, deterministic checks run first, and each step fails closed so a later step never runs against unverified input. Only step 1 and the record half of step 5 exist today. The full order and per-step status is specified in [call-graph.md](../spec/call-graph.md).

```
inbound A2A task
      |
      v
1. verify delegation chain      verify_chain(chain, max_depth)   [IMPLEMENTED]
      v
2. verify peer attestation      expected measurement             [PENDING, Tier 3]
      v
3. intersect scope with policy  leaf scope AND local Cedar        [PENDING, Tier 2]
      v
4. seal payload to measurement  SealedChannel.seal(...)           [PENDING, Tier 2]
      v
5. emit linked provenance       record_for -> verify_dag          [record model IMPLEMENTED]
      v
   accept and act on the task
```

If any step raises, the call is denied. That is the fail-closed tenet in [SPEC.md](../SPEC.md): absence of evidence is denial, not a warning.

## What you can do today

Two things work now against the shipped API, both offline and deterministic. Neither requires the runtime peer path, hardware, or a live A2A connection.

### 1. Build and verify a delegation chain

Mint keys, issue attenuated credentials hop by hop, and verify the chain. `verify_chain` raises the specific `CA2AError` for the first invariant that fails.

```python
from ca2a_runtime.delegation.credential import (
    DelegationCredential,
    new_keypair,
    verify_chain,
)

a_priv, a_pub = new_keypair()
b_priv, b_pub = new_keypair()
c_priv, c_pub = new_keypair()

# A grants B a bounded slice of its authority.
root = DelegationCredential(
    credential_id="cred-a",
    issuer=a_pub,
    subject=b_pub,
    scope=frozenset({"cap:read", "cap:write"}),
    depth=0,
    parent_id=None,
).sign(a_priv)

# B narrows further and delegates to C. Scope must be a subset of the parent.
child = DelegationCredential(
    credential_id="cred-b",
    issuer=b_pub,
    subject=c_pub,
    scope=frozenset({"cap:read"}),
    depth=1,
    parent_id="cred-a",
).sign(b_priv)

chain = [root, child]
verify_chain(chain, max_depth=8)  # raises on the first violation
```

The same chain verifies from a JSON file, which is what the CLI and `ca2a_verify` do:

```python
from ca2a_verify import verify_chain_file
from ca2a_runtime.errors import CA2AError

try:
    result = verify_chain_file("examples/minimal/chain.json")
    print(f"verified {result.hops} hops, leaf scope {result.leaf_scope}")
except CA2AError as exc:
    print(f"rejected: {exc.code}: {exc}")
```

```bash
ca2a verify-chain --chain examples/minimal/chain.json
# {"verified": true, "hops": 2, "leaf_scope": ["cap:read"]}
```

This is exactly step 1 of the inbound order above. A chain extracted from A2A extension fields is the same `list[DelegationCredential]` the CLI verifies from a file. For a full walkthrough that breaks each invariant, see [verify-a-delegation-chain.md](verify-a-delegation-chain.md) and [authoring-a-delegation-credential.md](authoring-a-delegation-credential.md).

### 2. Emit and verify provenance

For each hop, build a `DelegationRecord` linked to its parent record by hash, then verify the resulting DAG offline. This is the runtime-evidence side of the profile (step 5's record model).

```python
from ca2a_runtime.provenance import record_for, verify_dag, cross_check_chain

# Root hop: no parent link.
rec_a = record_for(root, record_id="rec-a", parent_record_hash=None)
# Child hop: linked to the parent record's hash.
rec_b = record_for(child, record_id="rec-b", parent_record_hash=rec_a.record_hash())

records = [rec_a, rec_b]
verify_dag(records)                 # raises PROVENANCE_LINK_BROKEN on tampering
cross_check_chain(records, chain)   # record i must match credential i (id + subject)
```

`verify_dag` recomputes each record's hash and checks it against the child's stored `parent_record_hash`, so a tampered or reparented record is caught. `cross_check_chain` ties each record back to the credential it acted under. See [emit-and-verify-provenance.md](emit-and-verify-provenance.md) and [provenance-dag.md](../spec/provenance-dag.md).

### Validate the runtime config surface

The runtime peer path is not built, but its configuration surface is defined and validated today. You can author and check a config so a deployment is ready when Tier 2 lands.

```yaml
# ca2a config
attestation:
  provider: auto
  enforcement_mode: enforcing
max_delegation_depth: 8
```

```bash
ca2a validate-config --config ca2a.yaml
# ok: provider=auto enforcement=enforcing
```

`Ca2aConfig` accepts `provider` from `auto`, `tpm`, `sev-snp`, `tdx`, `opaque`, `software-only`, and `enforcement_mode` from `enforcing`, `advisory`, `silent`. Hardware providers `detect()` to `False` until their backend lands, so `auto` never selects one silently. `max_delegation_depth` is passed straight through to `verify_chain`. The config is parsed and validated now; the runtime that consumes it on a live inbound call is Tier 2.

## What awaits Tier 2 and Tier 3

Do not present any of the following as usable. They are design today, and the code fails closed rather than pretend otherwise.

| Capability | Step | Status | What happens today |
|---|---|---|---|
| Runtime peer-call enforcement | reads chain off the wire, gates the inbound call | Tier 2, not built | No live path accepts a credential on an inbound A2A task |
| Peer attestation check | 2 | Tier 3, not built | `detect()` is `False` for all hardware providers; verification fails closed (`ATTESTATION_UNSUPPORTED` / `ATTESTATION_FAILED`) |
| Cedar scope intersection | 3 | Tier 2, not built | Runtime does not consult a policy; `policy_bundle_path` only reserves the surface |
| Sealed payload channel | 4 | Tier 2, fails closed | `SealedChannel.seal` / `open` raise `SEALED_CHANNEL_ERROR` rather than send plaintext |
| Live provenance emission | 5b | Tier 2, not built | The runtime does not emit and link records automatically on the inbound path |

Two consequences follow directly for an integrator:

- **Do not send confidential task payloads across a trust boundary and assume they are protected.** The sealed channel is not implemented; it fails closed. Confidentiality of the payload is a Tier 2 guarantee.
- **Do not describe a cA2A deployment as attested across trust domains.** No hardware backend verifies a quote yet. Attestation (step 2) is Tier 3 and is the sequenced-first critical path shared with cmcp.

## A staged integration path

Given the above, the honest way to adopt cA2A today:

1. **Issue and carry credentials.** Have your delegating agent mint attenuated `DelegationCredential`s hop by hop and attach the chain in A2A extension fields. Removing them leaves a valid A2A task, so this is non-breaking.
2. **Verify offline at the receiving end.** Reconstruct the chain from the extension fields and run `verify_chain` before your own application logic acts on the task. This gives you bounded authority (step 1) today, out of band from the transport.
3. **Emit provenance.** For each hop, build a `DelegationRecord` and keep the DAG so any third party can verify who delegated what to whom, offline, without trusting an operator.
4. **Stage the config.** Author a `Ca2aConfig` with `enforcement_mode: enforcing` so the deployment is ready to fail closed when the runtime path lands.
5. **Wait for Tier 2/3 before relying on peer integrity, local-policy intersection, or payload confidentiality.** These are not shortcuts you can turn on; the code fails closed until the backends exist.

## What you proved

You attached cA2A's trust envelope to an A2A task and verified bounded delegated authority and its provenance offline, without trusting whoever produced them. That is the property cA2A carries into the runtime peer path once attestation, scope intersection, and sealing land. For the adversary this staged posture still admits, see the residual-risks section of [threat-model.md](../spec/threat-model.md).
