# Emit and Verify Provenance

Build an unsigned record path, detect a broken link, and see why consistent hashes alone do not authenticate evidence. First run the Python blocks in [authoring a delegation credential](authoring-a-delegation-credential.md), which install the package and define a verified `chain` and independently retained `trusted_roots`. Continue in the same script or session.

## Emit one record per credential

```python
from ca2a_runtime.provenance import record_for, verify_dag, cross_check_chain

records = []
parent_hash = None
for i, credential in enumerate(chain):
    record = record_for(credential, record_id=f"rec-{i}", parent_record_hash=parent_hash)
    records.append(record)
    parent_hash = record.record_hash()

verify_dag(records)
cross_check_chain(records, chain)
print("3 records: links and credential references match")
```

Each record copies its credential's ID, subject, and delegated scope. The scope is the grant, not proof of completed actions. The canonical hash also covers caller-appraisal and any populated denial fields. These locally constructed records carry no independent signatures and do not show that a task ran.

## Detect an unrepaired change

```python
from dataclasses import replace
from ca2a_runtime.errors import ProvenanceLinkBroken

tampered = list(records)
tampered[1] = replace(records[1], scope=records[1].scope | {"cap:injected"})
try:
    verify_dag(tampered)
except ProvenanceLinkBroken:
    print("parent edit detected at its child")
else:
    raise AssertionError("broken parent link accepted")
```

Record 1's hash changed while record 2 still holds its old hash. Reparenting record 2 to the root instead of the preceding record is likewise rejected:

```python
reparented = list(records)
reparented[2] = replace(records[2], parent_record_hash=records[0].record_hash())
try:
    verify_dag(reparented)
except ProvenanceLinkBroken:
    print("reparenting detected")
else:
    raise AssertionError("wrong parent accepted")
```

## See the boundary

An attacker who can rewrite the entire unsigned path can recompute downstream links. The credential cross-check compares IDs and subjects, not every record field. This counterexample deliberately changes scope while retaining those references:

```python
repaired = list(tampered)
repaired[2] = replace(repaired[2], parent_record_hash=repaired[1].record_hash())
verify_dag(repaired)
cross_check_chain(repaired, chain)
assert repaired[1].scope != chain[1].scope
print("rewritten unsigned path passes consistency checks; authenticity is not established")
```

This does not change the signed delegation or grant additional runtime authority. It shows that hash consistency and credential references do not authenticate the record producer. A leaf edit has no child link to break at all.

## Use signed evidence for authenticity

The implemented TRACE binding signs records carrying delegation links. `verify_trace_dag` requires the recipient's trusted signing keys and checks signatures, structure, and parent links. `cross_check_trace_dag` then aligns non-root credential IDs with a separately verified chain. See the [verification library](../spec/verification-library.md).

Both path verifiers accept one ordered root-to-leaf sequence, not an arbitrary branching graph. Even signed authorization evidence does not establish task completion or completeness of the submitted history. For runtime checks, see [inbound peer-call decision](../spec/call-graph.md).
