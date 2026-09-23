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

The CLI now separates authenticated lineage from structural diagnostics:

```bash
ca2a verify-lineage --dag signed-trace-records.json --chain chain.json \
  --trusted-root-issuer <independently-trusted-root-issuer-hex>
```

The DAG file contains a list of signed TRACE records or `{"records": [...]}`.
Generate it with `ca2a_runtime.trace_binding.emit_dag`; see
`examples/trace-dag/`. This command verifies the credential chain first, uses its
delegates as trusted record signers, verifies signatures and signed parent links,
then cross-checks hop credential IDs and signer keys. Only success on all checks
returns `verified: true`, `verification: authenticated_lineage` and exit 0.
Revocation is reported separately; absent revocation evidence is `not_checked`.
`--at-time` applies to credential validity and revocation; TRACE freshness uses
the current clock, optionally bounded by `--max-age-seconds`.

Migration: `ca2a verify-dag` still reads the original unsigned format, but valid
structure now returns `verified: false`, `structural_verified: true`,
`code: UNAUTHENTICATED_LINEAGE` and exit 1. Add `--structural-only` to obtain exit
0 for a successful diagnostic; it never changes `verified` to true. Structural
failures still return exit 1. This is an intentional CLI compatibility change.
Existing native records cannot be upgraded by relabeling them: their producers
must emit and sign TRACE records. The native Python helpers retain their return
types and perform structural checks only.

This authenticates the submitted path's declarations, not the truth of every
declaration. It does not establish task completion, a unique or complete history,
or that a live request continued this path. The root TRACE record carries no
credential ID, so its binding is to the root delegate key rather than a specific
grant to that key. These limits and live-request binding remain under #168.

The implemented TRACE binding signs records carrying delegation links. `verify_trace_dag` requires the recipient's trusted signing keys and checks signatures, structure, and parent links. `cross_check_trace_dag` then aligns the DAG with a separately verified chain: path length, non-root credential IDs, and each record's `cnf.jwk` against that hop's credential `subject`. See the [verification library](../spec/verification-library.md).

Both path verifiers accept one ordered root-to-leaf sequence, not an arbitrary branching graph. Even signed authorization evidence does not establish task completion or completeness of the submitted history. For runtime checks, see [inbound peer-call decision](../spec/call-graph.md).
