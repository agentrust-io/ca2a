# Provenance DAG

A delegation credential describes authority. A provenance record describes a decision made under that authority. cA2A provides both unsigned `DelegationRecord` helpers and a signed TRACE binding. Choose the signed form when a recipient needs to authenticate who produced the evidence.

## DelegationRecord

`ca2a_runtime.provenance.DelegationRecord` contains a record ID, credential ID, subject, delegated scope, parent-record hash, and caller-attestation outcome. Denial records also carry the decision, requested capability, effective scope, and reason.

The `scope` field copies the credential's grant. It is not a list of actions the application completed. An allow record is constructed at the authorization decision, before the full handler opens any sealed payload.

`record_for(credential, record_id, parent_record_hash)` constructs an allow record. `denial_record_for` constructs a refusal. `record_hash()` computes SHA-256 over the RFC 8785 canonical body, including the caller-attestation outcome and any populated denial fields. These records have no independent signature.

## Build and check a path

This reference fragment assumes `chain` has already passed credential verification against independently trusted roots. For a complete walkthrough, see [emit and verify provenance](../tutorials/emit-and-verify-provenance.md).

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
```

`verify_dag` accepts one ordered root-to-leaf path. It rejects an empty path, a root with a parent, repeated record IDs, or a child whose parent hash differs from the recomputed hash of the immediately preceding record. Despite its name, it does not accept an arbitrary branching graph.

`cross_check_chain` checks path length, credential IDs, and subjects against a separately verified credential chain. It does not check the record's scope or authenticate its producer.

## What hash links establish

Changing a parent without updating its child's link is detected. Repointing a child away from the preceding record is also detected. C5 exercises those cases.

Hash links alone do not prevent an attacker from rewriting the records and recomputing every downstream hash. A leaf edit has no child link to break. Credential cross-checking does not fix this: an attacker can retain the credential IDs and subjects while changing other unsigned fields. An authenticated external commitment or signed records are needed to establish authenticity. Neither form alone proves task completion or that the supplied path includes every event.

## Signed TRACE binding

`ca2a_runtime.trace_binding` emits signed TRACE records carrying `delegation.parent_record_hash` and `delegation.credential_id`. `ca2a_verify.verify_trace_dag` checks signatures against the recipient's trusted keys, record structure, and the ordered parent links. `cross_check_trace_dag` aligns non-root credential IDs with the verified credential chain.

This binding is implemented. See the [verification library](verification-library.md) for trust and freshness inputs and the [TRACE A2A profile](trace-a2a-profile.md) for the wire fields. Software signing authenticates a key's statement; hardware assurance requires separate evidence and appraisal.
