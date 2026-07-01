# Experiment: Provenance DAG Integrity

**Claim:** Provenance DAG integrity (cA2A Claim 5). Linked TRACE-style delegation records are tamper-evident. Reparenting or forging a record is detected, and provenance ties back to the authority that produced it.

**What this experiment proves:**

1. A chain of `DelegationRecord`s emitted along a delegation chain (each carrying its parent's `record_hash` in `parent_record_hash`) verifies with `verify_dag`.
2. Tampering with any field of a record (here, its `scope`) triggers the hash avalanche: roughly half of the `record_hash` bits flip. The child's stored parent link no longer matches, so `verify_dag` raises `ProvenanceLinkBroken`.
3. Reparenting a record (pointing its `parent_record_hash` at a different record's hash) is detected by `verify_dag` because the recomputed previous-record hash no longer equals the stored link.
4. `cross_check_chain` ties record `i` to credential `i`: it passes on aligned records and raises `ProvenanceLinkBroken` when a record's `credential_id` does not match the delegation credential it claims to act under.

**What this means for governance:**

The record hash chain is the runtime evidence trail for a delegation. Because each link is the SHA-256 of the parent record's canonical body, a record cannot be edited, forged, or re-pointed at a different parent without breaking a downstream link. `cross_check_chain` closes the loop back to the signed delegation credentials, so a valid provenance DAG cannot be fabricated independently of the authority it claims. An auditor can replay both checks offline against the recorded records and credentials without trusting the runtime that emitted them.

## Running

```bash
# From repo root, with the package installed editable (pip install -e .)
.venv/Scripts/python.exe experiments/claim5-provenance-dag-integrity/run.py
```

## Expected output

```
============================================================
Experiment: Provenance DAG Integrity
Claim 5: cA2A tamper-evident delegation provenance
============================================================

[1. Valid DAG verifies]
    records emitted: 3
    verify_dag: ACCEPTED  OK

[2. Tamper a record's scope: hash avalanche + link break]
    original record_hash: ...
    tampered record_hash: ...
    bits changed (of 256): ~128 (~50%)
    verify_dag: ProvenanceLinkBroken raised  OK

[3. Reparent a record: detection]
    verify_dag: ProvenanceLinkBroken raised  OK

[4. cross_check_chain ties record i to credential i]
    aligned records: cross_check_chain passes  OK
    credential_id mismatch: ProvenanceLinkBroken raised  OK

============================================================
KEY RESULT: tamper flips ~50% of hash bits, ProvenanceLinkBroken raised; reparent detected; provenance bound to authority
```

The reported bit-change count varies per run because the chain uses fresh Ed25519 keys, but it stays near 128 of 256 bits (the SHA-256 avalanche property).
