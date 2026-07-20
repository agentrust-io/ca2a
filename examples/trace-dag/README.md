# TRACE delegation DAG

Emit a signed [TRACE](https://github.com/agentrust-io/trace-spec) Trust Record per
delegation hop, linked into a verifiable DAG via the A2A profile's `delegation`
block, then verify the DAG offline.

```bash
python examples/trace-dag/demo.py
```

The demo builds a three-hop chain (orchestrator to researcher to retriever),
lifts each hop into a TRACE record, verifies the DAG from the signed records
alone, cross-checks it against the delegation chain, confirms each record passes
the TRACE conformance suite at **Level 0**, and writes `dag.json`.

This is the **software-attestation** path (`runtime.platform` = `software-only`),
so the records are honestly Level 0. The appraisal and transparency URIs use the
reserved `.invalid` TLD so a software-mode record can never be mistaken for a
hardware-attested one. A run on confidential-computing hardware (a real TEE
measurement) is what lifts these records to Level 1.

## What each piece does

- `ca2a_runtime.trace_binding.emit_dag` — build and sign the linked records.
- `ca2a_verify.verify_trace_dag` — verify the DAG offline against trusted keys:
  each record valid and signed, and each `delegation.parent_record_hash` equal to
  the hash of the parent's **full signed record**.
- `ca2a_verify.cross_check_trace_dag` — tie the DAG to the delegation chain
  (each non-root hop acted under the credential the chain names).

Validate a single record with the TRACE tooling directly:

```bash
python -c "import json; json.dump(json.load(open('examples/trace-dag/dag.json'))[1], open('rec.json','w'))"
trace-tests verify --record rec.json --level 0
```
