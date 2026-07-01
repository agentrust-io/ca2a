# TRACE A2A Profile

cA2A emits a TRACE record per delegation hop. The A2A profile adds a delegation-link block to the TRACE record so a chain of records forms a verifiable delegation DAG.

## The delegation-link block

The base TRACE record has a subject but no notion of a parent. The A2A profile adds an optional block:

| Field | Meaning |
|---|---|
| `delegation.parent_record_hash` | Hash of the parent hop's TRACE record |
| `delegation.credential_id` | The `credential_id` of the delegation credential this hop acted under |

A root hop omits the block. Each subsequent hop references its parent, so the set of records across A to B to C reconstructs the delegation tree.

## The delegation DAG

Given the records for a workflow, a verifier can:

1. Rebuild the parent links from `parent_record_hash`.
2. Confirm each hop acted under a credential whose chain verifies (see [delegation chain](delegation-chain.md)).
3. Confirm no hop exceeded the scope granted upstream.

This is done offline, from signed records alone, without trusting the operators that produced them.

## Status

The delegation-link field is on the trace-spec roadmap as the "A2A profile, pending A2A protocol stability." A2A is now stable at v1.x, which clears that blocker. The DAG verifier lands with the Tier 2 provenance work in this repo. See [ROADMAP.md](../../ROADMAP.md).
