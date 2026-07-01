# Provenance DAG

A delegation chain proves who was *allowed* to act. The provenance DAG records what *actually happened*: one signed-in-substance record per delegation hop, each linked to its parent by hash. A chain of records forms a tamper-evident, hash-linked structure that a verifier reconstructs and checks offline, without trusting the operators that produced the records.

This module (`ca2a_runtime.provenance`) is implemented and validated. Claim C5 exercises all of its properties (see [reproducing the claims](../tutorials/reproducing-the-claims.md) and the experiment at `experiments/claim5-provenance-dag-integrity/`). It is the runtime-evidence side of the [TRACE A2A profile](trace-a2a-profile.md); the full TRACE record binding lands with the Tier 2 provenance work.

## DelegationRecord

A `DelegationRecord` is the provenance record a hop emits for the delegation credential it acted under. It is a frozen dataclass:

| Field | Type | Meaning |
|---|---|---|
| `record_id` | string | Unique id of this record |
| `credential_id` | string | The `credential_id` of the delegation credential this hop acted under |
| `subject` | hex | The delegate for this hop, copied from the credential's `subject` |
| `scope` | set of strings | Capabilities exercised at this hop, copied from the credential's `scope` |
| `parent_record_hash` | string or null | `record_hash()` of the parent record; null at the root |

The hashed portion of the record is its `body()`: `record_id`, `credential_id`, `subject`, `scope` as a sorted array, and `parent_record_hash`. There is no separate signature field on the record. Integrity comes from the hash link, and authority comes from binding the record back to its signed credential with `cross_check_chain()`.

## record_hash()

`record_hash()` is the SHA-256 hex digest over the canonical bytes of `body()`:

```python
def record_hash(self) -> str:
    return hashlib.sha256(canonical_bytes(self.body())).hexdigest()
```

`canonical_bytes` is the same RFC 8785 (JCS) encoding used to sign delegation credentials (see [delegation chain](delegation-chain.md)). Because the parent link is the hash of the parent's canonical body, and every other field of a record feeds that hash, any change to a record changes its `record_hash()` and therefore breaks the link in its child.

## record_for()

`record_for()` builds the record a hop emits for a given credential. It copies `credential_id`, `subject`, and `scope` straight off the `DelegationCredential`, so a record cannot silently claim a credential id, subject, or scope different from the one it was minted from:

```python
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.provenance import record_for

# `cred` is a signed DelegationCredential for this hop.
record = record_for(cred, record_id="rec-0", parent_record_hash=None)
```

The caller supplies the `record_id` and the `parent_record_hash` (the previous record's `record_hash()`, or `None` for the root). Chaining a workflow is a fold over the hops:

```python
from ca2a_runtime.provenance import record_for

records = []
parent_hash = None
for i, cred in enumerate(chain):
    rec = record_for(cred, record_id=f"rec-{i}", parent_record_hash=parent_hash)
    records.append(rec)
    parent_hash = rec.record_hash()
```

## verify_dag()

`verify_dag()` takes a root-to-leaf list of records, checks the linking invariants, and returns the list unchanged on success. It raises `ProvenanceLinkBroken` (error code `PROVENANCE_LINK_BROKEN`, HTTP 409) on the first violation:

```python
from ca2a_runtime.provenance import verify_dag
from ca2a_runtime.errors import ProvenanceLinkBroken

try:
    verify_dag(records)
except ProvenanceLinkBroken as exc:
    ...  # reject the workflow
```

The invariants are:

| Invariant | Violation |
|---|---|
| The list is non-empty | `PROVENANCE_LINK_BROKEN` (`empty provenance chain`) |
| The first record is a root: `parent_record_hash` is `None` | `PROVENANCE_LINK_BROKEN` (`root record must not reference a parent`) |
| Every later record's `parent_record_hash` equals the recomputed `record_hash()` of the immediately preceding record | `PROVENANCE_LINK_BROKEN` (`record i parent link does not match the previous record's hash`) |
| No `record_id` repeats | `PROVENANCE_LINK_BROKEN` (`duplicate record_id at position i`) |

The parent hash is *recomputed* from the previous record on every check rather than trusted. That is what makes the structure tamper-evident: the stored link and the recomputed hash have to agree.

## cross_check_chain()

`verify_dag()` proves the records are internally consistent, but on its own it says nothing about *authority*. `cross_check_chain()` ties provenance to the verified [delegation chain](delegation-chain.md): record `i` must reference credential `i` and carry the same subject.

```python
from ca2a_runtime.provenance import cross_check_chain

# `chain` has passed verify_chain; `records` has passed verify_dag.
cross_check_chain(records, chain)  # raises ProvenanceLinkBroken on any mismatch
```

It raises `ProvenanceLinkBroken` if the two lists differ in length, if any `record.credential_id` does not equal the corresponding `credential.credential_id`, or if any `record.subject` does not equal the corresponding `credential.subject`. Run `verify_chain` on the credentials and `verify_dag` on the records first, then `cross_check_chain` to bind the two. A forged `credential_id` on a record, for example, is caught here even though the record chain itself hashes cleanly.

## Tamper-evidence

SHA-256 exhibits the avalanche property: a one-field change to a record produces a digest that differs from the original in roughly half of its 256 bits. The C5 experiment measures this directly by adding a capability to a record's scope and counting differing bits between the old and new `record_hash()`. It observes about 128 of 256 bits flipped.

Because the child record stores the parent's *old* hash in `parent_record_hash`, a tampered record no longer hashes to that stored value, and `verify_dag()` raises `ProvenanceLinkBroken` at the child. An attacker cannot fix this by editing only one record: repairing the child's `parent_record_hash` to match the tampered parent changes the child's own hash, which breaks *its* child, and so on to the leaf. Correcting the whole tail requires recomputing every downstream link, which `cross_check_chain()` then rejects if the underlying credentials no longer line up.

## Reparenting

Reparenting is the attack of pointing a record at a different, legitimately-hashed parent to hide a hop or re-order the chain. It is caught by the same recompute-and-compare check. `verify_dag()` walks the list in order and requires each record's `parent_record_hash` to equal the hash of the record *immediately before it in the list*. A record whose `parent_record_hash` points at some other record's hash (for example the root's, skipping an intermediate hop) fails that equality and raises `ProvenanceLinkBroken`. The C5 experiment demonstrates this by repointing the leaf's `parent_record_hash` at the root's hash instead of its true parent and confirming detection.

## Status and scope

The provenance DAG in this module is implemented and reproducible under claim C5. What it does *not* yet do:

- The records are hash-linked, not independently signed. Authority binding is via `cross_check_chain()` against signed credentials, not a signature on each record.
- The full TRACE record binding described in the [TRACE A2A profile](trace-a2a-profile.md), emitting these links as `delegation.parent_record_hash` / `delegation.credential_id` fields inside a TRACE record, lands with the Tier 2 provenance work. See [ROADMAP.md](../../ROADMAP.md) and [LIMITATIONS.md](../../LIMITATIONS.md).

For the offline chain verifier that this module pairs with, see the [verification library](verification-library.md).
