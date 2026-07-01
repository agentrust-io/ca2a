# Emit and Verify Provenance

A verified delegation chain tells you who was allowed to act. A provenance DAG is the runtime evidence that the delegation actually happened, in order, and was not edited after the fact. This tutorial takes a signed chain, emits one `DelegationRecord` per hop, verifies the linked records offline, tampers with one record to watch the link break, and binds the provenance back to the delegation credentials it claims to act under.

Everything here runs offline with no hardware. It mirrors `experiments/claim5-provenance-dag-integrity`. For the model behind these records, see [provenance-dag.md](../spec/provenance-dag.md); for the credential model see [delegation-chain.md](../spec/delegation-chain.md).

## What a record is

Each delegation hop emits a `DelegationRecord`. The record names the credential it acted under, repeats that credential's `subject` and `scope`, and carries `parent_record_hash`: the SHA-256 of the previous record's canonical body. The hash link is what makes the DAG tamper-evident. Change any field of a record and its `record_hash()` changes, so the child that pointed at the old hash no longer lines up.

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class DelegationRecord:
    record_id: str
    credential_id: str
    subject: str
    scope: frozenset[str]
    parent_record_hash: str | None = None
```

`record_hash()` is SHA-256 over the canonical body (`record_id`, `credential_id`, `subject`, sorted `scope`, `parent_record_hash`). The canonicalization is the same RFC 8785 (JCS) encoding used to sign credentials, so an auditor recomputes the exact bytes.

## 1. Build a signed chain

Start from a correctly signed root-to-leaf delegation chain. This is the same setup used in [verify-a-delegation-chain.md](verify-a-delegation-chain.md); here we build it in code so we have the credentials in hand to emit records from.

```python
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair


def build_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    chain: list[DelegationCredential] = []
    priv, pub = new_keypair()
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{depth}",
            issuer=pub,
            subject=next_pub,
            scope=scope,
            depth=depth,
            parent_id=parent_id,
        ).sign(priv)
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain


chain = build_chain(
    [
        frozenset({"cap:a", "cap:b", "cap:c"}),
        frozenset({"cap:a", "cap:b"}),
        frozenset({"cap:a"}),
    ]
)
```

Each hop's `issuer` is the previous hop's `subject`, and scope narrows at every step. `new_keypair()` returns an `Ed25519PrivateKey` and its public key as raw hex.

## 2. Emit one record per hop

Walk the chain and call `record_for()` for each credential, threading the running `parent_record_hash`. The root record has no parent, so it starts at `None`.

```python
from ca2a_runtime.provenance import DelegationRecord, record_for


def records_from_chain(chain: list[DelegationCredential]) -> list[DelegationRecord]:
    records: list[DelegationRecord] = []
    parent_hash: str | None = None
    for i, cred in enumerate(chain):
        rec = record_for(cred, record_id=f"rec-{i}", parent_record_hash=parent_hash)
        records.append(rec)
        parent_hash = rec.record_hash()
    return records


records = records_from_chain(chain)
```

`record_for(credential, record_id, parent_record_hash)` copies `credential_id`, `subject`, and `scope` off the credential and stamps in the parent link you pass. After appending a record you recompute `record_hash()` and feed it forward as the next record's parent.

## 3. Verify the DAG

`verify_dag()` walks the records root to leaf and returns them in order on success. It enforces three things: the first record must be a root (no parent link), every later record's `parent_record_hash` must equal the recomputed hash of the immediately preceding record, and no `record_id` may repeat.

```python
from ca2a_runtime.provenance import verify_dag

verified = verify_dag(records)
print(f"verified {len(verified)} records")
# verified 3 records
```

If it returns without raising, the linked hash chain is intact.

## 4. Tamper with a record

Now edit one field of a record without touching anything else. Because `record_hash()` covers `scope`, adding a capability flips roughly half of the 256 hash bits (the SHA-256 avalanche), so record 1's new hash no longer matches the `parent_record_hash` that record 2 still stores.

```python
from ca2a_runtime.errors import ProvenanceLinkBroken

original = records[1]
tampered = DelegationRecord(
    record_id=original.record_id,
    credential_id=original.credential_id,
    subject=original.subject,
    scope=frozenset(original.scope | {"cap:injected"}),
    parent_record_hash=original.parent_record_hash,
)

tampered_records = list(records)
tampered_records[1] = tampered

try:
    verify_dag(tampered_records)
except ProvenanceLinkBroken as exc:
    print(f"{exc.code}: {exc}")
# PROVENANCE_LINK_BROKEN: record 2 parent link does not match the previous record's hash
```

`ProvenanceLinkBroken` carries code `PROVENANCE_LINK_BROKEN` and HTTP status 409. The message names the position where the link failed, and `exc.detail` reads `a tampered or reparented record was detected`. Note that the tampered record is at position 1, but the break is detected at position 2: the verifier catches the edit at the first child whose stored link no longer matches.

## 5. Reparent a record

The same mechanism catches a record repointed at a different parent, even when the record's own fields are untouched. Here the leaf is made to claim the root's hash as its parent instead of record 1's.

```python
leaf = records[2]
reparented = DelegationRecord(
    record_id=leaf.record_id,
    credential_id=leaf.credential_id,
    subject=leaf.subject,
    scope=leaf.scope,
    parent_record_hash=records[0].record_hash(),  # should be records[1]'s hash
)

reparented_records = list(records)
reparented_records[2] = reparented

try:
    verify_dag(reparented_records)
except ProvenanceLinkBroken as exc:
    print(f"{exc.code}: {exc}")
# PROVENANCE_LINK_BROKEN: record 2 parent link does not match the previous record's hash
```

You cannot splice a record into a different position in the DAG without breaking the link, because the stored `parent_record_hash` must equal the hash of the record that actually precedes it.

## 6. Bind provenance to authority

`verify_dag()` proves the records are internally consistent, but on its own it does not prove they describe the delegation you think they do. Records could be internally valid yet name credentials that never existed. `cross_check_chain()` closes that gap: record `i` must reference credential `i` and carry the same subject.

```python
from ca2a_runtime.provenance import cross_check_chain

cross_check_chain(records, chain)  # returns None on success
print("provenance bound to the delegation chain")
```

Forge a `credential_id` on any record and the cross-check rejects it:

```python
mismatch = list(records)
mismatch[0] = DelegationRecord(
    record_id=records[0].record_id,
    credential_id="FORGED-CRED-ID",
    subject=records[0].subject,
    scope=records[0].scope,
    parent_record_hash=None,
)

try:
    cross_check_chain(mismatch, chain)
except ProvenanceLinkBroken as exc:
    print(f"{exc.code}: {exc}")
# PROVENANCE_LINK_BROKEN: record 0 credential_id does not match the chain
```

`cross_check_chain()` also raises `ProvenanceLinkBroken` if the record list and the chain are different lengths, or if any record's `subject` does not match its credential's `subject`. Run both checks together and a valid provenance DAG cannot be fabricated independently of the signed authority it claims.

## What you proved

You emitted a linked provenance record per delegation hop, verified the DAG offline, and watched a single-field edit and a reparent both surface as `ProvenanceLinkBroken`. `cross_check_chain()` ties every record back to the credential it acted under, so the evidence trail is bound to the signed delegation chain, not free-floating. An auditor replays `verify_dag()` and `cross_check_chain()` against the recorded records and credentials without trusting the runtime that emitted them.

## Scope and limits

This is the runtime-evidence side of the cA2A profile and it works today. What it is not:

- These records are a hash-linked evidence trail. They are not yet the full TRACE binding; that lands with the Tier 2 provenance work. See [trace-a2a-profile.md](../spec/trace-a2a-profile.md).
- The DAG is verified after the fact from recorded records. cA2A does not yet enforce peer behavior at runtime (Tier 2), so a peer must still emit honest records for the trail to mean anything. See [threat-model.md](../spec/threat-model.md) and [LIMITATIONS.md](../../LIMITATIONS.md).
- The verifier walks a single root-to-leaf sequence. Branching DAGs and the wire format for transmitting records are on the [roadmap](../../ROADMAP.md).

## Next steps

- Reproduce the numbers behind this page: [reproducing-the-claims.md](reproducing-the-claims.md).
- Author the credentials the records point at: [authoring-a-delegation-credential.md](authoring-a-delegation-credential.md).
- The full provenance model and record schema: [provenance-dag.md](../spec/provenance-dag.md).
