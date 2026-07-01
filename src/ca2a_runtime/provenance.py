"""Delegation provenance: linked records forming a tamper-evident delegation DAG.

Each delegation hop emits a ``DelegationRecord`` that references its parent
record by hash and names the credential it acted under. A chain of records is
verifiable offline: the parent link is the hash of the parent record's canonical
body, so tampering with any record (its scope, subject, or its own parent link)
changes its hash and breaks the child's link. This is the runtime-evidence side
of the cA2A profile (see docs/spec/trace-a2a-profile.md); the full TRACE binding
lands with the Tier 2 provenance work.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from ca2a_runtime.delegation.credential import DelegationCredential, canonical_bytes
from ca2a_runtime.errors import ProvenanceLinkBroken


@dataclass(frozen=True)
class DelegationRecord:
    """A provenance record for a single delegation hop."""

    record_id: str
    credential_id: str
    subject: str
    scope: frozenset[str]
    parent_record_hash: str | None = None

    def body(self) -> dict[str, Any]:
        """The hashed portion of the record."""
        return {
            "record_id": self.record_id,
            "credential_id": self.credential_id,
            "subject": self.subject,
            "scope": sorted(self.scope),
            "parent_record_hash": self.parent_record_hash,
        }

    def record_hash(self) -> str:
        """SHA-256 over the canonical body. Any field change changes this value."""
        return hashlib.sha256(canonical_bytes(self.body())).hexdigest()


def record_for(
    credential: DelegationCredential,
    record_id: str,
    parent_record_hash: str | None,
) -> DelegationRecord:
    """Build the provenance record a hop emits for a delegation credential."""
    return DelegationRecord(
        record_id=record_id,
        credential_id=credential.credential_id,
        subject=credential.subject,
        scope=credential.scope,
        parent_record_hash=parent_record_hash,
    )


def verify_dag(records: list[DelegationRecord]) -> list[DelegationRecord]:
    """Verify a root-to-leaf provenance chain and return it in order.

    Raises ProvenanceLinkBroken on the first violation:

    - the first record must be a root (no parent link);
    - every later record's parent_record_hash must equal the recomputed hash of
      the immediately preceding record (so a tampered or reparented record is
      detected because its hash no longer matches the stored link);
    - no record_id may repeat.
    """
    if not records:
        raise ProvenanceLinkBroken("empty provenance chain")

    seen_ids: set[str] = set()
    prev: DelegationRecord | None = None

    for i, rec in enumerate(records):
        if rec.record_id in seen_ids:
            raise ProvenanceLinkBroken(f"duplicate record_id at position {i}: {rec.record_id}")
        seen_ids.add(rec.record_id)

        if prev is None:
            if rec.parent_record_hash is not None:
                raise ProvenanceLinkBroken("root record must not reference a parent")
        else:
            expected = prev.record_hash()
            if rec.parent_record_hash != expected:
                raise ProvenanceLinkBroken(
                    f"record {i} parent link does not match the previous record's hash",
                    detail="a tampered or reparented record was detected",
                )
        prev = rec

    return records


def cross_check_chain(
    records: list[DelegationRecord], chain: list[DelegationCredential]
) -> None:
    """Confirm a verified provenance chain lines up with a delegation chain.

    Ties provenance to authority: record ``i`` must reference credential ``i``
    and carry the same subject. Raises ProvenanceLinkBroken on any mismatch.
    """
    if len(records) != len(chain):
        raise ProvenanceLinkBroken(
            f"provenance length {len(records)} does not match chain length {len(chain)}"
        )
    for i, (rec, cred) in enumerate(zip(records, chain, strict=True)):
        if rec.credential_id != cred.credential_id:
            raise ProvenanceLinkBroken(f"record {i} credential_id does not match the chain")
        if rec.subject != cred.subject:
            raise ProvenanceLinkBroken(f"record {i} subject does not match the chain")
