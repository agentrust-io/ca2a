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
    """A provenance record for a single delegation hop.

    A record is emitted whether the hop was allowed or denied. A denial record
    carries what was asked for, what the effective scope actually was, and why
    the call was refused, so a refusal is evidence rather than an absence of
    evidence. The denial fields are omitted from the hashed body on an allow
    record, so allow-record hashes are unchanged from records emitted before
    denial records existed.
    """

    record_id: str
    credential_id: str
    subject: str
    scope: frozenset[str]
    parent_record_hash: str | None = None
    decision: str = "allow"
    requested_capability: str | None = None
    effective_scope: frozenset[str] | None = None
    denial_reason: str | None = None

    def body(self) -> dict[str, Any]:
        """The hashed portion of the record."""
        body: dict[str, Any] = {
            "record_id": self.record_id,
            "credential_id": self.credential_id,
            "subject": self.subject,
            "scope": sorted(self.scope),
            "parent_record_hash": self.parent_record_hash,
        }
        if self.decision != "allow":
            body["decision"] = self.decision
        if self.requested_capability is not None:
            body["requested_capability"] = self.requested_capability
        if self.effective_scope is not None:
            body["effective_scope"] = sorted(self.effective_scope)
        if self.denial_reason is not None:
            body["denial_reason"] = self.denial_reason
        return body

    @property
    def denied(self) -> bool:
        """True when this record documents a refused call."""
        return self.decision == "deny"

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


def denial_record_for(
    credential: DelegationCredential,
    record_id: str,
    parent_record_hash: str | None,
    *,
    requested_capability: str,
    effective_scope: frozenset[str],
    reason: str,
) -> DelegationRecord:
    """Build the provenance record a hop emits when it refuses a call.

    The record links into the same DAG as allow records, so an auditor walking
    the chain sees the refusal in place rather than a gap. It states the
    capability that was requested and the effective scope it fell outside of,
    which is what makes the refusal checkable offline against the signed chain.
    """
    return DelegationRecord(
        record_id=record_id,
        credential_id=credential.credential_id,
        subject=credential.subject,
        scope=credential.scope,
        parent_record_hash=parent_record_hash,
        decision="deny",
        requested_capability=requested_capability,
        effective_scope=effective_scope,
        denial_reason=reason,
    )


def verify_dag(records: list[DelegationRecord]) -> list[DelegationRecord]:
    """Verify a root-to-leaf provenance chain and return it in order.

    Raises ProvenanceLinkBroken on the first violation:

    - the first record must be a root (no parent link);
    - every later record's parent_record_hash must equal the recomputed hash of
      the immediately preceding record (so a tampered or reparented record is
      detected because its hash no longer matches the stored link);
    - no record_id may repeat;
    - a denial record is terminal: nothing may be chained onto a refused hop,
      so a chain claiming work continued past a denial is rejected.
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
        elif prev.denied:
            raise ProvenanceLinkBroken(
                f"record {i} is chained onto a denied hop",
                detail=f"record {prev.record_id} refused "
                f"{prev.requested_capability!r}; no hop may follow it",
            )
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

    Ties provenance to authority: hop record ``i`` must reference credential
    ``i`` and carry the same subject. Raises ProvenanceLinkBroken on any
    mismatch.

    A denial record documents a refused call, not a delegation hop, so it is not
    matched positionally against the chain. It must still name a credential that
    is actually in the chain, otherwise a refusal could be attributed to
    authority that was never granted.
    """
    hops = [r for r in records if not r.denied]
    if len(hops) != len(chain):
        raise ProvenanceLinkBroken(
            f"provenance length {len(hops)} does not match chain length {len(chain)}"
        )
    for i, (rec, cred) in enumerate(zip(hops, chain, strict=True)):
        if rec.credential_id != cred.credential_id:
            raise ProvenanceLinkBroken(f"record {i} credential_id does not match the chain")
        if rec.subject != cred.subject:
            raise ProvenanceLinkBroken(f"record {i} subject does not match the chain")

    by_id = {c.credential_id: c for c in chain}
    for rec in records:
        if not rec.denied:
            continue
        under = by_id.get(rec.credential_id)
        if under is None:
            raise ProvenanceLinkBroken(
                f"denial record {rec.record_id} references credential "
                f"{rec.credential_id!r}, which is not in the chain"
            )
        if rec.subject != under.subject:
            raise ProvenanceLinkBroken(
                f"denial record {rec.record_id} subject does not match the chain"
            )
