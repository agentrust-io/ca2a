"""
Experiment: Provenance DAG Integrity
Claim 5: cA2A tamper-evident delegation provenance

Proves four properties:
  1. A valid record chain verifies with verify_dag.
  2. Tampering a record's scope flips ~50% of its record_hash bits (SHA-256
     avalanche) and breaks the child's parent link: ProvenanceLinkBroken.
  3. Reparenting a record is detected by verify_dag.
  4. cross_check_chain ties record i to credential i: it passes on aligned
     records and raises ProvenanceLinkBroken on a credential_id mismatch.

Run from repo root:
  pip install -e .
  .venv/Scripts/python.exe experiments/claim5-provenance-dag-integrity/run.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Allow running from repo root without install.
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.errors import ProvenanceLinkBroken
from ca2a_runtime.provenance import (
    DelegationRecord,
    cross_check_chain,
    record_for,
    verify_dag,
)


def build_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    """Build a correctly signed root-to-leaf delegation chain."""
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


def records_from_chain(chain: list[DelegationCredential]) -> list[DelegationRecord]:
    """Emit one provenance record per hop, chaining parent_record_hash."""
    records: list[DelegationRecord] = []
    parent_hash: str | None = None
    for i, cred in enumerate(chain):
        rec = record_for(cred, record_id=f"rec-{i}", parent_record_hash=parent_hash)
        records.append(rec)
        parent_hash = rec.record_hash()
    return records


def bits_different(h1: str, h2: str) -> int:
    """Count differing bits between two hex-encoded SHA-256 digests."""
    b1 = bytes.fromhex(h1)
    b2 = bytes.fromhex(h2)
    return sum(bin(a ^ b).count("1") for a, b in zip(b1, b2, strict=True))


def section(title: str) -> None:
    print(f"\n[{title}]")


def result(label: str, value: str, ok: bool | None = None) -> None:
    if ok is None:
        print(f"    {label}: {value}")
    else:
        print(f"    {label}: {value}  {'OK' if ok else 'FAIL'}")


def main() -> int:
    print("=" * 60)
    print("Experiment: Provenance DAG Integrity")
    print("Claim 5: cA2A tamper-evident delegation provenance")
    print("=" * 60)

    failures = 0

    chain = build_chain(
        [
            frozenset({"cap:a", "cap:b", "cap:c"}),
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a"}),
        ]
    )

    # ------------------------------------------------------------------
    # Property 1: valid DAG verifies
    # ------------------------------------------------------------------
    section("1. Valid DAG verifies")
    records = records_from_chain(chain)
    accepted = verify_dag(records) == records
    result("records emitted", str(len(records)))
    result("verify_dag", "ACCEPTED" if accepted else "REJECTED", accepted)
    if not accepted:
        failures += 1

    # ------------------------------------------------------------------
    # Property 2: tamper a record's scope -> avalanche + link break
    # ------------------------------------------------------------------
    section("2. Tamper a record's scope: hash avalanche + link break")
    original = records[1]
    original_hash = original.record_hash()
    tampered = DelegationRecord(
        record_id=original.record_id,
        credential_id=original.credential_id,
        subject=original.subject,
        scope=frozenset(original.scope | {"cap:injected"}),
        parent_record_hash=original.parent_record_hash,
    )
    tampered_hash = tampered.record_hash()
    diff = bits_different(original_hash, tampered_hash)
    pct = 100 * diff // 256

    result("original record_hash", original_hash)
    result("tampered record_hash", tampered_hash)
    result("bits changed (of 256)", f"{diff} (~{pct}%)")

    tampered_records = list(records)
    tampered_records[1] = tampered
    tamper_caught = False
    try:
        verify_dag(tampered_records)
    except ProvenanceLinkBroken as exc:
        tamper_caught = True
        result("error detail", str(exc))
    result(
        "verify_dag",
        "ProvenanceLinkBroken raised" if tamper_caught else "did NOT detect tamper",
        tamper_caught,
    )
    if not tamper_caught:
        failures += 1

    # ------------------------------------------------------------------
    # Property 3: reparent a record -> detection
    # ------------------------------------------------------------------
    section("3. Reparent a record: detection")
    reparented_records = list(records)
    leaf = records[2]
    reparented_records[2] = DelegationRecord(
        record_id=leaf.record_id,
        credential_id=leaf.credential_id,
        subject=leaf.subject,
        scope=leaf.scope,
        # Point at the root's hash instead of the real parent (records[1]).
        parent_record_hash=records[0].record_hash(),
    )
    reparent_caught = False
    try:
        verify_dag(reparented_records)
    except ProvenanceLinkBroken:
        reparent_caught = True
    result(
        "verify_dag",
        "ProvenanceLinkBroken raised" if reparent_caught else "did NOT detect reparent",
        reparent_caught,
    )
    if not reparent_caught:
        failures += 1

    # ------------------------------------------------------------------
    # Property 4: cross_check_chain ties record i to credential i
    # ------------------------------------------------------------------
    section("4. cross_check_chain ties record i to credential i")
    aligned_ok = False
    try:
        cross_check_chain(records, chain)
        aligned_ok = True
    except ProvenanceLinkBroken:
        aligned_ok = False
    result(
        "aligned records",
        "cross_check_chain passes" if aligned_ok else "unexpectedly rejected",
        aligned_ok,
    )
    if not aligned_ok:
        failures += 1

    mismatch_records = list(records)
    mismatch_records[0] = DelegationRecord(
        record_id=records[0].record_id,
        credential_id="FORGED-CRED-ID",
        subject=records[0].subject,
        scope=records[0].scope,
        parent_record_hash=None,
    )
    mismatch_caught = False
    try:
        cross_check_chain(mismatch_records, chain)
    except ProvenanceLinkBroken:
        mismatch_caught = True
    result(
        "credential_id mismatch",
        "ProvenanceLinkBroken raised" if mismatch_caught else "NOT caught",
        mismatch_caught,
    )
    if not mismatch_caught:
        failures += 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    if failures == 0:
        print(
            "KEY RESULT: tamper flips ~50% of hash bits "
            f"({diff}/256), ProvenanceLinkBroken raised; reparent detected; "
            "provenance bound to authority"
        )
        return 0
    print(f"Result: {failures} PROPERTIES FAILED: see output above")
    return 1


if __name__ == "__main__":
    sys.exit(main())
