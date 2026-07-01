"""Claim 5 CI test: provenance DAG integrity.

Confirms that a valid record chain verifies, a tampered record breaks the DAG
with ProvenanceLinkBroken, and cross_check_chain ties records to authority
(passing on aligned records, raising on a credential_id mismatch).
"""

from __future__ import annotations

import pytest

from ca2a_runtime.delegation import DelegationCredential
from ca2a_runtime.errors import ProvenanceLinkBroken
from ca2a_runtime.provenance import (
    DelegationRecord,
    cross_check_chain,
    record_for,
    verify_dag,
)


def _records_from_chain(chain: list[DelegationCredential]) -> list[DelegationRecord]:
    records: list[DelegationRecord] = []
    parent_hash: str | None = None
    for i, cred in enumerate(chain):
        rec = record_for(cred, record_id=f"rec-{i}", parent_record_hash=parent_hash)
        records.append(rec)
        parent_hash = rec.record_hash()
    return records


def test_valid_dag_verifies(valid_chain: list[DelegationCredential]) -> None:
    records = _records_from_chain(valid_chain)
    assert verify_dag(records) == records


def test_tampered_scope_raises_provenance_link_broken(
    valid_chain: list[DelegationCredential],
) -> None:
    records = _records_from_chain(valid_chain)
    original = records[1]
    records[1] = DelegationRecord(
        record_id=original.record_id,
        credential_id=original.credential_id,
        subject=original.subject,
        scope=frozenset(original.scope | {"cap:injected"}),
        parent_record_hash=original.parent_record_hash,
    )
    with pytest.raises(ProvenanceLinkBroken):
        verify_dag(records)


def test_tamper_flips_many_hash_bits(
    valid_chain: list[DelegationCredential],
) -> None:
    records = _records_from_chain(valid_chain)
    original = records[1]
    tampered = DelegationRecord(
        record_id=original.record_id,
        credential_id=original.credential_id,
        subject=original.subject,
        scope=frozenset(original.scope | {"cap:injected"}),
        parent_record_hash=original.parent_record_hash,
    )
    b1 = bytes.fromhex(original.record_hash())
    b2 = bytes.fromhex(tampered.record_hash())
    bits_changed = sum(bin(a ^ b).count("1") for a, b in zip(b1, b2, strict=True))
    # SHA-256 avalanche: expect roughly half of the 256 bits to flip.
    assert 96 <= bits_changed <= 160


def test_cross_check_passes_on_aligned_records(
    valid_chain: list[DelegationCredential],
) -> None:
    records = _records_from_chain(valid_chain)
    cross_check_chain(records, valid_chain)


def test_cross_check_raises_on_credential_id_mismatch(
    valid_chain: list[DelegationCredential],
) -> None:
    records = _records_from_chain(valid_chain)
    original = records[0]
    records[0] = DelegationRecord(
        record_id=original.record_id,
        credential_id="FORGED-CRED-ID",
        subject=original.subject,
        scope=original.scope,
        parent_record_hash=None,
    )
    with pytest.raises(ProvenanceLinkBroken):
        cross_check_chain(records, valid_chain)
