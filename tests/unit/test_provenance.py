"""Tests for the delegation provenance DAG."""

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
from tests.unit.conftest import build_chain


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


def test_empty_dag_rejected() -> None:
    with pytest.raises(ProvenanceLinkBroken):
        verify_dag([])


def test_root_with_parent_rejected() -> None:
    rec = DelegationRecord("rec-0", "c0", "subj", frozenset({"cap:a"}), parent_record_hash="x")
    with pytest.raises(ProvenanceLinkBroken):
        verify_dag([rec])


def test_tampered_record_breaks_link(valid_chain: list[DelegationCredential]) -> None:
    records = _records_from_chain(valid_chain)
    # Tamper with the middle record's scope: its hash changes, so the leaf's
    # stored parent link no longer matches.
    tampered = DelegationRecord(
        records[1].record_id,
        records[1].credential_id,
        records[1].subject,
        frozenset({"cap:a", "cap:injected"}),
        records[1].parent_record_hash,
    )
    records[1] = tampered
    with pytest.raises(ProvenanceLinkBroken):
        verify_dag(records)


def test_reparented_record_detected(valid_chain: list[DelegationCredential]) -> None:
    records = _records_from_chain(valid_chain)
    reparented = DelegationRecord(
        records[2].record_id,
        records[2].credential_id,
        records[2].subject,
        records[2].scope,
        parent_record_hash="deadbeef",
    )
    records[2] = reparented
    with pytest.raises(ProvenanceLinkBroken):
        verify_dag(records)


def test_duplicate_record_id_rejected(valid_chain: list[DelegationCredential]) -> None:
    records = _records_from_chain(valid_chain)
    dup = DelegationRecord(
        records[0].record_id, "cX", "subjX", frozenset({"cap:a"}), records[1].parent_record_hash
    )
    with pytest.raises(ProvenanceLinkBroken):
        verify_dag([records[0], dup])


def test_cross_check_chain_ok(valid_chain: list[DelegationCredential]) -> None:
    records = _records_from_chain(valid_chain)
    cross_check_chain(records, valid_chain)


def test_cross_check_length_mismatch(valid_chain: list[DelegationCredential]) -> None:
    records = _records_from_chain(valid_chain)
    with pytest.raises(ProvenanceLinkBroken):
        cross_check_chain(records[:-1], valid_chain)


def test_cross_check_credential_mismatch(valid_chain: list[DelegationCredential]) -> None:
    records = _records_from_chain(valid_chain)
    bad = DelegationRecord(
        records[0].record_id, "WRONG", records[0].subject, records[0].scope, None
    )
    records[0] = bad
    with pytest.raises(ProvenanceLinkBroken):
        cross_check_chain(records, valid_chain)


def test_cross_check_subject_mismatch() -> None:
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a"})])
    records = _records_from_chain(chain)
    bad = DelegationRecord(
        records[1].record_id, records[1].credential_id, "WRONG-SUBJECT",
        records[1].scope, records[1].parent_record_hash,
    )
    records[1] = bad
    with pytest.raises(ProvenanceLinkBroken):
        cross_check_chain(records, chain)
