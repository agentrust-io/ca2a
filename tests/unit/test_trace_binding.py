"""Tests for the delegation-hop -> TRACE record binding and the TRACE DAG verifier.

These exercise the software-attestation path end to end: build a linked TRACE DAG
from a delegation chain, verify it offline, confirm each record passes the TRACE
conformance suite at Level 0 (software-only records are honestly Level 0), and
confirm tampering and untrusted keys fail closed.
"""

from __future__ import annotations

import time

import pytest
from agentrust_trace import generate_key, sign_record, validate_json
from trace_tests.runner import run as run_conformance

from ca2a_runtime.delegation import DelegationCredential
from ca2a_runtime.errors import ProvenanceLinkBroken, TraceRecordInvalid
from ca2a_runtime.trace_binding import (
    EAT_PROFILE,
    HopContext,
    HopSpec,
    build_trace_record,
    digest,
    emit_dag,
    sign_trace_record,
    trace_record_hash,
)
from ca2a_verify import cross_check_trace_dag, verify_trace_dag
from tests.unit.conftest import build_chain

_NOW = int(time.time())


def _software_context(label: str = "ca2a-peer") -> HopContext:
    return HopContext.software(
        model_provider="anthropic",
        model_id="claude-opus-4-8",
        image_label=label,
        policy_bundle_hash=digest(b"policy-bundle"),
    )


def _hops(chain: list[DelegationCredential], keys: list) -> list[HopSpec]:
    """One HopSpec per credential, each with its own signing key and subject."""
    return [
        HopSpec(
            subject=f"spiffe://ca2a.example/peer/{i}",
            signing_key=keys[i],
            context=_software_context(f"peer-{i}"),
            iat=_NOW,
            credential_id=cred.credential_id,
        )
        for i, cred in enumerate(chain)
    ]


def _trusted(keys: list) -> list:
    return [k.public_key() for k in keys]


# --- record construction ---------------------------------------------------


def test_root_record_is_schema_valid_when_signed() -> None:
    record = build_trace_record(subject="spiffe://ca2a.example/root", iat=_NOW, context=_software_context())
    assert "delegation" not in record
    assert record["eat_profile"] == EAT_PROFILE
    signed = sign_trace_record(record, generate_key())
    validate_json(signed)  # does not raise
    assert "signature" in signed and signed["cnf"]["jwk"]["kty"] == "OKP"


def test_non_root_record_carries_delegation_block() -> None:
    parent = sign_trace_record(
        build_trace_record(subject="spiffe://ca2a.example/root", iat=_NOW, context=_software_context()),
        generate_key(),
    )
    child = build_trace_record(
        subject="spiffe://ca2a.example/child",
        iat=_NOW,
        context=_software_context(),
        credential_id="cred-1",
        parent_record_hash=trace_record_hash(parent),
    )
    assert child["delegation"] == {
        "parent_record_hash": trace_record_hash(parent),
        "credential_id": "cred-1",
    }


def test_build_requires_both_credential_id_and_parent_hash() -> None:
    with pytest.raises(ValueError, match="root hop supplies neither"):
        build_trace_record(
            subject="spiffe://ca2a.example/x",
            iat=_NOW,
            context=_software_context(),
            credential_id="cred-1",  # parent_record_hash missing
        )


def test_digest_has_sha256_prefix() -> None:
    d = digest(b"x")
    assert d.startswith("sha256:") and len(d) == len("sha256:") + 64


# --- conformance -----------------------------------------------------------


def test_each_record_passes_trace_level0() -> None:
    keys = [generate_key() for _ in range(3)]
    chain = build_chain(
        [frozenset({"cap:a", "cap:b"}), frozenset({"cap:a", "cap:b"}), frozenset({"cap:a"})]
    )
    records = emit_dag(_hops(chain, keys))
    for i, record in enumerate(records):
        results = run_conformance(record, "trace", level=0)
        failed = [f for findings in results.values() for f in findings if f.failed()]
        assert not failed, f"record {i} failed Level 0: {failed}"


# --- DAG verification ------------------------------------------------------


def test_emit_dag_verifies_offline() -> None:
    keys = [generate_key() for _ in range(3)]
    chain = build_chain(
        [frozenset({"cap:a", "cap:b"}), frozenset({"cap:a", "cap:b"}), frozenset({"cap:a"})]
    )
    records = emit_dag(_hops(chain, keys))
    result = verify_trace_dag(records, trusted_keys=_trusted(keys))
    assert result.hops == 3
    assert result.root_subject == "spiffe://ca2a.example/peer/0"
    assert result.leaf_subject == "spiffe://ca2a.example/peer/2"


def test_cross_check_ties_dag_to_chain() -> None:
    keys = [generate_key() for _ in range(3)]
    chain = build_chain(
        [frozenset({"cap:a", "cap:b"}), frozenset({"cap:a", "cap:b"}), frozenset({"cap:a"})]
    )
    records = emit_dag(_hops(chain, keys))
    cross_check_trace_dag(records, chain)  # does not raise


def test_cross_check_rejects_credential_mismatch() -> None:
    keys = [generate_key() for _ in range(2)]
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a"})])
    hops = _hops(chain, keys)
    hops[1] = HopSpec(
        subject=hops[1].subject,
        signing_key=hops[1].signing_key,
        context=hops[1].context,
        iat=hops[1].iat,
        credential_id="cred-forged",
    )
    records = emit_dag(hops)
    with pytest.raises(ProvenanceLinkBroken, match="credential_id does not match"):
        cross_check_trace_dag(records, chain)


# --- fail-closed behavior --------------------------------------------------


def test_tampered_record_fails_signature() -> None:
    keys = [generate_key() for _ in range(2)]
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a"})])
    records = emit_dag(_hops(chain, keys))
    records[1]["data_class"] = "public"  # mutate after signing
    with pytest.raises(TraceRecordInvalid, match="signature does not verify"):
        verify_trace_dag(records, trusted_keys=_trusted(keys))


def test_resigned_parent_breaks_child_link() -> None:
    keys = [generate_key() for _ in range(2)]
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a"})])
    records = emit_dag(_hops(chain, keys))
    # Re-sign the root with a *valid* signature but altered content: signature
    # verifies, but the record hash changes, so the child's link no longer holds.
    mutated_root = {k: v for k, v in records[0].items() if k != "signature"}
    mutated_root["data_class"] = "public"
    records[0] = sign_record(mutated_root, keys[0])
    with pytest.raises(ProvenanceLinkBroken, match="parent link does not match"):
        verify_trace_dag(records, trusted_keys=_trusted(keys))


def test_untrusted_key_rejected() -> None:
    keys = [generate_key() for _ in range(2)]
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a"})])
    records = emit_dag(_hops(chain, keys))
    with pytest.raises(TraceRecordInvalid, match="untrusted key"):
        verify_trace_dag(records, trusted_keys=[generate_key().public_key()])


def test_root_with_delegation_block_rejected() -> None:
    key = generate_key()
    rogue_root = sign_trace_record(
        build_trace_record(
            subject="spiffe://ca2a.example/root",
            iat=_NOW,
            context=_software_context(),
            credential_id="cred-1",
            parent_record_hash=digest(b"phantom-parent"),
        ),
        key,
    )
    with pytest.raises(ProvenanceLinkBroken, match="root record must not carry"):
        verify_trace_dag([rogue_root], trusted_keys=[key.public_key()])


def test_empty_dag_rejected() -> None:
    with pytest.raises(ProvenanceLinkBroken, match="empty TRACE DAG"):
        verify_trace_dag([], trusted_keys=[])
