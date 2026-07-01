"""Tests for the inbound peer-call enforcement decision."""

from __future__ import annotations

import pytest

from ca2a_runtime.errors import ScopeEscalation, ScopeNotPermitted
from ca2a_runtime.peer import PeerDecision, effective_scope, enforce_peer_call
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import verify_dag
from tests.unit.conftest import build_chain


def _chain():
    # leaf scope is {read, write}; local policy will further constrain it.
    return build_chain([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])


def test_local_policy_helpers() -> None:
    p = LocalPolicy.of(["read", "audit"])
    assert p.permits("read") and not p.permits("write")
    assert p.intersect(frozenset({"read", "write"})) == frozenset({"read"})


def test_effective_scope_is_intersection() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    assert effective_scope(_chain(), policy) == frozenset({"read"})


def test_enforce_allows_capability_in_effective_scope() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    decision = enforce_peer_call(_chain(), "read", policy=policy, record_id="rec-0")
    assert isinstance(decision, PeerDecision)
    assert decision.granted_capability == "read"
    assert decision.effective_scope == frozenset({"read"})
    # the emitted record is a valid single-hop provenance root
    assert verify_dag([decision.record]) == [decision.record]


def test_enforce_denies_delegated_but_not_locally_allowed() -> None:
    # "write" is delegated to the leaf but the local policy does not allow it.
    policy = LocalPolicy.of(["read", "audit"])
    with pytest.raises(ScopeNotPermitted):
        enforce_peer_call(_chain(), "write", policy=policy, record_id="rec-0")


def test_enforce_denies_locally_allowed_but_not_delegated() -> None:
    # "audit" is locally allowed but was never delegated down the chain.
    policy = LocalPolicy.of(["read", "audit"])
    with pytest.raises(ScopeNotPermitted):
        enforce_peer_call(_chain(), "audit", policy=policy, record_id="rec-0")


def test_enforce_denies_capability_in_neither() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    with pytest.raises(ScopeNotPermitted):
        enforce_peer_call(_chain(), "admin", policy=policy, record_id="rec-0")


def test_enforce_rejects_invalid_chain() -> None:
    # An escalating chain must fail verification before any policy decision.
    bad = build_chain([frozenset({"read"}), frozenset({"read", "write"})])
    policy = LocalPolicy.of(["read", "write"])
    with pytest.raises(ScopeEscalation):
        enforce_peer_call(bad, "read", policy=policy, record_id="rec-0")


def test_enforce_record_links_to_parent() -> None:
    policy = LocalPolicy.of(["read"])
    decision = enforce_peer_call(_chain(), "read", policy=policy, record_id="rec-1",
                                 parent_record_hash="abc123")
    assert decision.record.parent_record_hash == "abc123"
    assert decision.record.credential_id == _chain()[-1].credential_id
