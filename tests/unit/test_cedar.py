"""Tests for the Cedar-backed local policy."""

from __future__ import annotations

import pytest

from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.errors import ScopeNotPermitted
from ca2a_runtime.peer import effective_scope, enforce_peer_call
from ca2a_runtime.policy import Policy
from tests.unit.conftest import build_chain

POLICIES = (
    'permit(principal, action == Action::"read", resource);\n'
    'permit(principal, action == Action::"write", resource);\n'
)


def _chain():
    return build_chain([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])


def test_cedar_policy_satisfies_protocol() -> None:
    assert isinstance(CedarPolicy(POLICIES), Policy)


def test_permits_reflects_cedar_decision() -> None:
    p = CedarPolicy(POLICIES)
    assert p.permits("read") and p.permits("write")
    assert not p.permits("admin")


def test_effective_scope_uses_cedar() -> None:
    # leaf delegated {read, write}; Cedar allows {read, write}; effective {read, write}.
    assert effective_scope(_chain(), CedarPolicy(POLICIES)) == frozenset({"read", "write"})


def test_effective_scope_narrows_to_cedar_allow() -> None:
    read_only = CedarPolicy('permit(principal, action == Action::"read", resource);')
    assert effective_scope(_chain(), read_only) == frozenset({"read"})


def test_enforce_denies_capability_cedar_forbids() -> None:
    read_only = CedarPolicy('permit(principal, action == Action::"read", resource);')
    with pytest.raises(ScopeNotPermitted):
        enforce_peer_call(_chain(), "write", policy=read_only, record_id="r0")


def test_enforce_grants_capability_cedar_allows() -> None:
    decision = enforce_peer_call(_chain(), "read", policy=CedarPolicy(POLICIES), record_id="r0")
    assert decision.granted_capability == "read"


def test_capability_with_colon() -> None:
    p = CedarPolicy('permit(principal, action == Action::"tool:read", resource);')
    assert p.permits("tool:read")
    assert not p.permits("tool:write")
