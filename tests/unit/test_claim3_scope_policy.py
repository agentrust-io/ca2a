"""Claim 3: effective permission is the delegated scope intersected with the
callee's local policy.

Validated via the enforcement decision core in ca2a_runtime.peer. Binding a
full Cedar policy engine as the local policy is tracked separately (#10); the
intersection semantics are what this claim establishes.
"""

from __future__ import annotations

import pytest

from ca2a_runtime.errors import ScopeNotPermitted
from ca2a_runtime.peer import effective_scope, enforce_peer_call
from ca2a_runtime.policy import LocalPolicy
from tests.unit.conftest import build_chain


def _chain():
    return build_chain([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])


def test_effective_scope_is_delegation_intersect_local_policy() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    # leaf delegated {read, write}; local allows {read, audit}; intersection {read}.
    assert effective_scope(_chain(), policy) == frozenset({"read"})


def test_effective_scope_never_wider_than_either_input() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    eff = effective_scope(_chain(), policy)
    assert eff <= _chain()[-1].scope
    assert eff <= policy.allow


def test_delegated_but_not_allowed_is_denied() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    with pytest.raises(ScopeNotPermitted):
        enforce_peer_call(_chain(), "write", policy=policy, record_id="r0")


def test_allowed_but_not_delegated_is_denied() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    with pytest.raises(ScopeNotPermitted):
        enforce_peer_call(_chain(), "audit", policy=policy, record_id="r0")


def test_permitted_capability_is_granted_with_provenance() -> None:
    policy = LocalPolicy.of(["read", "audit"])
    decision = enforce_peer_call(_chain(), "read", policy=policy, record_id="r0")
    assert decision.granted_capability == "read"
    assert decision.record.credential_id == _chain()[-1].credential_id
