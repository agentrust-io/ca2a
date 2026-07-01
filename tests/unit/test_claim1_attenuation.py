"""Claim 1: attenuation soundness. A child grant can never exceed its parent.

A strictly narrowing chain verifies, and a hand-built chain whose child adds a
capability its parent never held raises ScopeEscalation.
"""

from __future__ import annotations

import pytest

from ca2a_runtime.delegation import DelegationCredential, verify_chain
from ca2a_runtime.errors import ScopeEscalation
from tests.unit.conftest import build_chain


def test_known_narrowing_chain_verifies() -> None:
    chain = build_chain(
        [
            frozenset({"cap:a", "cap:b", "cap:c"}),
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a"}),
        ]
    )
    verify_chain(chain)  # does not raise


def test_escalating_chain_raises_scope_escalation() -> None:
    # Root grants a and b; the child re-broadens to add cap:c, which no
    # ancestor ever held. That is the confused-deputy escalation.
    chain = build_chain(
        [
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a", "cap:c"}),
        ]
    )
    with pytest.raises(ScopeEscalation) as exc_info:
        verify_chain(chain)
    assert "cap:c" in (exc_info.value.detail or "")


def test_escalation_caught_at_offending_hop() -> None:
    # Two clean narrowing hops, then hop 2 adds cap:new.
    chain = build_chain(
        [
            frozenset({"cap:a", "cap:b", "cap:c"}),
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a", "cap:new"}),
        ]
    )
    with pytest.raises(ScopeEscalation) as exc_info:
        verify_chain(chain)
    assert "hop 2" in str(exc_info.value)


def test_equal_scope_is_not_escalation() -> None:
    # A subset that equals the parent (no narrowing, no widening) is allowed.
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a"})])
    verify_chain(chain)  # does not raise


def test_hand_built_escalating_chain_raises() -> None:
    # Build the chain without the conftest helper to show the escalation is a
    # property of the credential scopes, not the helper.
    from ca2a_runtime.delegation import new_keypair

    root_priv, root_pub = new_keypair()
    mid_priv, mid_pub = new_keypair()
    _, leaf_pub = new_keypair()
    root = DelegationCredential(
        "c0", root_pub, mid_pub, frozenset({"cap:read"}), 0
    ).sign(root_priv)
    child = DelegationCredential(
        "c1",
        mid_pub,
        leaf_pub,
        frozenset({"cap:read", "cap:write"}),
        1,
        parent_id="c0",
    ).sign(mid_priv)
    with pytest.raises(ScopeEscalation):
        verify_chain([root, child])
