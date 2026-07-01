"""Claim 3: delegated scope intersected with local Cedar policy.

Gated on Tier 2 (runtime peer-delegation enforcement and Cedar intersection are
not built). This placeholder is marked skip so CI records it as skipped, not
failed, until the runtime path exists. See ROADMAP.md.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(
    reason="Tier 2: runtime scope-policy intersection not implemented; see ROADMAP.md"
)
def test_effective_scope_is_delegation_intersect_local_policy() -> None:
    """Effective capability set equals delegated scope AND local Cedar policy.

    When Tier 2 lands, this will build a verified delegation chain, evaluate the
    callee's local Cedar policy, and assert the effective set is the intersection
    of the two, never wider than either input.
    """
    raise AssertionError("not implemented until Tier 2")
