"""Placeholder test for Claim 6: cross-operator attestation.

Gated on Tier 3. Real hardware attestation backends are not implemented, so
there is no verifiable quote to exercise mutual attestation or binary-swap
detection against. The test is skipped so CI records it as skipped, not failed.
"""

from __future__ import annotations

import pytest


@pytest.mark.skip(
    reason="Tier 3: real hardware attestation backend not implemented; see ROADMAP.md"
)
def test_cross_operator_mutual_attestation_detects_binary_swap() -> None:
    """Two peers in different trust domains mutually attest; a swapped binary
    changes that peer's measurement and is caught by the counterparty.

    Requires a real hardware provider that can produce and verify a quote.
    """
    raise AssertionError("unreachable: gated on Tier 3 hardware attestation")
