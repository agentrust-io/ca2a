"""Claim 2: cross-chain replay rejection.

A credential replayed within a chain (duplicate credential_id) or spliced from
another chain is rejected by verify_chain.
"""

from __future__ import annotations

import pytest

from ca2a_runtime.delegation import DelegationCredential, verify_chain
from ca2a_runtime.errors import BrokenDelegationLink, CredentialReplay
from tests.unit.conftest import build_chain


def _chain_a() -> list[DelegationCredential]:
    return build_chain(
        [
            frozenset({"cap:a", "cap:b", "cap:c"}),
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a"}),
        ]
    )


def test_control_chain_is_valid() -> None:
    verify_chain(_chain_a())


def test_duplicate_credential_id_raises_replay() -> None:
    chain = _chain_a()
    replayed = [chain[0], chain[1], chain[1]]
    with pytest.raises(CredentialReplay):
        verify_chain(replayed)


def test_cross_chain_splice_is_rejected() -> None:
    chain_a = _chain_a()
    chain_b = build_chain(
        [
            frozenset({"cap:x", "cap:y", "cap:z"}),
            frozenset({"cap:x", "cap:y"}),
            frozenset({"cap:x"}),
        ]
    )
    # A credential minted for chain A spliced into chain B breaks B's
    # continuity: its issuer is not B's previous subject.
    spliced = [chain_b[0], chain_a[1], chain_b[2]]
    with pytest.raises((BrokenDelegationLink, CredentialReplay)):
        verify_chain(spliced)
