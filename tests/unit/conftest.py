"""Shared fixtures: build valid and tampered delegation chains for tests."""

from __future__ import annotations

import pytest

from ca2a_runtime.delegation import DelegationCredential, new_keypair


def build_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    """Build a correctly signed chain where hop i grants scopes[i].

    Continuity is preserved (each issuer is the previous subject) and depth
    increments from 0. Callers pass narrowing scopes to exercise attenuation.
    """
    chain: list[DelegationCredential] = []
    priv, pub = new_keypair()
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{depth}",
            issuer=pub,
            subject=next_pub,
            scope=scope,
            depth=depth,
            parent_id=parent_id,
        ).sign(priv)
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain


@pytest.fixture
def valid_chain() -> list[DelegationCredential]:
    return build_chain(
        [
            frozenset({"cap:a", "cap:b", "cap:c"}),
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a"}),
        ]
    )
