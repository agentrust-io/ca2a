"""Tests for delegation credential signing and chain verification."""

from __future__ import annotations

import pytest

from ca2a_runtime.delegation import DelegationCredential, canonical_bytes, new_keypair, verify_chain
from ca2a_runtime.errors import (
    BrokenDelegationLink,
    CredentialReplay,
    DelegationDepthExceeded,
    InvalidCredential,
    ScopeEscalation,
)
from tests.unit.conftest import build_chain


def test_canonical_bytes_is_deterministic() -> None:
    a = canonical_bytes({"b": 1, "a": 2})
    b = canonical_bytes({"a": 2, "b": 1})
    assert a == b


def test_sign_and_verify_roundtrip() -> None:
    priv, pub = new_keypair()
    _, sub = new_keypair()
    cred = DelegationCredential("c0", pub, sub, frozenset({"cap:a"}), 0).sign(priv)
    cred.verify_signature()  # does not raise


def test_sign_with_wrong_key_rejected() -> None:
    priv, pub = new_keypair()
    other_priv, _ = new_keypair()
    _, sub = new_keypair()
    cred = DelegationCredential("c0", pub, sub, frozenset({"cap:a"}), 0)
    with pytest.raises(InvalidCredential):
        cred.sign(other_priv)


def test_unsigned_credential_fails_verify() -> None:
    _, pub = new_keypair()
    _, sub = new_keypair()
    with pytest.raises(InvalidCredential):
        DelegationCredential("c0", pub, sub, frozenset({"cap:a"}), 0).verify_signature()


def test_tampered_scope_fails_verify() -> None:
    priv, pub = new_keypair()
    _, sub = new_keypair()
    signed = DelegationCredential("c0", pub, sub, frozenset({"cap:a"}), 0).sign(priv)
    tampered = DelegationCredential(
        signed.credential_id, signed.issuer, signed.subject,
        frozenset({"cap:a", "cap:root"}), signed.depth, signed.parent_id, signed.signature,
    )
    with pytest.raises(InvalidCredential):
        tampered.verify_signature()


def test_valid_chain_verifies(valid_chain: list[DelegationCredential]) -> None:
    verify_chain(valid_chain)


def test_empty_chain_rejected() -> None:
    with pytest.raises(BrokenDelegationLink):
        verify_chain([])


def test_scope_escalation_rejected() -> None:
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a", "cap:b"})])
    with pytest.raises(ScopeEscalation):
        verify_chain(chain)


def test_depth_limit_enforced(valid_chain: list[DelegationCredential]) -> None:
    with pytest.raises(DelegationDepthExceeded):
        verify_chain(valid_chain, max_depth=1)


def test_broken_parent_link_rejected() -> None:
    # Hop 0: root issues to `mid`. Hop 1: `mid` issues to leaf but names the
    # wrong parent_id, so continuity is broken despite valid signatures.
    root_priv, root_pub = new_keypair()
    mid_priv, mid_pub = new_keypair()
    _, leaf_pub = new_keypair()
    root = DelegationCredential("c0", root_pub, mid_pub, frozenset({"cap:a"}), 0).sign(root_priv)
    child = DelegationCredential(
        "c1", mid_pub, leaf_pub, frozenset({"cap:a"}), 1, parent_id="wrong"
    ).sign(mid_priv)
    with pytest.raises(BrokenDelegationLink):
        verify_chain([root, child])


def test_replayed_credential_id_rejected() -> None:
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a"})])
    dup = DelegationCredential(
        chain[0].credential_id, chain[0].issuer, chain[0].subject,
        chain[0].scope, chain[0].depth, chain[0].parent_id, chain[0].signature,
    )
    with pytest.raises(CredentialReplay):
        verify_chain([chain[0], dup])


def test_root_with_parent_rejected() -> None:
    priv, pub = new_keypair()
    _, sub = new_keypair()
    root = DelegationCredential("c0", pub, sub, frozenset({"cap:a"}), 0, parent_id="x").sign(priv)
    with pytest.raises(BrokenDelegationLink):
        verify_chain([root])


def test_from_dict_roundtrip(valid_chain: list[DelegationCredential]) -> None:
    d = valid_chain[0].body() | {"signature": valid_chain[0].signature}
    restored = DelegationCredential.from_dict(d)
    assert restored == valid_chain[0]


def test_from_dict_malformed() -> None:
    with pytest.raises(InvalidCredential):
        DelegationCredential.from_dict({"issuer": "x"})
