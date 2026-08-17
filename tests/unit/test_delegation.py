"""Tests for delegation credential signing and chain verification."""

from __future__ import annotations

from dataclasses import replace

import pytest

from ca2a_runtime.delegation import DelegationCredential, canonical_bytes, new_keypair, verify_chain
from ca2a_runtime.errors import (
    BrokenDelegationLink,
    CredentialExpired,
    CredentialNotYetValid,
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
        signed.credential_id,
        signed.issuer,
        signed.subject,
        frozenset({"cap:a", "cap:root"}),
        signed.depth,
        signed.parent_id,
        signed.signature,
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
        chain[0].credential_id,
        chain[0].issuer,
        chain[0].subject,
        chain[0].scope,
        chain[0].depth,
        chain[0].parent_id,
        chain[0].signature,
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


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("credential_id", 7),
        ("issuer", "00"),
        ("subject", "not-a-key"),
        ("scope", "read"),
        ("scope", ["read", "read"]),
        ("scope", ["read", 1]),
        ("depth", 0.9),
        ("depth", True),
        ("depth", -1),
        ("parent_id", 7),
        ("signature", "00"),
        ("not_before", 1.5),
        ("not_before", True),
        ("not_before", -1),
        ("not_before", None),
        ("not_after", "soon"),
        ("not_after", None),
    ],
)
def test_from_dict_rejects_type_coercion_and_invalid_crypto_fields(
    valid_chain: list[DelegationCredential], field: str, value: object
) -> None:
    raw = valid_chain[0].body() | {"signature": valid_chain[0].signature}
    raw[field] = value
    with pytest.raises(InvalidCredential):
        DelegationCredential.from_dict(raw)


def test_from_dict_rejects_unsigned_extra_semantics(
    valid_chain: list[DelegationCredential],
) -> None:
    raw = valid_chain[0].body() | {
        "signature": valid_chain[0].signature,
        "admin": True,
    }
    with pytest.raises(InvalidCredential, match="fields"):
        DelegationCredential.from_dict(raw)


# --- Validity window ---


def test_windowed_credential_roundtrip_and_inclusive_bounds() -> None:
    chain = build_chain([frozenset({"cap:a"})], not_before=1_000, not_after=2_000)
    verify_chain(chain, at_time=1_000)
    verify_chain(chain, at_time=2_000)
    restored = DelegationCredential.from_dict(chain[0].body() | {"signature": chain[0].signature})
    assert restored == chain[0]


def test_expired_credential_rejected() -> None:
    chain = build_chain([frozenset({"cap:a"})], not_before=1_000, not_after=2_000)
    with pytest.raises(CredentialExpired):
        verify_chain(chain, at_time=2_001)


def test_not_yet_valid_credential_rejected() -> None:
    chain = build_chain([frozenset({"cap:a"})], not_before=1_000, not_after=2_000)
    with pytest.raises(CredentialNotYetValid):
        verify_chain(chain, at_time=999)


def test_expired_credential_rejected_by_default_clock() -> None:
    # No at_time supplied: verification must evaluate at the current time
    # rather than skipping the window, or an expired chain would pass on every
    # existing call site by default.
    chain = build_chain([frozenset({"cap:a"})], not_after=1_000)
    with pytest.raises(CredentialExpired):
        verify_chain(chain)


def test_stripping_a_signed_validity_bound_breaks_the_signature() -> None:
    chain = build_chain([frozenset({"cap:a"})], not_after=2_000)
    stripped = replace(chain[0], not_after=None)
    with pytest.raises(InvalidCredential):
        stripped.verify_signature()


def test_body_omits_absent_bounds(valid_chain: list[DelegationCredential]) -> None:
    # Encoding absent bounds as null would change the canonical bytes of every
    # credential signed before the fields existed.
    body = valid_chain[0].body()
    assert "not_before" not in body
    assert "not_after" not in body
    valid_chain[0].verify_signature()


@pytest.mark.parametrize("field", ["not_before", "not_after"])
@pytest.mark.parametrize("value", [True, -5, 1.5, "1000"])
def test_direct_construction_rejects_invalid_bounds(field: str, value: object) -> None:
    # The dataclass is a public constructor too; without __post_init__ a bound
    # outside the documented wire format could be signed into a body that this
    # implementation's own from_dict rejects.
    _, pub = new_keypair()
    _, sub = new_keypair()
    with pytest.raises(InvalidCredential):
        DelegationCredential(
            "c0",
            pub,
            sub,
            frozenset({"cap:a"}),
            0,
            **{field: value},  # type: ignore[arg-type]
        )


def test_direct_construction_rejects_inverted_window() -> None:
    _, pub = new_keypair()
    _, sub = new_keypair()
    with pytest.raises(InvalidCredential, match="inverted"):
        DelegationCredential(
            "c0", pub, sub, frozenset({"cap:a"}), 0, not_before=2_000, not_after=1_000
        )


@pytest.mark.parametrize("bad_at_time", [True, 1.5, -1, "1500"])
def test_verify_chain_rejects_non_integer_at_time(
    valid_chain: list[DelegationCredential], bad_at_time: object
) -> None:
    # The credential bounds are strict JSON integers; the evaluation time they
    # are compared against holds the same line for library callers.
    with pytest.raises(ValueError, match="at_time"):
        verify_chain(valid_chain, at_time=bad_at_time)  # type: ignore[arg-type]


def test_from_dict_rejects_inverted_window(valid_chain: list[DelegationCredential]) -> None:
    raw = valid_chain[0].body() | {
        "signature": valid_chain[0].signature,
        "not_before": 2_000,
        "not_after": 1_000,
    }
    with pytest.raises(InvalidCredential, match="inverted"):
        DelegationCredential.from_dict(raw)
