"""Tests for callee-issued challenges.

A challenge exists to stop a caller replaying an attestation report it made
earlier for someone else. So the tests are the ways a challenge could look valid
and not be: forged, expired, issued by a different peer, or reshaped so a field
an attacker controls gets read before anything authenticates it.
"""

from __future__ import annotations

import time

import pytest

from ca2a_runtime.challenge import (
    DEFAULT_TTL_SECONDS,
    generate_secret,
    issue_challenge,
    verify_challenge,
)
from ca2a_runtime.errors import AttestationFailed


def test_round_trip() -> None:
    secret = generate_secret()
    verify_challenge(secret, issue_challenge(secret))


def test_a_different_peer_secret_does_not_verify() -> None:
    """A challenge is only worth something to the peer that issued it."""
    challenge = issue_challenge(generate_secret())
    with pytest.raises(AttestationFailed, match="not issued by this peer"):
        verify_challenge(generate_secret(), challenge)


def test_expiry_is_enforced() -> None:
    secret = generate_secret()
    challenge = issue_challenge(secret, ttl_seconds=1)
    with pytest.raises(AttestationFailed, match="expired"):
        verify_challenge(secret, challenge, now=int(time.time()) + 5)


def test_valid_until_the_moment_it_expires() -> None:
    secret = generate_secret()
    expiry = int(issue_challenge(secret, ttl_seconds=30).split(".")[1])
    challenge = issue_challenge(secret, ttl_seconds=30)
    verify_challenge(secret, challenge, now=expiry - 1)


def test_tampering_with_the_expiry_is_caught() -> None:
    """The reason the MAC covers the timestamp.

    Without it, extending a captured challenge is a one-character edit.
    """
    secret = generate_secret()
    _, expiry, rand, mac = issue_challenge(secret, ttl_seconds=1).split(".")
    forged = f"v1.{int(expiry) + 86400}.{rand}.{mac}"
    with pytest.raises(AttestationFailed, match="not issued by this peer"):
        verify_challenge(secret, forged)


def test_a_forged_challenge_is_reported_as_forged_not_expired() -> None:
    """Order matters: authenticate before reading the timestamp.

    Reporting "expired" for a forgery tells the sender their forgery was
    well-formed, and acting on an unauthenticated timestamp means trusting an
    attacker's arithmetic.
    """
    secret = generate_secret()
    forged = f"v1.{int(time.time()) - 10}.deadbeef.{'0' * 64}"
    with pytest.raises(AttestationFailed, match="not issued by this peer"):
        verify_challenge(secret, forged)


def test_challenges_are_unique() -> None:
    secret = generate_secret()
    assert len({issue_challenge(secret) for _ in range(50)}) == 50


@pytest.mark.parametrize(
    "bad",
    ["", "nonsense", "v1.123", "v1.123.abc", "v2.123.abc.def", "v1.notanint.abc.def"],
)
def test_malformed_challenges_are_refused(bad: str) -> None:
    with pytest.raises(AttestationFailed):
        verify_challenge(generate_secret(), bad)


def test_zero_ttl_is_refused_at_issue_time() -> None:
    """A challenge that never validates is a bug that would present as flaky."""
    with pytest.raises(ValueError, match="not a challenge"):
        issue_challenge(generate_secret(), ttl_seconds=0)


def test_default_window_is_short() -> None:
    """Stateless means the window is the only replay bound there is."""
    assert DEFAULT_TTL_SECONDS <= 300


def test_a_restarted_peer_invalidates_outstanding_challenges() -> None:
    """A restarted enclave is a different enclave.

    The secret is per-process and not persisted, so this is the behaviour rather
    than an accident of it.
    """
    challenge = issue_challenge(generate_secret())
    with pytest.raises(AttestationFailed):
        verify_challenge(generate_secret(), challenge)


@pytest.mark.parametrize(
    "mac",
    ["é" * 64, "A" * 64, "0" * 63, "0" * 65, "g" * 64],
    ids=["non-ascii", "uppercase", "short", "long", "non-hex"],
)
def test_a_malformed_mac_is_refused_as_attestation_failure(mac: str) -> None:
    """The MAC arrives from the caller, inside a holder proof or an offer nonce.

    A non-ASCII MAC used to reach hmac.compare_digest, which raises TypeError on
    such a str, so the refusal escaped as an unhandled exception rather than as
    the AttestationFailed every other bad challenge produces.
    """
    secret = generate_secret()
    prefix, expiry, rand, _ = issue_challenge(secret).split(".")
    with pytest.raises(AttestationFailed, match="malformed"):
        verify_challenge(secret, f"{prefix}.{expiry}.{rand}.{mac}")


@pytest.mark.parametrize("bad_ttl", [True, False, -5, 1.5, "60"])
def test_issue_challenge_rejects_boolean_or_non_int_ttl(bad_ttl) -> None:
    with pytest.raises(ValueError):
        issue_challenge(generate_secret(), ttl_seconds=bad_ttl)


@pytest.mark.parametrize("bad_secret", [b"", b"short", "32-char-string------------------", None])
def test_challenge_rejects_invalid_secret(bad_secret) -> None:
    with pytest.raises(ValueError, match="secret"):
        issue_challenge(bad_secret)
    with pytest.raises(ValueError, match="secret"):
        verify_challenge(bad_secret, "v1.1.aa.bb")


@pytest.mark.parametrize("bad_now", [True, False, 1.5, "100"])
def test_verify_challenge_rejects_boolean_or_non_int_now(bad_now) -> None:
    secret = generate_secret()
    ch = issue_challenge(secret)
    with pytest.raises(ValueError, match="now"):
        verify_challenge(secret, ch, now=bad_now)


@pytest.mark.parametrize(
    "bad_challenge",
    [
        123,
        None,
        ["v1"],
        f"v1.+100.{'a' * 32}.{'0' * 64}",
        f"v1. 100 .{'a' * 32}.{'0' * 64}",
        f"v1.{'9' * 4301}.{'a' * 32}.{'0' * 64}",
    ],
)
def test_verify_challenge_rejects_non_str_and_non_decimal_expiry(bad_challenge) -> None:
    with pytest.raises(AttestationFailed):
        verify_challenge(generate_secret(), bad_challenge)


@pytest.mark.parametrize("bad_iat", [True, False, 0, -1, 1.5, 2**53])
def test_build_trace_record_and_emit_dag_validate_inputs(bad_iat) -> None:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ca2a_runtime.trace_binding import HopContext, HopSpec, build_trace_record, emit_dag

    ctx = HopContext.software(
        model_provider="p",
        model_id="m",
        image_label="img",
        policy_bundle_hash="sha256:" + "a" * 64,
    )
    with pytest.raises(ValueError):
        build_trace_record(subject="spiffe://example/a", iat=bad_iat, context=ctx)
    with pytest.raises(ValueError):
        build_trace_record(subject="", iat=1000, context=ctx)
    with pytest.raises(ValueError):
        build_trace_record(
            subject="spiffe://example/a",
            iat=1000,
            context=ctx,
            credential_id="",
            parent_record_hash="sha256:" + "b" * 64,
        )
    with pytest.raises(ValueError):
        emit_dag([])
    key = Ed25519PrivateKey.generate()
    with pytest.raises(ValueError, match="non-root hop"):
        emit_dag(
            [
                HopSpec(subject="spiffe://example/0", signing_key=key, context=ctx, iat=1000),
                HopSpec(subject="spiffe://example/1", signing_key=key, context=ctx, iat=1000),
            ]
        )
