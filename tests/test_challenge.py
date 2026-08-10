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
