"""Callee-issued challenges for mutual attestation.

A caller that picks its own nonce proves it can produce an attestation report,
not that it produced one for *this* exchange. So the callee issues the nonce the
caller's report must bind. See ``docs/spec/mutual-attestation.md``.

**Stateless, and the guarantee is weaker than a store's.** A challenge is
``v1.<expiry>.<random>.<mac>`` where the MAC is HMAC-SHA256 over the first three
parts under a server secret, so any instance can verify what any other issued and
nothing has to be remembered. The cost is that single-use is unachievable without
state: the same challenge replays until it expires.

That makes the property **at-most-once-per-window**, not exactly-once, and the
window is the TTL. Sixty seconds is the default because it is long enough for a
handshake over a slow link and short enough that a captured challenge is worth
little. Deployments that need exactly-once want a challenge store, which is the
option this one was chosen over and which remains the right answer for a peer
that only ever runs as one process.

The secret is per-process by default. Restarting the callee invalidates
outstanding challenges, which is correct: a restarted enclave is a different
enclave, and a challenge it never issued should not verify.
"""

from __future__ import annotations

import hmac
import secrets
import time
from hashlib import sha256

from ca2a_runtime.errors import AttestationFailed

__all__ = ["DEFAULT_TTL_SECONDS", "generate_secret", "issue_challenge", "verify_challenge"]

DEFAULT_TTL_SECONDS = 60
_PREFIX = "v1"
_RANDOM_BYTES = 16


def generate_secret() -> bytes:
    """A per-process challenge secret. Not persisted, deliberately."""
    return secrets.token_bytes(32)


def _mac(secret: bytes, expiry: int, rand: str) -> str:
    return hmac.new(secret, f"{_PREFIX}.{expiry}.{rand}".encode(), sha256).hexdigest()


def issue_challenge(secret: bytes, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    """Issue a challenge that expires ``ttl_seconds`` from now."""
    if ttl_seconds <= 0:
        raise ValueError(
            "ttl_seconds must be positive; a challenge that never validates is not a challenge"
        )
    expiry = int(time.time()) + ttl_seconds
    rand = secrets.token_hex(_RANDOM_BYTES)
    return f"{_PREFIX}.{expiry}.{rand}.{_mac(secret, expiry, rand)}"


def verify_challenge(secret: bytes, challenge: str, *, now: int | None = None) -> None:
    """Raise :class:`AttestationFailed` unless *challenge* is one we issued and is unexpired.

    Order matters: the MAC is checked before the expiry. Reading a timestamp out
    of an unauthenticated string and acting on it means trusting an attacker's
    arithmetic, and reporting "expired" for a forged challenge tells the sender
    their forgery was well-formed.
    """
    parts = (challenge or "").split(".")
    if len(parts) != 4 or parts[0] != _PREFIX:
        raise AttestationFailed(
            "challenge is malformed",
            detail="expected v1.<expiry>.<random>.<mac>",
        )
    _, expiry_str, rand, mac = parts
    try:
        expiry = int(expiry_str)
    except ValueError as exc:
        raise AttestationFailed("challenge expiry is not an integer") from exc

    if not hmac.compare_digest(mac, _mac(secret, expiry, rand)):
        raise AttestationFailed(
            "challenge was not issued by this peer",
            detail="the MAC does not verify under this peer's challenge secret",
        )

    current = int(time.time()) if now is None else now
    if current >= expiry:
        raise AttestationFailed(
            "challenge has expired",
            detail=(
                "challenges are valid for a bounded window; this is a stateless "
                "scheme, so the window is the only replay bound there is"
            ),
        )
