"""Holder binding: proving the presenter of a chain is the delegate it names.

A delegation chain is a signed statement about *what* authority was granted. On
its own it says nothing about *who* is presenting it, so a chain lifted from an
audit bundle, a log, a published DAG, or the wire can be replayed verbatim by a
party that holds none of its keys. That is the confused deputy the chain exists
to prevent, so the callee must bind the chain to the caller before acting on it.

**This is not what caller attestation establishes.** An appraised
``caller_offer`` says what the caller is *running*: a measurement, and an X25519
channel key, fresh against a challenge. It says nothing about the Ed25519
delegation subject. A caller can attest itself honestly, present a chain issued
to somebody else, and satisfy both checks, because the two key hierarchies are
never joined. Appraisal answers "what are you"; this module answers "who were
you delegated to". Both are needed and neither substitutes for the other.

The binding material is already in the credential. ``subject`` is an Ed25519
public key, and the delegate demonstrably holds its private half: it is the key
it signs child credentials with. This module makes the callee use it, turning
``subject`` from a string compared for continuity into a key that must answer a
challenge.

The proof is an Ed25519 signature by ``chain[-1].subject`` over the RFC 8785
(JCS) canonical form of a body committing to:

- ``audience``            -- the callee's channel key, so a proof captured by one
                             peer cannot be presented to another;
- ``challenge``           -- issued by the callee (:mod:`ca2a_runtime.challenge`);
- ``credential_id``, ``subject`` -- the specific grant being exercised;
- ``requested_capability``, ``record_id`` -- the specific action, so a proof for
                             a read cannot be lifted onto a write;
- ``payload_sha256``      -- the sealed payload, so the ciphertext cannot be
                             swapped under an otherwise valid proof;
- ``caller_channel_key``  -- the channel key from the caller's own offer, when it
                             made one. **This is the join.** It ties the attested
                             runtime and the delegated principal into one
                             statement: the delegate signed for a call from
                             *this* enclave. Neither mechanism provides that
                             alone.

Canonicalization is JCS rather than delimiter-joining for the reason set out in
``docs/spec/attestation.md``: with a delimiter, a value containing it shifts the
split without changing the digest, and ``audience`` and ``challenge`` are
attacker-influenced strings.

**Replay is bounded by the challenge, not eliminated.**
:mod:`ca2a_runtime.challenge` is stateless by design, so it is
at-most-once-per-window rather than exactly-once, and a captured proof replays
until the challenge expires. That bound is the challenge TTL. A deployment that
needs exactly-once wants a challenge store, which is the trade that module
documents; holder binding inherits whichever choice it makes rather than
introducing a second challenge mechanism beside it.

This is the RFC 7800 confirmation pattern -- the same ``cnf`` semantics the
TRACE layer already applies to provenance records in ``ca2a_verify.dag`` --
applied to the credential that actually gates authority.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.challenge import DEFAULT_TTL_SECONDS, verify_challenge
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.errors import AttestationFailed, HolderProofInvalid

#: Domain separator. A signature made for a holder proof must never be
#: mistakable for a signature over a credential body or a TRACE record.
PROOF_DOMAIN = "ca2a-holder-proof-v1"

#: Default ceiling on remembered proofs. At roughly 80 bytes an entry this is a
#: few megabytes, and entries live only as long as a challenge does, so the
#: steady-state size is request rate times TTL rather than this number.
DEFAULT_MAX_REMEMBERED = 100_000

__all__ = [
    "DEFAULT_MAX_REMEMBERED",
    "PROOF_DOMAIN",
    "HolderProof",
    "ProofReplayCache",
    "build_holder_proof",
    "proof_body",
    "verify_holder_proof",
]


class ProofReplayCache:
    """Remembers accepted proofs so each one is honoured exactly once.

    The challenge underneath is stateless and therefore cannot be consumed, so
    single-use has to come from remembering the *proof* rather than the
    challenge. That is what this does: a proof is recorded once it has verified,
    and a second presentation of the same signature is refused.

    **Entries only need to outlive the challenge they answer.** A proof whose
    challenge has expired is already refused by :func:`verify_challenge`, so
    nothing is gained by remembering it longer. ``ttl_seconds`` must therefore be
    at least the challenge TTL, or a proof could be forgotten while still
    otherwise valid; :class:`~ca2a_runtime.node.PeerNode` passes its own
    challenge TTL for exactly that reason.

    **Bounded, and honest about what the bound costs.** Past ``max_entries`` the
    oldest entry is evicted, so a flood of distinct valid proofs can push an
    earlier one out and let it be replayed inside its window. Refusing new calls
    instead would turn the same flood into an outage, which is worse. So the
    guarantee is exactly-once up to the cache's capacity, degrading to the
    challenge window under flood, rather than exactly-once unconditionally.
    """

    def __init__(
        self,
        *,
        ttl_seconds: float = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_REMEMBERED,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self.max_entries = max_entries
        self._seen: OrderedDict[str, float] = OrderedDict()
        self._lock = threading.Lock()

    def record(self, signature: str) -> bool:
        """Record ``signature``. Return False if it had already been recorded."""
        now = time.monotonic()
        with self._lock:
            self._expire(now)
            if signature in self._seen:
                return False
            while len(self._seen) >= self.max_entries:
                self._seen.popitem(last=False)
            self._seen[signature] = now + self.ttl_seconds
            return True

    def _expire(self, now: float) -> None:
        """Drop expired entries. Caller holds the lock."""
        for sig in [s for s, expires_at in self._seen.items() if expires_at < now]:
            del self._seen[sig]

    def __len__(self) -> int:
        with self._lock:
            self._expire(time.monotonic())
            return len(self._seen)


def proof_body(
    *,
    audience: str,
    challenge: str,
    credential_id: str,
    subject: str,
    requested_capability: str,
    record_id: str,
    sealed_payload: bytes | None,
    caller_channel_key: str | None,
) -> dict[str, Any]:
    """The signed body of a holder proof.

    ``payload_sha256`` is the hex digest of the sealed payload, or ``None`` when
    the request carries none. Committing to the digest rather than the bytes
    keeps the signed body small and JSON-safe while still pinning the ciphertext.

    ``caller_channel_key`` is ``None`` when the caller made no offer. It is a
    committed field either way, so a caller cannot strip its own offer and reuse
    a proof that was made while attesting.
    """
    return {
        "domain": PROOF_DOMAIN,
        "audience": audience,
        "challenge": challenge,
        "credential_id": credential_id,
        "subject": subject,
        "requested_capability": requested_capability,
        "record_id": record_id,
        "payload_sha256": (
            None if sealed_payload is None else hashlib.sha256(sealed_payload).hexdigest()
        ),
        "caller_channel_key": caller_channel_key,
    }


@dataclass(frozen=True)
class HolderProof:
    """A caller's proof that it holds the private key of the leaf ``subject``."""

    challenge: str
    signature: str  # Ed25519 over canonicalize(proof_body(...)), hex

    def to_dict(self) -> dict[str, str]:
        return {"challenge": self.challenge, "signature": self.signature}

    @classmethod
    def from_dict(cls, data: Any) -> HolderProof:
        if not isinstance(data, dict):
            raise HolderProofInvalid(
                "holder_proof must be an object",
                detail=f"got {type(data).__name__}",
            )
        challenge = data.get("challenge")
        signature = data.get("signature")
        if not isinstance(challenge, str) or not challenge:
            raise HolderProofInvalid("holder_proof.challenge must be a non-empty string")
        if not isinstance(signature, str) or not signature:
            raise HolderProofInvalid("holder_proof.signature must be a non-empty string")
        return cls(challenge=challenge, signature=signature)


def build_holder_proof(
    private_key: Ed25519PrivateKey,
    leaf: DelegationCredential,
    *,
    audience: str,
    challenge: str,
    requested_capability: str,
    record_id: str,
    sealed_payload: bytes | None = None,
    caller_channel_key: str | None = None,
) -> HolderProof:
    """Sign a holder proof for ``leaf`` with the delegate's private key.

    ``private_key`` MUST be the private half of ``leaf.subject``; signing with
    any other key produces a proof the callee will reject. ``caller_channel_key``
    must be the channel key of the offer sent with the same request, when one is
    sent, or the callee will reject the mismatch.
    """
    expected = private_key.public_key().public_bytes_raw().hex()
    if expected != leaf.subject:
        raise HolderProofInvalid(
            "signing key does not match the leaf credential subject",
            detail=f"subject={leaf.subject} key={expected}",
        )
    body = proof_body(
        audience=audience,
        challenge=challenge,
        credential_id=leaf.credential_id,
        subject=leaf.subject,
        requested_capability=requested_capability,
        record_id=record_id,
        sealed_payload=sealed_payload,
        caller_channel_key=caller_channel_key,
    )
    return HolderProof(challenge=challenge, signature=private_key.sign(canonicalize(body)).hex())


def verify_holder_proof(
    proof: HolderProof,
    leaf: DelegationCredential,
    *,
    audience: str,
    challenge_secret: bytes,
    requested_capability: str,
    record_id: str,
    sealed_payload: bytes | None = None,
    caller_channel_key: str | None = None,
    seen: ProofReplayCache | None = None,
) -> None:
    """Verify a holder proof against the leaf credential, or raise.

    The challenge is checked first, against this callee's own secret, so a proof
    answering a challenge nobody here issued is refused before any signature
    work. Then the signature must verify under ``leaf.subject`` over the exact
    request being made. Then, if ``seen`` is supplied, the proof is recorded and
    a second presentation of it is refused.

    Raises :class:`HolderProofInvalid` in every case. A stale or forged challenge
    surfaces as a holder-proof failure rather than an attestation one, because
    what failed is the caller's claim to the credential, not its runtime.

    **The replay check comes last, and that ordering is deliberate.** Recording
    before verifying would let anyone fill the cache with unverifiable junk, or
    pre-insert a signature to lock a legitimate caller out of its own proof.
    Recording only what has already verified means an attacker would need the
    delegated key to put anything in there at all, which is the thing they do
    not have.

    Without ``seen`` the guarantee is at-most-once-per-window: a captured proof
    stays usable until its challenge expires.
    """
    try:
        verify_challenge(challenge_secret, proof.challenge)
    except AttestationFailed as exc:
        raise HolderProofInvalid(
            f"holder proof challenge is not usable: {exc}",
            detail=exc.detail,
        ) from exc

    body = proof_body(
        audience=audience,
        challenge=proof.challenge,
        credential_id=leaf.credential_id,
        subject=leaf.subject,
        requested_capability=requested_capability,
        record_id=record_id,
        sealed_payload=sealed_payload,
        caller_channel_key=caller_channel_key,
    )
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(leaf.subject))
        pub.verify(bytes.fromhex(proof.signature), canonicalize(body))
    except (InvalidSignature, ValueError) as exc:
        raise HolderProofInvalid(
            "holder proof signature failed to verify against the leaf subject",
            detail="the presenter does not hold the delegated key",
        ) from exc

    if seen is not None and not seen.record(proof.signature):
        raise HolderProofInvalid(
            "this holder proof has already been used",
            detail="a proof is good for one call; request a fresh challenge",
        )
