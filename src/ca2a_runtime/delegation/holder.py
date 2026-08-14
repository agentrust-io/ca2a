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
- ``parent_record_hash``  -- where the emitted provenance record links, so a party
                             on the path cannot re-parent the hop while leaving
                             the proof intact;
- ``caller_channel_key``  -- the channel key from the caller's own offer, when it
                             made one. **This is the join.** It ties the attested
                             runtime and the delegated principal into one
                             statement: the delegate signed for a call from
                             *this* enclave. Neither mechanism provides that
                             alone.

The rule the list follows: every field of the request that reaches the emitted
record is committed. `record_id` without `parent_record_hash` would be half a
commitment to the record's identity, so both are in.

Canonicalization is JCS rather than delimiter-joining for the reason set out in
``docs/spec/attestation.md``: with a delimiter, a value containing it shifts the
split without changing the digest, and ``audience`` and ``challenge`` are
attacker-influenced strings.

**Replay is bounded by the challenge, not eliminated.**
:mod:`ca2a_runtime.challenge` is stateless by design and so cannot be consumed,
which makes this at-most-once-per-window rather than exactly-once: a captured
proof stays usable until its challenge expires, and the window is the TTL.
Keeping the path stateless is the deliberate trade, the same one that module
documents for itself. A deployment needing exactly-once has to supply state, and
the place for it is the challenge rather than here, so the codebase carries one
such decision instead of two.

This is the RFC 7800 confirmation pattern -- the same ``cnf`` semantics the
TRACE layer already applies to provenance records in ``ca2a_verify.dag`` --
applied to the credential that actually gates authority.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.challenge import verify_challenge
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.errors import AttestationFailed, HolderProofInvalid

#: Domain separator. A signature made for a holder proof must never be
#: mistakable for a signature over a credential body or a TRACE record.
PROOF_DOMAIN = "ca2a-holder-proof-v1"

__all__ = [
    "PROOF_DOMAIN",
    "HolderProof",
    "build_holder_proof",
    "proof_body",
    "verify_holder_proof",
]


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
    parent_record_hash: str | None,
) -> dict[str, Any]:
    """The signed body of a holder proof.

    Every field of the request that reaches the emitted provenance record is
    committed here, so a party on the path cannot alter the record's shape while
    leaving the proof intact.

    ``payload_sha256`` is the hex digest of the sealed payload, or ``None`` when
    the request carries none. Committing to the digest rather than the bytes
    keeps the signed body small and JSON-safe while still pinning the ciphertext.

    ``caller_channel_key`` is ``None`` when the caller made no offer, and
    ``parent_record_hash`` is ``None`` on a root hop. Both are committed either
    way: a caller cannot strip its own offer and reuse a proof made while
    attesting, and a root hop cannot have a parent bolted onto it.
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
        "parent_record_hash": parent_record_hash,
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
    parent_record_hash: str | None = None,
) -> HolderProof:
    """Sign a holder proof for ``leaf`` with the delegate's private key.

    ``private_key`` MUST be the private half of ``leaf.subject``; signing with
    any other key produces a proof the callee will reject. ``caller_channel_key``
    must be the channel key of the offer sent with the same request, when one is
    sent, and ``parent_record_hash`` the same value the request carries, or the
    callee will reject the mismatch.
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
        parent_record_hash=parent_record_hash,
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
    parent_record_hash: str | None = None,
) -> None:
    """Verify a holder proof against the leaf credential, or raise.

    The challenge is checked first, against this callee's own secret, so a proof
    answering a challenge nobody here issued is refused before any signature
    work. Then the signature must verify under ``leaf.subject`` over the exact
    request being made.

    Raises :class:`HolderProofInvalid` in both cases. A stale or forged challenge
    surfaces as a holder-proof failure rather than an attestation one, because
    what failed is the caller's claim to the credential, not its runtime.

    **Replay is bounded by the challenge, not eliminated.** The challenge is
    stateless by design and so cannot be consumed, which makes this
    at-most-once-per-window: a captured proof stays usable until its challenge
    expires, and the window is the TTL. Keeping the path stateless is the
    deliberate trade, the same one :mod:`ca2a_runtime.challenge` documents for
    itself; a deployment that needs exactly-once has to supply state, and the
    place to put it is there rather than here, so there is one such decision in
    the codebase instead of two.
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
        parent_record_hash=parent_record_hash,
    )
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(leaf.subject))
        pub.verify(bytes.fromhex(proof.signature), canonicalize(body))
    except (InvalidSignature, ValueError) as exc:
        raise HolderProofInvalid(
            "holder proof signature failed to verify against the leaf subject",
            detail="the presenter does not hold the delegated key",
        ) from exc
