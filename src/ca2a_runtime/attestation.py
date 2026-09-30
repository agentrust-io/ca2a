"""Attestation handshake that gates the sealed channel on a live call.

The sealed channel (:mod:`ca2a_runtime.channel`) seals a task payload to a peer's
X25519 channel key. For that to mean anything, the caller must first obtain that
key from a *verified* attestation report, so the payload is sealed only to a key
the peer's measured enclave holds. This module is that handshake:

- the callee calls :func:`offer_channel` (or :func:`attest_channel` for a
  long-lived enclave key) to bind its channel public key into an attestation
  report under the caller's nonce;
- the caller calls :func:`verify_offer` to check the report binds the offered key
  to that nonce, then :func:`seal_to_peer` to seal a payload to it.

The same primitives run the other direction: a callee that issued a challenge
appraises the caller's own attested channel key with :func:`appraise_caller`. See
``docs/spec/mutual-attestation.md`` for what that adds and what it still does not.

The two directions are kept apart in two ways (``ca2a-caller-offer-v2``). Every
offer is minted for a *role*, and the role selects the binding prefix the
hardware signs (:mod:`ca2a_runtime.tee.binding`): the public handshake endpoint
only ever mints callee offers, and a callee only accepts caller offers. And a
caller offer is not enough on its own: the caller proves it holds the attested
channel private key with :func:`prove_caller_possession`, a MAC over the request
transcript keyed from X25519 between the two attested channel keys. Without that
proof an offer is only evidence that *some* enclave holds the key, which is what
a relay exploits.

Two assurance modes, never blended. In ``software-only`` mode there is no
hardware guarantee: :func:`verify_offer` returns ``assurance="none"`` and the
seal protects against a passive network observer only. On a confidential VM a
``verifier`` callable checks the hardware quote (wrapping :mod:`ca2a_verify`) and
the report-data binding, and :func:`verify_offer` returns ``assurance="hardware"``.
The ``verifier`` seam keeps this module free of any hardware dependency; driving
it off a real hardware quote end to end is the remaining hardware step (ROADMAP).
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.challenge import verify_challenge
from ca2a_runtime.channel import SealedChannel, generate_channel_keypair
from ca2a_runtime.errors import AttestationFailed
from ca2a_runtime.tee.base import AttestationReport, BaseProvider
from ca2a_runtime.tee.binding import ROLE_CALLEE, ROLE_CALLER

SOFTWARE_ONLY = "software-only"

# A hardware verifier takes an attestation report and the nonce the caller
# expects, and returns the verified enclave measurement or raises
# AttestationFailed. On a confidential VM this wraps ca2a_verify (SEV-SNP, TDX,
# or TPM); it is injected so this module carries no hardware dependency.
Verifier = Callable[[AttestationReport, str], str]


@dataclass(frozen=True)
class ChannelOffer:
    """A callee's attested channel-key offer: a public key and the report binding it."""

    channel_public_key: str
    report: AttestationReport


@dataclass(frozen=True)
class VerifiedPeer:
    """A peer channel key the caller has appraised, with its assurance level."""

    public_key: str
    assurance: str  # "hardware" or "none"
    measurement: str


def attest_channel(
    provider: BaseProvider, public_key: str, nonce: str, *, role: str = ROLE_CALLEE
) -> ChannelOffer:
    """Bind an existing enclave channel ``public_key`` into a report under ``nonce``.

    ``role`` defaults to a callee offer, which is what a handshake endpoint
    serves. The role is passed to the provider only when it is not the default,
    so a provider written against the pre-role interface still serves handshakes.
    """
    report = (
        provider.attest(public_key, nonce)
        if role == ROLE_CALLEE
        else provider.attest(public_key, nonce, role=role)
    )
    if report.role != role:
        raise AttestationFailed(
            "the provider attested a different offer role than was requested",
            detail=f"requested {role!r}, report says {report.role!r}",
        )
    return ChannelOffer(channel_public_key=public_key, report=report)


def offer_channel(
    provider: BaseProvider, *, nonce: str, role: str = ROLE_CALLEE
) -> tuple[X25519PrivateKey, ChannelOffer]:
    """Generate a channel keypair and bind its public key into a report under ``nonce``.

    The private key is returned to the offerer and, on hardware, never leaves the
    enclave. The offer carries the public key and the report that binds it. A
    caller minting its own offer passes ``role=ROLE_CALLER`` and keeps the
    private key to answer :func:`prove_caller_possession`.
    """
    private_key, public_key = generate_channel_keypair()
    return private_key, attest_channel(provider, public_key, nonce, role=role)


def verify_offer(
    offer: ChannelOffer,
    *,
    expected_nonce: str,
    verifier: Verifier | None = None,
    require_hardware: bool = False,
    role: str = ROLE_CALLEE,
) -> VerifiedPeer:
    """Appraise a channel offer and return the peer key with its assurance level.

    ``role`` is the role the offer must have been minted for: a caller appraising
    a callee expects ``ROLE_CALLEE`` (the default), and :func:`appraise_caller`
    expects ``ROLE_CALLER``. It is checked first, and on hardware the verifier
    recomputes the binding under the report's role, so a relabelled offer fails
    there as well.

    Checks the report binds the offered public key under ``expected_nonce`` so a
    stale or swapped offer is rejected. In ``software-only`` mode the assurance
    is ``none``. If the report claims a hardware platform, a ``verifier`` is
    required and establishes ``assurance="hardware"``; a hardware report with no
    verifier fails closed rather than being trusted. Fails closed on any
    mismatch (raises :class:`AttestationFailed`).

    Set ``require_hardware=True`` when the payload requires a hardware boundary.
    Merely supplying a verifier does not reject software offers for compatibility.
    """
    report = offer.report
    if report.role != role:
        raise AttestationFailed(
            f"channel offer was minted for the {report.role!r} role, expected {role!r}",
            detail=(
                "a handshake-endpoint offer cannot be presented as a caller offer; a caller "
                f"offer must be minted for the caller's own call ({CALLER_OFFER_VERSION}), "
                "and a pre-v2 caller offer carries no role"
            ),
        )
    if report.public_key != offer.channel_public_key:
        raise AttestationFailed("attestation report does not bind the offered channel key")
    if report.nonce != expected_nonce:
        raise AttestationFailed(
            "attestation report nonce does not match the expected nonce",
            detail="stale or replayed channel offer",
        )
    if report.platform == SOFTWARE_ONLY:
        if require_hardware:
            raise AttestationFailed(
                "peer hardware attestation is required; software-only offer refused"
            )
        return VerifiedPeer(
            public_key=offer.channel_public_key,
            assurance="none",
            measurement=report.measurement,
        )
    if verifier is None:
        raise AttestationFailed(
            f"a {report.platform!r} report requires a hardware verifier",
            detail="refusing to trust a hardware attestation report without verification",
        )
    measurement = verifier(report, expected_nonce)
    return VerifiedPeer(
        public_key=offer.channel_public_key,
        assurance="hardware",
        measurement=measurement,
    )


def appraise_caller(
    offer: ChannelOffer,
    *,
    challenge_secret: bytes,
    verifier: Verifier | None = None,
) -> VerifiedPeer:
    """Appraise a *caller's* offer against a challenge this peer issued.

    The mirror image of :func:`verify_offer`, and the two differ in where the
    expected nonce comes from. A caller appraising a callee remembers the nonce it
    sent, so :func:`verify_offer` compares the report against a value the caller
    already holds. A callee keeps no such state: the challenge scheme is
    stateless by design (see :mod:`ca2a_runtime.challenge`), so the nonce arrives
    inside the report and the callee re-derives whether it is one of its own.

    That makes the order here load-bearing. ``verify_challenge`` runs first and is
    the substantive check: it recomputes the MAC under this peer's secret and
    rejects an expired window, which is what establishes that this peer issued
    the nonce and issued it recently. Only then is the nonce trustworthy enough to
    appraise the report against, so passing ``expected_nonce=offer.report.nonce``
    into :func:`verify_offer` is not the circular check it looks like: by that
    point the nonce is authenticated, and what remains for ``verify_offer`` to do
    is bind the offered channel key to it and establish the assurance level.

    An appraised caller offer establishes that an enclave with this measurement
    holds the offered key. It does not establish that the party *presenting* the
    offer is that enclave; :func:`verify_caller_possession` does, and the inbound
    pipeline requires both.
    """
    verify_challenge(challenge_secret, offer.report.nonce)
    return verify_offer(
        offer, expected_nonce=offer.report.nonce, verifier=verifier, role=ROLE_CALLER
    )


#: The caller-offer protocol version: role-separated bindings plus proof of
#: possession. Carried on the wire with the proof and committed in its transcript.
CALLER_OFFER_VERSION = "ca2a-caller-offer-v2"
_POSSESSION_KEY_INFO = b"ca2a/caller-possession/v2/key"
_POSSESSION_STATEMENT = b"ca2a/caller-possession/v2/statement\x00"


@dataclass(frozen=True)
class CallerPossession:
    """The caller's proof that it holds the private half of its offered channel key."""

    version: str
    mac: str  # HMAC-SHA256 over the canonical transcript, hex

    def to_dict(self) -> dict[str, str]:
        return {"version": self.version, "mac": self.mac}

    @classmethod
    def from_dict(cls, data: Any) -> CallerPossession:
        if not isinstance(data, dict):
            raise AttestationFailed(
                "caller_possession must be an object", detail=f"got {type(data).__name__}"
            )
        version, mac = data.get("version"), data.get("mac")
        if not isinstance(version, str) or not version:
            raise AttestationFailed("caller_possession.version must be a non-empty string")
        if not isinstance(mac, str) or not mac:
            raise AttestationFailed("caller_possession.mac must be a non-empty string")
        return cls(version=version, mac=mac)


def caller_possession_transcript(
    *,
    challenge: str,
    callee_channel_key: str,
    caller_channel_key: str,
    credential_id: str,
    subject: str,
    requested_capability: str,
    record_id: str,
    sealed_payload: bytes | None,
    parent_record_hash: str | None,
    holder_proof_signature: str | None,
) -> dict[str, Any]:
    """The statement a proof of possession MACs.

    It commits the same request fields a holder proof does, plus the holder
    proof's own signature, so a proof captured from one request cannot be lifted
    onto another: a different record, capability, payload, parent, credential, or
    challenge changes the transcript. ``holder_proof_signature`` is ``None`` only
    on a path that runs without holder binding.
    """
    return {
        "version": CALLER_OFFER_VERSION,
        "challenge": challenge,
        "callee_channel_key": callee_channel_key,
        "caller_channel_key": caller_channel_key,
        "credential_id": credential_id,
        "subject": subject,
        "requested_capability": requested_capability,
        "record_id": record_id,
        "payload_sha256": (
            None if sealed_payload is None else hashlib.sha256(sealed_payload).hexdigest()
        ),
        "parent_record_hash": parent_record_hash,
        "holder_proof_signature": holder_proof_signature,
    }


def _possession_mac(
    private_key: X25519PrivateKey,
    peer_public_key: str,
    *,
    caller_channel_key: str,
    callee_channel_key: str,
    transcript: dict[str, Any],
) -> str:
    """HMAC the transcript under a key only the two attested channel keys share.

    The same shape as the sealed channel and the response MAC: X25519, then
    HKDF-SHA256 under a label of its own, over both public keys and the shared
    secret. Either side computes it from its own private key and the other's
    public key.
    """
    try:
        shared = private_key.exchange(
            X25519PublicKey.from_public_bytes(bytes.fromhex(peer_public_key))
        )
        ikm = bytes.fromhex(caller_channel_key) + bytes.fromhex(callee_channel_key) + shared
    except ValueError as exc:
        # A malformed key, or a low-order point that yields no shared secret.
        raise AttestationFailed(
            "caller proof of possession could not be keyed", detail=str(exc)
        ) from exc
    key = HKDF(algorithm=SHA256(), length=32, salt=None, info=_POSSESSION_KEY_INFO).derive(ikm)
    return hmac.new(key, _POSSESSION_STATEMENT + canonicalize(transcript), "sha256").hexdigest()


def prove_caller_possession(
    caller_private_key: X25519PrivateKey,
    *,
    callee_channel_key: str,
    transcript: dict[str, Any],
) -> CallerPossession:
    """Caller side: prove the offered channel key is held by the party calling."""
    caller_channel_key = caller_private_key.public_key().public_bytes_raw().hex()
    if transcript.get("caller_channel_key") != caller_channel_key:
        raise AttestationFailed("possession transcript names a different caller channel key")
    if transcript.get("callee_channel_key") != callee_channel_key:
        raise AttestationFailed("possession transcript names a different callee channel key")
    mac = _possession_mac(
        caller_private_key,
        callee_channel_key,
        caller_channel_key=caller_channel_key,
        callee_channel_key=callee_channel_key,
        transcript=transcript,
    )
    return CallerPossession(version=CALLER_OFFER_VERSION, mac=mac)


def verify_caller_possession(
    possession: CallerPossession | None,
    *,
    callee_private_key: X25519PrivateKey,
    transcript: dict[str, Any],
) -> None:
    """Callee side: recompute the MAC and compare in constant time, or raise.

    The key comes from X25519(callee private key, the caller key the *report*
    attests), so only the holder of that attested key could have produced the
    MAC. A party relaying another enclave's offer holds the offer, not the key.
    """
    if possession is None:
        raise AttestationFailed(
            "caller offer carries no proof of possession of its channel key",
            detail=f"{CALLER_OFFER_VERSION} requires caller_possession with every "
            "caller_offer; an older caller must be upgraded",
        )
    if possession.version != CALLER_OFFER_VERSION:
        raise AttestationFailed(
            "caller proof of possession has an unsupported version",
            detail=f"got {possession.version!r}, expected {CALLER_OFFER_VERSION!r}",
        )
    callee_channel_key = callee_private_key.public_key().public_bytes_raw().hex()
    if transcript.get("callee_channel_key") != callee_channel_key:
        raise AttestationFailed("possession transcript names a different callee channel key")
    caller_channel_key = str(transcript.get("caller_channel_key"))
    expected = _possession_mac(
        callee_private_key,
        caller_channel_key,
        caller_channel_key=caller_channel_key,
        callee_channel_key=callee_channel_key,
        transcript=transcript,
    )
    if not hmac.compare_digest(possession.mac.encode(), expected.encode()):
        raise AttestationFailed(
            "caller proof of possession did not verify",
            detail="the presenter does not hold the attested caller channel key, "
            "or the proof was made for a different request",
        )


def seal_to_peer(peer: VerifiedPeer, payload: bytes, *, aad: bytes = b"") -> bytes:
    """Seal ``payload`` to a verified peer's channel key."""
    return SealedChannel(peer.public_key).seal(payload, aad=aad)
