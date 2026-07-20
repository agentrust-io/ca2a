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

Two assurance modes, never blended. In ``software-only`` mode there is no
hardware guarantee: :func:`verify_offer` returns ``assurance="none"`` and the
seal protects against a passive network observer only. On a confidential VM a
``verifier`` callable checks the hardware quote (wrapping :mod:`ca2a_verify`) and
the report-data binding, and :func:`verify_offer` returns ``assurance="hardware"``.
The ``verifier`` seam keeps this module free of any hardware dependency; driving
it off a real hardware quote end to end is the remaining hardware step (ROADMAP).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair
from ca2a_runtime.errors import AttestationFailed
from ca2a_runtime.tee.base import AttestationReport, BaseProvider

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


def attest_channel(provider: BaseProvider, public_key: str, nonce: str) -> ChannelOffer:
    """Bind an existing enclave channel ``public_key`` into a report under ``nonce``."""
    return ChannelOffer(
        channel_public_key=public_key,
        report=provider.attest(public_key, nonce),
    )


def offer_channel(
    provider: BaseProvider, *, nonce: str
) -> tuple[X25519PrivateKey, ChannelOffer]:
    """Generate a channel keypair and bind its public key into a report under ``nonce``.

    The private key is returned to the callee and, on hardware, never leaves the
    enclave. The offer carries the public key and the report that binds it.
    """
    private_key, public_key = generate_channel_keypair()
    return private_key, attest_channel(provider, public_key, nonce)


def verify_offer(
    offer: ChannelOffer, *, expected_nonce: str, verifier: Verifier | None = None
) -> VerifiedPeer:
    """Appraise a channel offer and return the peer key with its assurance level.

    Checks the report binds the offered public key under ``expected_nonce`` so a
    stale or swapped offer is rejected. In ``software-only`` mode the assurance
    is ``none``. If the report claims a hardware platform, a ``verifier`` is
    required and establishes ``assurance="hardware"``; a hardware report with no
    verifier fails closed rather than being trusted. Fails closed on any
    mismatch (raises :class:`AttestationFailed`).
    """
    report = offer.report
    if report.public_key != offer.channel_public_key:
        raise AttestationFailed("attestation report does not bind the offered channel key")
    if report.nonce != expected_nonce:
        raise AttestationFailed(
            "attestation report nonce does not match the expected nonce",
            detail="stale or replayed channel offer",
        )
    if report.platform == SOFTWARE_ONLY:
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


def seal_to_peer(peer: VerifiedPeer, payload: bytes, *, aad: bytes = b"") -> bytes:
    """Seal ``payload`` to a verified peer's channel key."""
    return SealedChannel(peer.public_key).seal(payload, aad=aad)
