"""A cA2A peer node: the runtime state behind an inbound call.

A :class:`PeerNode` holds the enclave channel keypair (the private key the sealed
channel opens against), the local policy the delegated scope is intersected with,
and the attestation provider. :meth:`PeerNode.offer` produces an attested
channel-key offer for the handshake; :meth:`PeerNode.handle` parses a cA2A-profile
A2A message with :mod:`ca2a_runtime.transport.a2a_adapter` and runs the full
inbound pipeline (verify chain, intersect with policy, enforce, open the sealed
payload with the enclave key, emit a linked provenance record). The node is
transport-agnostic; :mod:`ca2a_runtime.transport.server` wraps it over HTTP.
"""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from ca2a_runtime.attestation import ChannelOffer, Verifier, attest_channel
from ca2a_runtime.challenge import DEFAULT_TTL_SECONDS, generate_secret, issue_challenge
from ca2a_runtime.channel import generate_channel_keypair
from ca2a_runtime.delegation.holder import ProofReplayCache
from ca2a_runtime.errors import ConfigError, TransportError
from ca2a_runtime.peer import (
    REQUIRE_HARDWARE,
    REQUIRE_NONE,
    REQUIREMENT_VALUES,
    PeerResult,
    handle_peer_request,
)
from ca2a_runtime.policy import Policy
from ca2a_runtime.tee.base import BaseProvider
from ca2a_runtime.tee.software import SoftwareProvider


class _Unset:
    """Sentinel, so ``seen_proofs=None`` can mean "no cache" rather than "default"."""


_UNSET = _Unset()


class PeerNode:
    """A callee holding a stable enclave channel key, a policy, and a provider.

    Also holds the secret behind the challenges it issues for mutual attestation.
    The secret is per-process and never persisted: a restarted node is a different
    enclave, and a challenge it never issued should not verify.

    ``require_caller_attestation`` defaults to demanding nothing of the caller (see
    :data:`ca2a_runtime.peer.REQUIRE_NONE`). A deployment that wants "hardware or
    nothing" can say so; it is not said for it.
    """

    def __init__(
        self,
        policy: Policy,
        *,
        provider: BaseProvider | None = None,
        max_depth: int = 8,
        require_caller_attestation: str = REQUIRE_NONE,
        caller_verifier: Verifier | None = None,
        challenge_ttl_seconds: int = DEFAULT_TTL_SECONDS,
        require_holder_proof: bool = True,
        seen_proofs: ProofReplayCache | None | _Unset = _UNSET,
        trusted_root_issuers: Collection[str] = (),
    ) -> None:
        if require_caller_attestation not in REQUIREMENT_VALUES:
            raise ConfigError(
                f"require_caller_attestation must be one of {sorted(REQUIREMENT_VALUES)}, "
                f"got {require_caller_attestation!r}"
            )
        if require_caller_attestation == REQUIRE_HARDWARE and caller_verifier is None:
            # verify_offer already refuses a hardware report with no verifier, so
            # this would fail on every call. Failing at construction turns a
            # runtime surprise into a misconfiguration the operator sees at once.
            raise ConfigError(
                "require_caller_attestation='hardware' needs a caller_verifier",
                detail="a hardware report cannot be appraised without one, so every "
                "call would be refused",
            )
        self.policy = policy
        self.provider: BaseProvider = provider if provider is not None else SoftwareProvider()
        self.max_depth = max_depth
        self.require_caller_attestation = require_caller_attestation
        self.caller_verifier = caller_verifier
        self.challenge_ttl_seconds = challenge_ttl_seconds
        self.require_holder_proof = require_holder_proof
        # A proof is honoured once. The challenge underneath is stateless and so
        # cannot be consumed, so single-use comes from remembering the proof. The
        # TTL matches this node's challenge TTL: a proof cannot outlive the
        # challenge it answers, so nothing is gained by remembering it longer.
        # A deployment behind a load balancer wants a shared store or sticky
        # routing, the same caveat the challenge secret already carries; pass
        # ``seen_proofs=None`` to opt out and accept the window instead.
        self.seen_proofs: ProofReplayCache | None
        if isinstance(seen_proofs, _Unset):
            self.seen_proofs = ProofReplayCache(ttl_seconds=challenge_ttl_seconds)
        else:
            self.seen_proofs = seen_proofs
        self.trusted_root_issuers = frozenset(trusted_root_issuers)
        self._private_key, self.channel_public_key = generate_channel_keypair()
        self._challenge_secret = generate_secret()

    def offer(self, nonce: str) -> ChannelOffer:
        """Re-attest the stable enclave channel key under a caller-supplied nonce."""
        return attest_channel(self.provider, self.channel_public_key, nonce)

    def issue_challenge(self) -> str:
        """Issue a challenge for the caller to bind its own channel key into."""
        return issue_challenge(self._challenge_secret, ttl_seconds=self.challenge_ttl_seconds)

    def handle(self, message: dict[str, Any]) -> PeerResult:
        """Parse a cA2A-profile A2A message and run the full inbound pipeline."""
        from ca2a_runtime.transport.a2a_adapter import parse_peer_request

        request = parse_peer_request(message)
        if request is None:
            raise TransportError("message carries no cA2A extension metadata")
        return handle_peer_request(
            request,
            policy=self.policy,
            enclave_private_key=self._private_key,
            max_depth=self.max_depth,
            challenge_secret=self._challenge_secret,
            require_caller_attestation=self.require_caller_attestation,
            caller_verifier=self.caller_verifier,
            audience=self.channel_public_key,
            require_holder_proof=self.require_holder_proof,
            seen_proofs=self.seen_proofs,
            trusted_root_issuers=self.trusted_root_issuers,
        )
