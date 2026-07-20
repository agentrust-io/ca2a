"""A cA2A peer node: the runtime state behind an inbound call.

A :class:`PeerNode` holds the enclave channel keypair (the private key the sealed
channel opens against), the local policy the delegated scope is intersected with,
and the attestation provider. :meth:`PeerNode.offer` produces an attested
channel-key offer for the handshake; :meth:`PeerNode.handle` runs the full
inbound pipeline for a parsed cA2A-profile A2A message (verify chain, intersect
with policy, enforce, open the sealed payload with the enclave key, emit a linked
provenance record). The node is transport-agnostic;
:mod:`ca2a_runtime.transport.server` wraps it over HTTP.
"""

from __future__ import annotations

from typing import Any

from ca2a_runtime.attestation import ChannelOffer, attest_channel
from ca2a_runtime.channel import generate_channel_keypair
from ca2a_runtime.peer import PeerResult, handle_peer_request
from ca2a_runtime.policy import Policy
from ca2a_runtime.tee.base import BaseProvider
from ca2a_runtime.tee.software import SoftwareProvider


class PeerNode:
    """A callee holding a stable enclave channel key, a policy, and a provider."""

    def __init__(
        self,
        policy: Policy,
        *,
        provider: BaseProvider | None = None,
        max_depth: int = 8,
    ) -> None:
        self.policy = policy
        self.provider: BaseProvider = provider if provider is not None else SoftwareProvider()
        self.max_depth = max_depth
        self._private_key, self.channel_public_key = generate_channel_keypair()

    def offer(self, nonce: str) -> ChannelOffer:
        """Re-attest the stable enclave channel key under a caller-supplied nonce."""
        return attest_channel(self.provider, self.channel_public_key, nonce)

    def handle(self, message: dict[str, Any]) -> PeerResult:
        """Run the full inbound pipeline for a parsed cA2A-profile A2A message."""
        from ca2a_runtime.transport import a2a

        request = a2a.parse_peer_request(message)
        return handle_peer_request(
            request,
            policy=self.policy,
            enclave_private_key=self._private_key,
            max_depth=self.max_depth,
        )
