"""Inbound peer-call enforcement: the decision the callee makes before it acts.

When a peer presents a delegation chain and requests a capability, the callee:

1. verifies the chain (signature, continuity, attenuation, depth, replay);
2. computes the effective scope as the leaf's delegated scope intersected with
   the callee's local policy;
3. enforces: the requested capability must be in the effective scope;
4. emits a provenance record for the accepted hop, linked to its parent.

`enforce_peer_call` is the enforcement decision core. `handle_peer_request`
composes it into the full transport-agnostic inbound pipeline: verify, enforce,
open any sealed payload with the enclave key, and emit a provenance record. A
transport (an A2A server) parses its wire format into a `PeerRequest` and calls
this; cA2A does not define the transport itself, only what the peer does with a
parsed request.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.channel import open_sealed
from ca2a_runtime.delegation.credential import DelegationCredential, verify_chain
from ca2a_runtime.errors import ScopeNotPermitted, SealedChannelError
from ca2a_runtime.policy import Policy
from ca2a_runtime.provenance import DelegationRecord, record_for


def effective_scope(
    chain: list[DelegationCredential], policy: Policy, *, max_depth: int = 8
) -> frozenset[str]:
    """Verify the chain and return the effective scope (delegated ∩ local policy).

    Raises the relevant CA2AError if the chain does not verify.
    """
    verify_chain(chain, max_depth=max_depth)
    return policy.intersect(chain[-1].scope)


@dataclass(frozen=True)
class PeerDecision:
    """The result of an accepted peer call."""

    effective_scope: frozenset[str]
    granted_capability: str
    record: DelegationRecord


def enforce_peer_call(
    chain: list[DelegationCredential],
    requested_capability: str,
    *,
    policy: Policy,
    record_id: str,
    parent_record_hash: str | None = None,
    max_depth: int = 8,
) -> PeerDecision:
    """Verify, intersect with local policy, enforce, and emit a provenance record.

    Raises ScopeNotPermitted if the requested capability is not in the effective
    scope, and the underlying CA2AError if the chain does not verify. On accept,
    returns a PeerDecision carrying the linked provenance record.
    """
    effective = effective_scope(chain, policy, max_depth=max_depth)
    if requested_capability not in effective:
        raise ScopeNotPermitted(
            f"capability {requested_capability!r} is not in the effective scope",
            detail=f"effective={sorted(effective)}",
        )
    record = record_for(chain[-1], record_id=record_id, parent_record_hash=parent_record_hash)
    return PeerDecision(
        effective_scope=effective,
        granted_capability=requested_capability,
        record=record,
    )


@dataclass(frozen=True)
class PeerRequest:
    """A transport-agnostic inbound peer request.

    A transport (an A2A server) parses its wire format into this shape and hands
    it to ``handle_peer_request``. cA2A does not define the transport; it defines
    what a peer does with the request once parsed.
    """

    chain: list[DelegationCredential]
    requested_capability: str
    record_id: str
    sealed_payload: bytes | None = None
    parent_record_hash: str | None = None


@dataclass(frozen=True)
class PeerResult:
    """The outcome of handling an accepted peer request."""

    effective_scope: frozenset[str]
    granted_capability: str
    record: DelegationRecord
    payload: bytes | None


def handle_peer_request(
    request: PeerRequest,
    *,
    policy: Policy,
    enclave_private_key: X25519PrivateKey | None = None,
    max_depth: int = 8,
) -> PeerResult:
    """Run the full inbound pipeline for a parsed peer request.

    Verifies the delegation chain, intersects the delegated scope with the local
    policy and enforces the requested capability, opens any sealed payload with
    the enclave-bound key, and emits a linked provenance record. Fails closed:
    any verification or authorization failure raises the relevant CA2AError and
    no payload is returned.
    """
    decision = enforce_peer_call(
        request.chain,
        request.requested_capability,
        policy=policy,
        record_id=request.record_id,
        parent_record_hash=request.parent_record_hash,
        max_depth=max_depth,
    )

    payload: bytes | None = None
    if request.sealed_payload is not None:
        if enclave_private_key is None:
            raise SealedChannelError("a sealed payload was sent but no enclave key is available")
        payload = open_sealed(request.sealed_payload, enclave_private_key)

    return PeerResult(
        effective_scope=decision.effective_scope,
        granted_capability=decision.granted_capability,
        record=decision.record,
        payload=payload,
    )
