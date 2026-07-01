"""Inbound peer-call enforcement: the decision the callee makes before it acts.

When a peer presents a delegation chain and requests a capability, the callee:

1. verifies the chain (signature, continuity, attenuation, depth, replay);
2. computes the effective scope as the leaf's delegated scope intersected with
   the callee's local policy;
3. enforces: the requested capability must be in the effective scope;
4. emits a provenance record for the accepted hop, linked to its parent.

This module is the enforcement decision core. Wiring it to a live A2A transport
(accepting the credential off an actual inbound request) is tracked separately;
attestation of the peer and sealing of the payload are Tier 2/3 and are not part
of this decision.
"""

from __future__ import annotations

from dataclasses import dataclass

from ca2a_runtime.delegation.credential import DelegationCredential, verify_chain
from ca2a_runtime.errors import ScopeNotPermitted
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import DelegationRecord, record_for


def effective_scope(
    chain: list[DelegationCredential], policy: LocalPolicy, *, max_depth: int = 8
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
    policy: LocalPolicy,
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
