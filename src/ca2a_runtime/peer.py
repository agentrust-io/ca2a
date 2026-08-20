"""Inbound peer-call enforcement: the decision the callee makes before it acts.

When a peer presents a delegation chain and requests a capability, the callee:

1. verifies the chain (signature, continuity, attenuation, depth, replay);
2. verifies holder binding: the presenter must prove, against a challenge this
   callee issued, that it controls the leaf ``subject`` key
   (see :mod:`ca2a_runtime.delegation.holder`);
3. computes the effective scope as the leaf's delegated scope intersected with
   the callee's local policy;
4. appraises what the caller is *running*, if it offered an attestation bound to
   a challenge this callee issued (see ``docs/spec/mutual-attestation.md``);
5. enforces: the requested capability must be in the effective scope;
6. emits a provenance record for the accepted hop, linked to its parent.

Steps 1 and 3 are authorization and say what the chain *allows*; step 2 is
authentication and says whether the caller is the party it was allowed for; step
4 is appraisal and says what the caller *is running*. All three are independent.
A chain establishes authority without identifying its bearer, and an appraisal
identifies a runtime without claiming anyone's authority, so neither substitutes
for the other: without step 2 a caller can attest itself honestly and exercise a
chain issued to somebody else.

Step 2 runs before any authorization step, so a caller that has proved nothing
never reaches policy evaluation and never elicits a signed denial record. Steps 2
and 4 both run before the callee opens the sealed payload -- appraising or
authenticating afterwards would mean the caller had already had its work done.

`enforce_peer_call` is the enforcement decision core. `handle_peer_request`
composes it into the full transport-agnostic inbound pipeline: verify, appraise,
enforce, open any sealed payload with the enclave key, and emit a provenance
record. A transport (an A2A server) parses its wire format into a `PeerRequest`
and calls this; cA2A does not define the transport itself, only what the peer
does with a parsed request.
"""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.attestation import ChannelOffer, Verifier, appraise_caller
from ca2a_runtime.channel import open_sealed
from ca2a_runtime.delegation.credential import DelegationCredential, verify_chain
from ca2a_runtime.delegation.holder import HolderProof, verify_holder_proof
from ca2a_runtime.errors import (
    AttestationFailed,
    ConfigError,
    HolderProofInvalid,
    ScopeNotPermitted,
    SealedChannelError,
)
from ca2a_runtime.policy import Policy
from ca2a_runtime.provenance import (
    CALLER_FAILED,
    CALLER_HARDWARE,
    CALLER_NOT_OFFERED,
    CALLER_SOFTWARE_ONLY,
    DelegationRecord,
    denial_record_for,
    record_for,
)

#: How much the callee demands of the caller's own runtime.
#:
#: ``"none"`` is the default and demands nothing: the outcome is recorded and the
#: call proceeds. It is the default during the Developer Preview because not every caller can
#: attest yet, so a callee that refused unattested callers out of the box would be
#: a callee nobody could talk to -- and a control that breaks the common case gets
#: switched off and never switched back on. Strictness is opt-in, one rung at a
#: time: ``"any"`` requires an offer that appraises (software assurance is enough),
#: ``"hardware"`` requires the assurance to be hardware-backed.
#:
#: An offer that is *present and does not appraise* is refused at every rung,
#: including ``"none"``. Demanding nothing means accepting a caller that proves
#: nothing; it does not mean accepting a broken proof, because then a
#: misconfigured attestation path would look exactly like a caller that never had
#: one.
REQUIRE_NONE = "none"
REQUIRE_ANY = "any"
REQUIRE_HARDWARE = "hardware"

REQUIREMENT_VALUES = frozenset({REQUIRE_NONE, REQUIRE_ANY, REQUIRE_HARDWARE})


def effective_scope(
    chain: list[DelegationCredential],
    policy: Policy,
    *,
    max_depth: int = 8,
    trusted_root_issuers: Collection[str] = (),
) -> frozenset[str]:
    """Verify the chain and return the effective scope (delegated ∩ local policy).

    Raises the relevant CA2AError if the chain does not verify.
    """
    verify_chain(chain, max_depth=max_depth, trusted_root_issuers=trusted_root_issuers)
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
    caller_attestation: str = CALLER_NOT_OFFERED,
    trusted_root_issuers: Collection[str] = (),
) -> PeerDecision:
    """Verify, intersect with local policy, enforce, and emit a provenance record.

    Raises ScopeNotPermitted if the requested capability is not in the effective
    scope, and the underlying CA2AError if the chain does not verify. On accept,
    returns a PeerDecision carrying the linked provenance record.

    ``caller_attestation`` is stamped onto whichever record this emits. Callers
    that appraise the peer's runtime pass the outcome they established;
    :func:`handle_peer_request` does exactly that. The default is the honest value
    for a path that appraised nothing.
    """
    effective = effective_scope(
        chain,
        policy,
        max_depth=max_depth,
        trusted_root_issuers=trusted_root_issuers,
    )
    return decide_capability(
        chain,
        requested_capability,
        effective,
        record_id=record_id,
        parent_record_hash=parent_record_hash,
        caller_attestation=caller_attestation,
    )


def decide_capability(
    chain: list[DelegationCredential],
    requested_capability: str,
    effective: frozenset[str],
    *,
    record_id: str,
    parent_record_hash: str | None = None,
    caller_attestation: str = CALLER_NOT_OFFERED,
) -> PeerDecision:
    """Enforce the capability against an already-computed effective scope.

    Split out of :func:`enforce_peer_call` so the inbound pipeline can appraise
    the caller's runtime *between* verifying the chain and deciding the call,
    without verifying the chain twice. That ordering is what lets every emitted
    record -- allow or deny -- state the appraisal outcome accurately, rather than
    a scope refusal claiming nothing was offered when something was.

    The chain must already be verified: this function emits provenance, and a
    record built from an unverified credential is a claim about authority nobody
    checked.
    """
    if requested_capability not in effective:
        reason = f"capability {requested_capability!r} is not in the effective scope"
        raise ScopeNotPermitted(
            reason,
            detail=f"effective={sorted(effective)}",
            # The refusal is evidence too: emit a linked denial record so an
            # auditor walking the DAG sees why the call stopped here, rather
            # than a gap where a hop should be.
            record=denial_record_for(
                chain[-1],
                record_id=record_id,
                parent_record_hash=parent_record_hash,
                requested_capability=requested_capability,
                effective_scope=effective,
                reason=reason,
                caller_attestation=caller_attestation,
            ),
        )
    record = record_for(
        chain[-1],
        record_id=record_id,
        parent_record_hash=parent_record_hash,
        caller_attestation=caller_attestation,
    )
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
    caller_offer: ChannelOffer | None = None
    """The caller's own attested channel key, bound to a challenge this callee
    issued. Optional: a caller that cannot attest omits it and, by default, is
    still served. Present-and-unappraisable is refused; see :data:`REQUIRE_NONE`."""
    holder_proof: HolderProof | None = None
    """The caller's proof that it controls ``chain[-1].subject``, against a
    challenge this callee issued. Required by default, unlike ``caller_offer``:
    attesting a runtime is a capability not every caller has, but holding the key
    you were delegated is not optional -- it is what being the delegate means."""


@dataclass(frozen=True)
class PeerResult:
    """The outcome of handling an accepted peer request."""

    effective_scope: frozenset[str]
    granted_capability: str
    record: DelegationRecord
    payload: bytes | None
    caller_attestation: str = CALLER_NOT_OFFERED
    """What the callee established about the caller's runtime. Also on ``record``,
    where it is part of the portable evidence rather than just this return value."""


def appraise_caller_runtime(
    request: PeerRequest,
    effective: frozenset[str],
    *,
    requirement: str = REQUIRE_NONE,
    challenge_secret: bytes | None = None,
    caller_verifier: Verifier | None = None,
) -> str:
    """Appraise the caller's offer and return the recorded outcome, or refuse.

    Returns one of the ``CALLER_*`` values. Raises :class:`AttestationFailed`,
    carrying a linked denial record, when the caller does not meet
    ``requirement`` or presents an offer that does not appraise. The chain must
    already be verified, for the same reason as :func:`decide_capability`: this
    can emit provenance.
    """
    if requirement not in REQUIREMENT_VALUES:
        raise ConfigError(
            f"require_caller_attestation must be one of {sorted(REQUIREMENT_VALUES)}, "
            f"got {requirement!r}"
        )

    def refuse(reason: str, *, outcome: str, detail: str | None = None) -> AttestationFailed:
        return AttestationFailed(
            reason,
            detail=detail,
            record=denial_record_for(
                request.chain[-1],
                record_id=request.record_id,
                parent_record_hash=request.parent_record_hash,
                requested_capability=request.requested_capability,
                effective_scope=effective,
                reason=reason,
                caller_attestation=outcome,
            ),
        )

    if request.caller_offer is None:
        if requirement == REQUIRE_NONE:
            return CALLER_NOT_OFFERED
        raise refuse(
            "the callee requires caller attestation and the caller offered none",
            outcome=CALLER_NOT_OFFERED,
            detail=f"require_caller_attestation={requirement!r}",
        )

    if challenge_secret is None:
        # The caller attested to a challenge, but this callee has no secret to
        # check it against, so it cannot have issued that challenge. Refusing is
        # the only honest answer: accepting would record an appraisal that never
        # happened, and reporting "not offered" would discard a proof that was.
        raise refuse(
            "the caller offered an attestation but this callee issues no challenges",
            outcome=CALLER_FAILED,
            detail="no challenge secret is configured, so no offer can be appraised",
        )

    try:
        peer = appraise_caller(
            request.caller_offer,
            challenge_secret=challenge_secret,
            verifier=caller_verifier,
        )
    except AttestationFailed as exc:
        raise refuse(
            f"the caller's attestation did not appraise: {exc}",
            outcome=CALLER_FAILED,
            detail=exc.detail,
        ) from exc

    outcome = CALLER_HARDWARE if peer.assurance == "hardware" else CALLER_SOFTWARE_ONLY
    if requirement == REQUIRE_HARDWARE and outcome != CALLER_HARDWARE:
        # The appraisal succeeded, so record what was actually established rather
        # than "failed"; the reason says it was the floor that refused the call.
        raise refuse(
            "the callee requires a hardware-attested caller",
            outcome=outcome,
            detail=f"the caller appraised at assurance {peer.assurance!r}",
        )
    return outcome


def verify_caller_holds_leaf(
    request: PeerRequest,
    *,
    audience: str | None,
    challenge_secret: bytes | None,
) -> None:
    """Bind the presented chain to the caller, or raise :class:`HolderProofInvalid`.

    The chain must already be verified, so ``chain[-1].subject`` is a key someone
    was genuinely delegated rather than one the caller asserted.

    Unlike :func:`appraise_caller_runtime` this emits no provenance record. A
    caller that has not shown it holds the credential has not earned a signed
    statement about the credential, and a denial record naming a subject the
    caller may have no relationship to would attribute a refusal to the wrong
    party. It also keeps an unauthenticated caller from mining denial records for
    what the callee permits.
    """
    if request.holder_proof is None:
        raise HolderProofInvalid(
            "no holder proof was presented with the delegation chain",
            detail="a chain alone does not establish that the caller is its subject",
        )
    if audience is None or challenge_secret is None:
        # Requiring the proof while having nothing to check it against would
        # verify a signature over an audience and challenge the callee never
        # chose, which is indistinguishable from not checking at all.
        raise HolderProofInvalid(
            "holder proof required but this callee has no challenge context",
            detail="the callee must name itself as the audience and hold the "
            "secret behind the challenge it issued",
        )
    verify_holder_proof(
        request.holder_proof,
        request.chain[-1],
        audience=audience,
        challenge_secret=challenge_secret,
        requested_capability=request.requested_capability,
        record_id=request.record_id,
        sealed_payload=request.sealed_payload,
        # Committed either way. A caller that attested cannot strip its offer and
        # reuse the proof, and one that did not cannot bolt an offer on.
        caller_channel_key=(
            None if request.caller_offer is None else request.caller_offer.channel_public_key
        ),
        parent_record_hash=request.parent_record_hash,
    )


def handle_peer_request(
    request: PeerRequest,
    *,
    policy: Policy,
    enclave_private_key: X25519PrivateKey | None = None,
    max_depth: int = 8,
    challenge_secret: bytes | None = None,
    require_caller_attestation: str = REQUIRE_NONE,
    caller_verifier: Verifier | None = None,
    audience: str | None = None,
    require_holder_proof: bool = True,
    trusted_root_issuers: Collection[str] = (),
) -> PeerResult:
    """Run the full inbound pipeline for a parsed peer request.

    Verifies the delegation chain, intersects the delegated scope with the local
    policy, appraises what the caller is running, enforces the requested
    capability, opens any sealed payload with the enclave-bound key, and emits a
    linked provenance record. Fails closed: any verification, appraisal, or
    authorization failure raises the relevant CA2AError and no payload is
    returned.

    **The step order is the security property, not an implementation detail.**
    The payload is sealed to this callee's channel key, so the callee *could* read
    it the instant it arrives; appraisal therefore has to happen before
    :func:`~ca2a_runtime.channel.open_sealed`, not merely before the response is
    written. Appraising afterwards would mean an unattested caller had already had
    its work done, and every guarantee this function offers would be a report on
    something that already happened. ``tests/unit/test_mutual_attestation.py``
    asserts the payload is never opened when appraisal refuses, so swapping these
    two calls fails the suite.

    ``audience`` is this callee's channel key, the identity a holder proof commits
    to. With ``require_holder_proof`` set, it and ``challenge_secret`` are both
    required, and their absence is a failure rather than a reason to skip the
    check. ``require_holder_proof=False`` reproduces the pre-holder-binding
    behaviour, in which any party holding a copy of the chain is granted the
    leaf's authority; it exists for offline replay of recorded evidence, where
    there is no live caller to challenge, and must not be used on a live peer
    path.
    """
    # The chain, trust set included, is verified exactly once: here, before the
    # caller is challenged, so an untrusted or malformed chain is refused before
    # a proof is demanded about a credential this peer was never going to honour.
    # The scope intersection below reads the leaf of this verified chain, so it
    # does not verify it again.
    verify_chain(
        request.chain,
        max_depth=max_depth,
        trusted_root_issuers=trusted_root_issuers,
    )
    if require_holder_proof:
        # Before the scope intersection, so an unauthenticated caller never
        # reaches authorization and never elicits a denial record.
        verify_caller_holds_leaf(
            request,
            audience=audience,
            challenge_secret=challenge_secret,
        )

    effective = policy.intersect(request.chain[-1].scope)

    caller_attestation = appraise_caller_runtime(
        request,
        effective,
        requirement=require_caller_attestation,
        challenge_secret=challenge_secret,
        caller_verifier=caller_verifier,
    )

    decision = decide_capability(
        request.chain,
        request.requested_capability,
        effective,
        record_id=request.record_id,
        parent_record_hash=request.parent_record_hash,
        caller_attestation=caller_attestation,
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
        caller_attestation=caller_attestation,
    )
