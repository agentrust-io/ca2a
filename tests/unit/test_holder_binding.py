"""Holder binding: a delegation chain must not be usable by whoever holds a copy.

The regression pinned here: before holder binding, the inbound path granted the
leaf's authority to any caller that presented a well-formed chain. Chains are
published for offline audit, embedded in provenance DAGs, and shipped as
fixtures, so obtaining one is not an exotic capability.

Caller attestation does not cover this, and the tests under "the join" are the
ones that say why. An appraised ``caller_offer`` establishes what the caller is
*running*; it makes no claim about the Ed25519 delegation subject. A caller can
attest itself honestly and still be refused, which is the property that matters:
"I am a measured enclave" is not "I am the delegate".
"""

from __future__ import annotations

import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ca2a_runtime import challenge as challenge_mod
from ca2a_runtime.attestation import ChannelOffer
from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.channel import SealedChannel, generate_channel_keypair
from ca2a_runtime.delegation import DelegationCredential, build_holder_proof
from ca2a_runtime.delegation.holder import HolderProof, ProofReplayCache, proof_body
from ca2a_runtime.errors import HolderProofInvalid
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import REQUIRE_ANY, PeerRequest, handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.tee.base import AttestationReport
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.transport import a2a_adapter, client, server
from tests.unit.conftest import (
    TEST_AUDIENCE,
    TEST_SECRET,
    build_chain_with_keys,
    proved_request,
)

POLICY = LocalPolicy.of(["read", "write"])


def _chain():
    return build_chain_with_keys([frozenset({"read", "write"})])


def _handle(req, **kwargs):
    return handle_peer_request(
        req, policy=POLICY, audience=TEST_AUDIENCE, challenge_secret=TEST_SECRET, **kwargs
    )


def _offer(challenge: str, *, platform: str = "software-only") -> ChannelOffer:
    """A caller's own attested channel key, bound to ``challenge``."""
    key = SoftwareProvider().attest("x", "y").public_key
    return ChannelOffer(
        channel_public_key=key,
        report=AttestationReport(
            platform=platform, measurement="caller-measurement", public_key=key, nonce=challenge
        ),
    )


# --------------------------------------------------------------------------
# The attack
# --------------------------------------------------------------------------


def test_replayed_chain_without_proof_is_refused() -> None:
    """The original exploit: present a captured chain, get the leaf's authority."""
    chain, _keys = _chain()
    captured = [
        DelegationCredential.from_dict({**c.body(), "signature": c.signature}) for c in chain
    ]
    req = PeerRequest(chain=captured, requested_capability="write", record_id="r0")
    with pytest.raises(HolderProofInvalid) as exc:
        _handle(req)
    assert exc.value.code == "HOLDER_PROOF_INVALID"
    assert exc.value.http_status == 401


def test_attacker_cannot_forge_a_proof_with_their_own_key() -> None:
    chain, _keys = _chain()
    mallory = Ed25519PrivateKey.generate()
    challenge = challenge_mod.issue_challenge(TEST_SECRET)
    body = proof_body(
        audience=TEST_AUDIENCE,
        challenge=challenge,
        credential_id=chain[-1].credential_id,
        subject=chain[-1].subject,
        requested_capability="write",
        record_id="r0",
        sealed_payload=None,
        caller_channel_key=None,
    )
    forged = HolderProof(challenge=challenge, signature=mallory.sign(canonicalize(body)).hex())
    req = PeerRequest(
        chain=chain, requested_capability="write", record_id="r0", holder_proof=forged
    )
    with pytest.raises(HolderProofInvalid, match="failed to verify against the leaf subject") as e:
        _handle(req)
    assert e.value.detail == "the presenter does not hold the delegated key"


def test_legitimate_holder_is_granted() -> None:
    chain, keys = _chain()
    result = _handle(proved_request(chain, keys[-1], "write", "r0", secret=TEST_SECRET))
    assert result.granted_capability == "write"


# --------------------------------------------------------------------------
# The join: attestation and holder binding are not substitutes
# --------------------------------------------------------------------------


def test_an_attested_caller_still_cannot_use_someone_elses_chain() -> None:
    """The point of the whole change.

    Mallory attests herself perfectly: a real offer, bound to a challenge this
    callee issued, appraising at software assurance. She then presents a chain
    issued to Bob. Attestation says what she is running and nothing about whose
    authority she holds, so the call must still be refused.
    """
    chain, _bobs_keys = _chain()
    offer = _offer(challenge_mod.issue_challenge(TEST_SECRET))
    req = PeerRequest(
        chain=chain,
        requested_capability="write",
        record_id="r0",
        caller_offer=offer,
    )
    with pytest.raises(HolderProofInvalid):
        _handle(req, require_caller_attestation=REQUIRE_ANY)


def test_a_proof_made_while_attesting_cannot_be_reused_without_the_offer() -> None:
    """The offer's channel key is committed, so it cannot be stripped."""
    chain, keys = _chain()
    challenge = challenge_mod.issue_challenge(TEST_SECRET)
    offer = _offer(challenge)
    with_offer = proved_request(
        chain, keys[-1], "write", "r0", caller_offer=offer, challenge=challenge
    )
    stripped = PeerRequest(
        chain=chain,
        requested_capability="write",
        record_id="r0",
        holder_proof=with_offer.holder_proof,
    )
    with pytest.raises(HolderProofInvalid):
        _handle(stripped)


def test_a_proof_made_without_an_offer_cannot_have_one_bolted_on() -> None:
    """The mirror: committing to ``None`` is a commitment too."""
    chain, keys = _chain()
    challenge = challenge_mod.issue_challenge(TEST_SECRET)
    without = proved_request(chain, keys[-1], "write", "r0", challenge=challenge)
    bolted = PeerRequest(
        chain=chain,
        requested_capability="write",
        record_id="r0",
        caller_offer=_offer(challenge),
        holder_proof=without.holder_proof,
    )
    with pytest.raises(HolderProofInvalid):
        _handle(bolted)


def test_holder_binding_and_attestation_compose() -> None:
    """Both present and both valid: the delegate calling from an attested runtime."""
    chain, keys = _chain()
    challenge = challenge_mod.issue_challenge(TEST_SECRET)
    offer = _offer(challenge)
    req = proved_request(chain, keys[-1], "write", "r0", caller_offer=offer, challenge=challenge)
    result = _handle(req, require_caller_attestation=REQUIRE_ANY)
    assert result.granted_capability == "write"
    assert result.caller_attestation == "software-only"


# --------------------------------------------------------------------------
# Scope of a proof
# --------------------------------------------------------------------------


def test_proof_for_another_challenge_is_refused() -> None:
    """A challenge from a secret this callee never held does not verify."""
    chain, keys = _chain()
    other = challenge_mod.generate_secret()
    req = proved_request(chain, keys[-1], "write", "r0", secret=other)
    with pytest.raises(HolderProofInvalid, match="not usable"):
        _handle(req)


def test_expired_challenge_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The replay bound. A captured proof stops working when its challenge does.

    Rather than sleeping: the challenge encodes its own expiry, so moving the
    clock forward is the same code path a real timeout takes.
    """
    chain, keys = _chain()
    stale = challenge_mod.issue_challenge(TEST_SECRET, ttl_seconds=1)
    req = proved_request(chain, keys[-1], "write", "r0", challenge=stale)

    real_time = time.time
    monkeypatch.setattr(challenge_mod.time, "time", lambda: real_time() + 5)
    with pytest.raises(HolderProofInvalid, match="not usable"):
        _handle(req)


def test_proof_for_another_audience_is_refused() -> None:
    """A proof made for one peer cannot be presented to another."""
    chain, keys = _chain()
    req = proved_request(chain, keys[-1], "write", "r0", audience="a-different-peer")
    with pytest.raises(HolderProofInvalid):
        _handle(req)


def test_proof_does_not_transfer_across_capability_or_record() -> None:
    chain, keys = _chain()
    proof = proved_request(chain, keys[-1], "read", "r0").holder_proof

    with pytest.raises(HolderProofInvalid):
        _handle(
            PeerRequest(
                chain=chain, requested_capability="write", record_id="r0", holder_proof=proof
            )
        )
    with pytest.raises(HolderProofInvalid):
        _handle(
            PeerRequest(
                chain=chain, requested_capability="read", record_id="other", holder_proof=proof
            )
        )


def test_proof_pins_the_sealed_payload() -> None:
    """The ciphertext cannot be swapped under an otherwise valid proof."""
    chain, keys = _chain()
    priv, pub = generate_channel_keypair()
    req = proved_request(
        chain, keys[-1], "write", "r0", sealed_payload=SealedChannel(pub).seal(b"agreed task")
    )
    swapped = PeerRequest(
        chain=chain,
        requested_capability="write",
        record_id="r0",
        sealed_payload=SealedChannel(pub).seal(b"a different task"),
        holder_proof=req.holder_proof,
    )
    with pytest.raises(HolderProofInvalid):
        _handle(swapped, enclave_private_key=priv)


def test_proof_must_be_signed_by_the_leaf_not_an_ancestor() -> None:
    """Authority narrows down the chain; an ancestor key must not stand in."""
    chain, keys = build_chain_with_keys([frozenset({"read", "write"}), frozenset({"read"})])
    with pytest.raises(HolderProofInvalid, match="does not match the leaf"):
        build_holder_proof(
            keys[0],
            chain[-1],
            audience=TEST_AUDIENCE,
            challenge=challenge_mod.issue_challenge(TEST_SECRET),
            requested_capability="read",
            record_id="r0",
        )


# --------------------------------------------------------------------------
# Single use: a proof is honoured once, not once per window
# --------------------------------------------------------------------------


def test_a_proof_is_honoured_once() -> None:
    """The whole request, valid proof included, cannot be replayed."""
    chain, keys = _chain()
    seen = ProofReplayCache()
    req = proved_request(chain, keys[-1], "write", "r0")

    assert _handle(req, seen_proofs=seen).granted_capability == "write"
    with pytest.raises(HolderProofInvalid, match="already been used"):
        _handle(req, seen_proofs=seen)


def test_without_a_cache_the_guarantee_is_only_the_window() -> None:
    """Stated as a test so the weaker mode is a choice rather than a surprise."""
    chain, keys = _chain()
    req = proved_request(chain, keys[-1], "write", "r0")
    assert _handle(req).granted_capability == "write"
    assert _handle(req).granted_capability == "write"  # replayed, and accepted


def test_the_cache_only_remembers_proofs_that_verified() -> None:
    """Recording before verifying would let anyone poison it.

    An attacker who could insert a signature they had not proved would be able to
    lock the real delegate out of its own proof, so nothing enters the cache until
    it has verified under the leaf subject.
    """
    chain, keys = _chain()
    seen = ProofReplayCache()
    challenge = challenge_mod.issue_challenge(TEST_SECRET)
    good = proved_request(chain, keys[-1], "write", "r0", challenge=challenge)

    # Mallory presents the same signature under a mismatched capability, so the
    # signature check fails. Nothing should be remembered.
    with pytest.raises(HolderProofInvalid):
        _handle(
            PeerRequest(
                chain=chain,
                requested_capability="read",
                record_id="r0",
                holder_proof=good.holder_proof,
            ),
            seen_proofs=seen,
        )
    assert len(seen) == 0

    # Bob's own call still works: his proof was never recorded by the failure.
    assert _handle(good, seen_proofs=seen).granted_capability == "write"


def test_cache_entries_expire_with_their_challenge(monkeypatch: pytest.MonkeyPatch) -> None:
    seen = ProofReplayCache(ttl_seconds=1)
    assert seen.record("sig") is True
    assert seen.record("sig") is False
    real = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real() + 5)
    assert seen.record("sig") is True  # forgotten, because its challenge is dead too


def test_cache_is_bounded_and_says_what_that_costs() -> None:
    """Past capacity the oldest goes, so a flood degrades to the window."""
    seen = ProofReplayCache(max_entries=4)
    for i in range(20):
        assert seen.record(f"sig-{i}") is True
    assert len(seen) <= 4
    assert seen.record("sig-0") is True  # evicted, so replayable again
    assert seen.record("sig-19") is False  # still remembered


def test_a_node_remembers_proofs_by_default() -> None:
    """The default posture, over the transport, not just the handler."""
    node = PeerNode(POLICY)
    assert node.seen_proofs is not None
    chain, keys = _chain()
    message = a2a_adapter.attach_ca2a_metadata(
        {},
        PeerRequest(
            chain=chain,
            requested_capability="write",
            record_id="r0",
            holder_proof=build_holder_proof(
                keys[-1],
                chain[-1],
                audience=node.channel_public_key,
                challenge=node.issue_challenge(),
                requested_capability="write",
                record_id="r0",
            ),
        ),
    )
    assert node.handle(message).granted_capability == "write"
    with pytest.raises(HolderProofInvalid, match="already been used"):
        node.handle(message)


def test_a_node_can_opt_out_of_remembering() -> None:
    """For a multi-instance deployment that shares no state."""
    node = PeerNode(POLICY, seen_proofs=None)
    assert node.seen_proofs is None


# --------------------------------------------------------------------------
# Fail-closed wiring
# --------------------------------------------------------------------------


def test_missing_challenge_context_fails_closed() -> None:
    """Requiring a proof but holding nothing to check it against is a failure."""
    chain, keys = _chain()
    req = proved_request(chain, keys[-1], "write", "r0")
    with pytest.raises(HolderProofInvalid, match="no challenge context"):
        handle_peer_request(req, policy=POLICY)


@pytest.mark.parametrize(
    "bad", [{"challenge": "c"}, {"signature": "ab"}, {"challenge": "", "signature": "ab"}, "str", 7]
)
def test_malformed_proof_is_rejected(bad: object) -> None:
    with pytest.raises(HolderProofInvalid):
        HolderProof.from_dict(bad)


def test_unauthenticated_caller_never_reaches_policy_evaluation() -> None:
    """A caller that proved nothing must not get back a signed denial record."""
    chain, _keys = _chain()
    req = PeerRequest(chain=chain, requested_capability="admin", record_id="r0")
    with pytest.raises(HolderProofInvalid) as exc:
        _handle(req)
    # ScopeNotPermitted and AttestationFailed both carry a record; this must not.
    assert getattr(exc.value, "record", None) is None


def test_escape_hatch_reproduces_the_old_behaviour_explicitly() -> None:
    chain, _keys = _chain()
    req = PeerRequest(chain=chain, requested_capability="write", record_id="r0")
    result = handle_peer_request(req, policy=POLICY, require_holder_proof=False)
    assert result.granted_capability == "write"


def test_holder_proof_round_trips_through_a2a_metadata() -> None:
    chain, keys = _chain()
    req = proved_request(chain, keys[-1], "write", "r0")
    parsed = a2a_adapter.parse_peer_request(a2a_adapter.attach_ca2a_metadata({}, req))
    assert parsed is not None
    assert parsed.holder_proof == req.holder_proof


def test_a_malformed_holder_proof_on_the_wire_fails_closed() -> None:
    chain, keys = _chain()
    message = a2a_adapter.attach_ca2a_metadata({}, proved_request(chain, keys[-1], "write", "r0"))
    from ca2a_runtime.transport.constants import KEY_HOLDER_PROOF

    message["metadata"][KEY_HOLDER_PROOF] = {"challenge": "c"}  # no signature
    with pytest.raises(HolderProofInvalid):
        a2a_adapter.parse_peer_request(message)


# --------------------------------------------------------------------------
# Over the wire
# --------------------------------------------------------------------------


def test_replay_over_http_is_refused() -> None:
    """Bob calls legitimately; every route Mallory has is refused."""
    node = PeerNode(POLICY)
    srv = server.serve(node, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        chain, keys = _chain()

        # Bob, who holds the leaf key, gets through.
        ok = client.send_task(base, chain, "write", "r0", holder_key=keys[-1])
        assert ok["accepted"] is True

        # (a) the bare captured chain
        status, body = client._post_json(
            f"{base}{server.TASK_PATH}",
            a2a_adapter.attach_ca2a_metadata(
                {}, PeerRequest(chain=chain, requested_capability="write", record_id="m1")
            ),
        )
        assert status == 401
        assert body["error"]["code"] == "HOLDER_PROOF_INVALID"

        # (b) a proof forged with Mallory's own key against a fresh challenge
        mallory = Ed25519PrivateKey.generate()
        hello = client.handshake(base)
        assert hello.challenge is not None
        body_bytes = proof_body(
            audience=hello.peer.public_key,
            challenge=hello.challenge,
            credential_id=chain[-1].credential_id,
            subject=chain[-1].subject,
            requested_capability="write",
            record_id="m2",
            sealed_payload=None,
            caller_channel_key=None,
        )
        status, body = client._post_json(
            f"{base}{server.TASK_PATH}",
            a2a_adapter.attach_ca2a_metadata(
                {},
                PeerRequest(
                    chain=chain,
                    requested_capability="write",
                    record_id="m2",
                    holder_proof=HolderProof(
                        challenge=hello.challenge,
                        signature=mallory.sign(canonicalize(body_bytes)).hex(),
                    ),
                ),
            ),
        )
        assert status == 401
        assert body["error"]["code"] == "HOLDER_PROOF_INVALID"
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_node_can_opt_out_for_offline_replay() -> None:
    node = PeerNode(POLICY, require_holder_proof=False)
    message = a2a_adapter.attach_ca2a_metadata(
        {}, PeerRequest(chain=_chain()[0], requested_capability="write", record_id="r0")
    )
    assert node.handle(message).granted_capability == "write"
