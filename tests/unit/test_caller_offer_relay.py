"""Caller-offer relay: an attestation is not the presenter's until it proves the key.

The regression pinned here. Before ``ca2a-caller-offer-v2``, a callee appraised a
caller's offer (channel key plus a report bound to the callee's challenge) but
never asked the caller to prove it held that channel key. The handshake endpoint
attests the node's own key under any nonce anybody sends, and callee and caller
offers shared one binding. So a delegate with no enclave could take challenge C
from target T, ask an honest hardware peer V to attest under C through V's public
``/channel`` endpoint, present V's offer as its own, and be recorded by T as
``caller_attestation="hardware"``.

Two independent fixes, each tested on its own:

- role separation: the handshake endpoint only mints callee-role offers, and a
  callee only accepts caller-role offers, with the role inside the signed binding;
- proof of possession: the caller MACs the request transcript under a key derived
  from X25519 between its attested channel key and the callee's, so an offer that
  is genuinely caller-role but belongs to somebody else still does not appraise.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import threading

import pytest

from ca2a_runtime import attestation as attestation_mod
from ca2a_runtime.attestation import (
    CALLER_OFFER_VERSION,
    CallerPossession,
    ChannelOffer,
    attest_channel,
    caller_possession_transcript,
    offer_channel,
    verify_offer,
)
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.delegation.holder import build_holder_proof
from ca2a_runtime.errors import AttestationFailed, CA2AError, TransportError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import REQUIRE_HARDWARE, PeerRequest
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import (
    CALLER_FAILED,
    CALLER_HARDWARE,
    CALLER_NOT_OFFERED,
    CALLER_SOFTWARE_ONLY,
)
from ca2a_runtime.tee.base import AttestationReport, BaseProvider
from ca2a_runtime.tee.binding import ROLE_CALLEE, ROLE_CALLER
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.tee.tpm import tpm_qualifying_data
from ca2a_runtime.transport import a2a_adapter, client, server, wire
from ca2a_runtime.transport.constants import KEY_CALLER_OFFER, KEY_CALLER_POSSESSION
from tests.unit.conftest import with_possession

#: Stands in for a TPM signing chain. The verifier below checks the signature and
#: recomputes the key/nonce/role binding exactly as ``ca2a_verify.tpm`` does.
_HW_ROOT = b"simulated-hardware-root"


class FakeHardware(BaseProvider):
    """A hardware-shaped provider whose quote signs the role-separated binding."""

    platform = "tpm"

    @classmethod
    def detect(cls) -> bool:
        return True

    def attest(self, public_key: str, nonce: str, *, role: str = ROLE_CALLEE) -> AttestationReport:
        binding = tpm_qualifying_data(public_key, nonce, role=role)
        return AttestationReport(
            platform="tpm",
            measurement="sha256:golden",
            public_key=public_key,
            nonce=nonce,
            raw_evidence=binding,
            quote_signature=hmac.new(_HW_ROOT, binding, hashlib.sha256).digest(),
            role=role,
        )


def verifier(report: AttestationReport, nonce: str) -> str:
    """A correct verifier: the signature, and the binding under the report's role."""
    binding = tpm_qualifying_data(report.public_key, nonce, role=report.role)
    expected_sig = hmac.new(_HW_ROOT, binding, hashlib.sha256).digest()
    if report.raw_evidence != binding or not hmac.compare_digest(
        report.quote_signature or b"", expected_sig
    ):
        raise AttestationFailed("quote does not verify")
    return report.measurement


def role_blind_verifier(report: AttestationReport, nonce: str) -> str:
    """A verifier written before roles existed: it always recomputes the callee binding.

    Role separation cannot help against this one, so these tests show proof of
    possession refusing the relay on its own.
    """
    binding = tpm_qualifying_data(report.public_key, nonce)
    expected_sig = hmac.new(_HW_ROOT, binding, hashlib.sha256).digest()
    if report.raw_evidence != binding or not hmac.compare_digest(
        report.quote_signature or b"", expected_sig
    ):
        raise AttestationFailed("quote does not verify")
    return report.measurement


def _setup(caller_verifier=verifier):
    """Target T (demands a hardware caller), honest hardware peer V, attacker chain."""
    root_priv, root_pub = new_keypair()
    attacker_priv, attacker_pub = new_keypair()
    chain = [
        DelegationCredential("c0", root_pub, attacker_pub, frozenset({"read"}), 0).sign(root_priv)
    ]
    target = PeerNode(
        LocalPolicy.of(["read"]),
        require_caller_attestation=REQUIRE_HARDWARE,
        caller_verifier=caller_verifier,
        trusted_root_issuers=[root_pub],
    )
    honest = PeerNode(LocalPolicy.of(["read"]), provider=FakeHardware())
    return target, honest, chain, attacker_priv


def _present(target, chain, holder_key, offer, challenge, *, possession=None, record_id="r1"):
    proof = build_holder_proof(
        holder_key,
        chain[-1],
        audience=target.channel_public_key,
        challenge=challenge,
        requested_capability="read",
        record_id=record_id,
        caller_channel_key=offer.channel_public_key,
    )
    request = PeerRequest(
        chain=chain,
        requested_capability="read",
        record_id=record_id,
        caller_offer=offer,
        holder_proof=proof,
        caller_possession=possession,
    )
    return request, a2a_adapter.attach_ca2a_metadata({}, request)


def _forge_possession(request: PeerRequest, callee_channel_key: str) -> PeerRequest:
    """The attacker's best effort at a proof for an offer whose key it does not hold.

    It computes the MAC exactly as an honest caller would, over the transcript
    naming the relayed offer's key, but keyed with a channel private key it does
    hold, since it has no other.
    """
    offer = request.caller_offer
    assert offer is not None and request.holder_proof is not None
    own_key, _ = offer_channel(SoftwareProvider(), nonce="unused", role=ROLE_CALLER)
    transcript = caller_possession_transcript(
        challenge=offer.report.nonce,
        callee_channel_key=callee_channel_key,
        caller_channel_key=offer.channel_public_key,
        credential_id=request.chain[-1].credential_id,
        subject=request.chain[-1].subject,
        requested_capability=request.requested_capability,
        record_id=request.record_id,
        sealed_payload=request.sealed_payload,
        parent_record_hash=request.parent_record_hash,
        holder_proof_signature=request.holder_proof.signature,
    )
    mac = attestation_mod._possession_mac(
        own_key,
        callee_channel_key,
        caller_channel_key=offer.channel_public_key,
        callee_channel_key=callee_channel_key,
        transcript=transcript,
    )
    return dataclasses.replace(
        request, caller_possession=CallerPossession(CALLER_OFFER_VERSION, mac)
    )


# --------------------------------------------------------------------------
# (a) The relay from the probe
# --------------------------------------------------------------------------


def test_relayed_handshake_offer_is_refused_as_a_callee_role_offer() -> None:
    """The probe, verbatim: V's /channel offer under T's challenge, presented to T."""
    target, honest, chain, attacker = _setup()
    challenge = target.issue_challenge()
    borrowed = honest.offer(challenge)  # GET V/.well-known/ca2a/channel?nonce=<C>
    assert borrowed.report.role == ROLE_CALLEE
    _, message = _present(target, chain, attacker, borrowed, challenge)
    with pytest.raises(AttestationFailed, match="'callee' role") as exc_info:
        target.handle(message)
    assert exc_info.value.record.caller_attestation == CALLER_FAILED


def test_relayed_offer_relabelled_as_caller_role_fails_the_signed_binding() -> None:
    """Editing the role on the wire does not help: the role is inside the quote."""
    target, honest, chain, attacker = _setup()
    challenge = target.issue_challenge()
    borrowed = honest.offer(challenge)
    relabelled = ChannelOffer(
        channel_public_key=borrowed.channel_public_key,
        report=dataclasses.replace(borrowed.report, role=ROLE_CALLER),
    )
    _, message = _present(target, chain, attacker, relabelled, challenge)
    with pytest.raises(AttestationFailed, match="did not appraise"):
        target.handle(message)


def test_relabelled_offer_is_still_refused_by_possession_under_a_role_blind_verifier() -> None:
    """Defence in depth: a verifier that ignores the role still cannot be relayed past."""
    target, honest, chain, attacker = _setup(caller_verifier=role_blind_verifier)
    challenge = target.issue_challenge()
    borrowed = honest.offer(challenge)
    relabelled = ChannelOffer(
        channel_public_key=borrowed.channel_public_key,
        report=dataclasses.replace(borrowed.report, role=ROLE_CALLER),
    )
    request, _ = _present(target, chain, attacker, relabelled, challenge)
    # The attacker's best effort: a MAC under a channel key it does hold.
    forged = _forge_possession(request, target.channel_public_key)
    with pytest.raises(AttestationFailed, match="proof of possession did not verify"):
        target.handle(a2a_adapter.attach_ca2a_metadata({}, forged))


def test_a_genuine_caller_role_offer_minted_by_someone_else_fails_possession() -> None:
    """Suppose V minted a real caller-role offer under C for its own call to T.

    Role separation is satisfied, the quote verifies, and the offer is exactly
    what an honest caller would send. The attacker still lacks V's channel private
    key, so it cannot produce the proof of possession, and T refuses.
    """
    target, _honest, chain, attacker = _setup()
    challenge = target.issue_challenge()
    _v_private, v_offer = offer_channel(FakeHardware(), nonce=challenge, role=ROLE_CALLER)

    # No proof at all.
    _, message = _present(target, chain, attacker, v_offer, challenge)
    with pytest.raises(AttestationFailed, match="no proof of possession"):
        target.handle(message)

    # A proof keyed from a channel key the attacker does hold.
    request, _ = _present(target, chain, attacker, v_offer, challenge)
    forged = _forge_possession(request, target.channel_public_key)
    with pytest.raises(AttestationFailed, match="proof of possession did not verify") as exc_info:
        target.handle(a2a_adapter.attach_ca2a_metadata({}, forged))
    assert exc_info.value.record.caller_attestation == CALLER_FAILED


def test_the_handshake_endpoint_only_ever_serves_callee_role_offers() -> None:
    """Over real HTTP: whatever nonce is sent, the served offer is callee-role."""
    node = PeerNode(LocalPolicy.of(["read"]), provider=FakeHardware())
    srv = server.serve(node, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        body = client._get_json(f"{base}{server.CHANNEL_PATH}?nonce={node.issue_challenge()}")
        assert "role" not in body["attestation"]
        assert wire.parse_channel_offer(body).report.role == ROLE_CALLEE
    finally:
        srv.shutdown()
        srv.server_close()


def test_a_caller_does_not_accept_a_caller_role_offer_from_a_callee() -> None:
    """The mirror: the two roles are separated in both directions."""
    _priv, offer = offer_channel(SoftwareProvider(), nonce="n", role=ROLE_CALLER)
    with pytest.raises(AttestationFailed, match="'caller' role"):
        verify_offer(offer, expected_nonce="n")


# --------------------------------------------------------------------------
# (b) Passive replay of a genuine offer and proof
# --------------------------------------------------------------------------


def _genuine_call(target, chain, holder_key, *, record_id="r1"):
    challenge = target.issue_challenge()
    caller_private, offer = offer_channel(FakeHardware(), nonce=challenge, role=ROLE_CALLER)
    request, _ = _present(target, chain, holder_key, offer, challenge, record_id=record_id)
    return with_possession(request, caller_private, target.channel_public_key), challenge


def test_replayed_offer_and_proof_on_another_record_is_refused() -> None:
    target, _honest, chain, delegate = _setup()
    genuine, challenge = _genuine_call(target, chain, delegate, record_id="r1")
    assert target.handle(a2a_adapter.attach_ca2a_metadata({}, genuine)).caller_attestation == (
        CALLER_HARDWARE
    )

    # Same offer, same proof of possession, a fresh valid holder proof for r2.
    replay, _ = _present(target, chain, delegate, genuine.caller_offer, challenge, record_id="r2")
    replay = dataclasses.replace(replay, caller_possession=genuine.caller_possession)
    with pytest.raises(AttestationFailed, match="proof of possession did not verify"):
        target.handle(a2a_adapter.attach_ca2a_metadata({}, replay))


def test_replayed_offer_and_proof_to_another_callee_is_refused() -> None:
    """The MAC key is shared with one callee's channel key, so it does not transfer."""
    target, _honest, chain, delegate = _setup()
    genuine, _ = _genuine_call(target, chain, delegate)
    other = PeerNode(
        LocalPolicy.of(["read"]),
        require_caller_attestation=REQUIRE_HARDWARE,
        caller_verifier=verifier,
        trusted_root_issuers=[chain[0].issuer],
        require_holder_proof=False,
    )
    # Two instances behind one load balancer share a challenge secret, so the
    # challenge verifies at both; the channel keys still differ.
    other._challenge_secret = target._challenge_secret
    with pytest.raises(AttestationFailed, match="proof of possession did not verify"):
        other.handle(a2a_adapter.attach_ca2a_metadata({}, genuine))


def test_a_forged_or_wrong_version_proof_is_refused() -> None:
    target, _honest, chain, delegate = _setup()
    genuine, _ = _genuine_call(target, chain, delegate)
    mac = genuine.caller_possession.mac
    cases = {
        "did not verify": CallerPossession(CALLER_OFFER_VERSION, "00" * 32),
        "unsupported version": CallerPossession("ca2a-caller-offer-v1", mac),
    }
    for reason, possession in cases.items():
        bad = dataclasses.replace(genuine, caller_possession=possession)
        with pytest.raises(AttestationFailed, match=reason):
            target.handle(a2a_adapter.attach_ca2a_metadata({}, bad))


# --------------------------------------------------------------------------
# (c) The legitimate hardware caller still passes; (d) software stays "none"
# --------------------------------------------------------------------------


def _serve(node):
    srv = server.serve(node, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_a_legitimate_hardware_caller_is_recorded_as_hardware_end_to_end() -> None:
    target, _honest, chain, delegate = _setup()
    srv, base = _serve(target)
    try:
        body = client.send_task(
            base,
            chain,
            "read",
            "r1",
            holder_key=delegate,
            payload=b"confidential",
            caller_provider=FakeHardware(),
        )
    finally:
        srv.shutdown()
        srv.server_close()
    assert body["accepted"] is True
    assert body["caller_attestation"] == CALLER_HARDWARE
    assert body["record"]["caller_attestation"] == CALLER_HARDWARE


def test_a_software_caller_still_appraises_at_assurance_none() -> None:
    root_priv, root_pub = new_keypair()
    delegate, delegate_pub = new_keypair()
    chain = [
        DelegationCredential("c0", root_pub, delegate_pub, frozenset({"read"}), 0).sign(root_priv)
    ]
    target = PeerNode(LocalPolicy.of(["read"]), trusted_root_issuers=[root_pub])
    srv, base = _serve(target)
    try:
        attested = client.send_task(
            base, chain, "read", "r1", holder_key=delegate, caller_provider=SoftwareProvider()
        )
        plain = client.send_task(base, chain, "read", "r2", holder_key=delegate)
    finally:
        srv.shutdown()
        srv.server_close()
    assert attested["caller_attestation"] == CALLER_SOFTWARE_ONLY
    assert plain["caller_attestation"] == CALLER_NOT_OFFERED
    _priv, offer = offer_channel(SoftwareProvider(), nonce="n", role=ROLE_CALLER)
    assert verify_offer(offer, expected_nonce="n", role=ROLE_CALLER).assurance == "none"


# --------------------------------------------------------------------------
# Wire compatibility
# --------------------------------------------------------------------------


def test_a_pre_v2_caller_offer_fails_with_a_clear_error() -> None:
    """An old caller: a role-less offer and no caller_possession key."""
    root_priv, root_pub = new_keypair()
    delegate, delegate_pub = new_keypair()
    chain = [
        DelegationCredential("c0", root_pub, delegate_pub, frozenset({"read"}), 0).sign(root_priv)
    ]
    target = PeerNode(LocalPolicy.of(["read"]), trusted_root_issuers=[root_pub])
    challenge = target.issue_challenge()
    old_offer = attest_channel(SoftwareProvider(), "ab" * 32, challenge)  # v1 callers did this
    _, message = _present(target, chain, delegate, old_offer, challenge)
    assert "role" not in message["metadata"][KEY_CALLER_OFFER]["attestation"]
    assert KEY_CALLER_POSSESSION not in message["metadata"]
    with pytest.raises(AttestationFailed, match="'callee' role") as exc_info:
        target.handle(message)
    assert "ca2a-caller-offer-v2" in (exc_info.value.detail or "")


def test_a_possession_without_an_offer_is_refused() -> None:
    target, _honest, chain, delegate = _setup()
    genuine, _ = _genuine_call(target, chain, delegate)
    message = a2a_adapter.attach_ca2a_metadata({}, genuine)
    del message["metadata"][KEY_CALLER_OFFER]
    with pytest.raises(CA2AError):
        target.handle(message)


@pytest.mark.parametrize("bad", [42, "x", {"version": CALLER_OFFER_VERSION}, {"mac": "00"}])
def test_a_malformed_possession_fails_closed(bad: object) -> None:
    target, _honest, chain, delegate = _setup()
    genuine, _ = _genuine_call(target, chain, delegate)
    message = a2a_adapter.attach_ca2a_metadata({}, genuine)
    message["metadata"][KEY_CALLER_POSSESSION] = bad
    with pytest.raises(TransportError, match="malformed caller_possession"):
        a2a_adapter.parse_peer_request(message)


def test_an_unknown_role_on_the_wire_fails_closed() -> None:
    body = wire.serialize_channel_offer(PeerNode(LocalPolicy.of(["read"])).offer("n"))
    body["attestation"]["role"] = "observer"
    with pytest.raises(TransportError, match="malformed channel offer") as exc_info:
        wire.parse_channel_offer(body)
    assert "unknown offer role" in (exc_info.value.detail or "")


def test_caller_and_callee_bindings_differ_on_every_platform() -> None:
    """The role is inside the signed bytes, not only a label beside them."""
    from ca2a_runtime.tee.sev_snp import snp_report_data
    from ca2a_runtime.tee.tdx import tdx_report_data

    for derive in (tpm_qualifying_data, snp_report_data, tdx_report_data):
        assert derive("ab" * 32, "n") == derive("ab" * 32, "n", role=ROLE_CALLEE)
        assert derive("ab" * 32, "n") != derive("ab" * 32, "n", role=ROLE_CALLER)
        with pytest.raises(AttestationFailed, match="unknown offer role"):
            derive("ab" * 32, "n", role="observer")
