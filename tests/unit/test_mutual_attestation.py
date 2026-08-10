"""Mutual attestation: the callee appraising what the *caller* is running.

The delegation chain says what a caller is allowed to ask for. It says nothing
about what the caller is, and until this the callee never asked. These tests
cover the callee-issued challenge, the caller offer bound to it, the requirement
ladder, and -- above all -- the ordering: appraisal happens before the sealed
payload is opened, so an unattested caller never gets its work done. See
``docs/spec/mutual-attestation.md``.
"""

from __future__ import annotations

import threading
import time

import pytest

from ca2a_runtime import challenge as challenge_mod
from ca2a_runtime import peer as peer_mod
from ca2a_runtime.attestation import ChannelOffer, appraise_caller, seal_to_peer, verify_offer
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.errors import AttestationFailed, CA2AError, ConfigError, TransportError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import (
    REQUIRE_ANY,
    REQUIRE_HARDWARE,
    REQUIRE_NONE,
    PeerRequest,
    handle_peer_request,
)
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import (
    CALLER_FAILED,
    CALLER_HARDWARE,
    CALLER_NOT_OFFERED,
    CALLER_SOFTWARE_ONLY,
)
from ca2a_runtime.tee.base import AttestationReport
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.transport import a2a_adapter, client, server, wire
from ca2a_runtime.transport.constants import KEY_CALLER_OFFER

POLICY = LocalPolicy.of({"read"})


def _chain() -> list[DelegationCredential]:
    root_priv, root_pub = new_keypair()
    subject_pub = new_keypair()[1]
    return [
        DelegationCredential(
            credential_id="c0",
            issuer=root_pub,
            subject=subject_pub,
            scope=frozenset({"read", "write"}),
            depth=0,
        ).sign(root_priv)
    ]


def _caller_offer(challenge: str, *, platform: str = "software-only") -> ChannelOffer:
    """A caller's own attested channel key, bound to ``challenge``."""
    public_key = SoftwareProvider().attest("x", "y").public_key  # a well-formed key string
    return ChannelOffer(
        channel_public_key=public_key,
        report=AttestationReport(
            platform=platform,
            measurement="caller-measurement",
            public_key=public_key,
            nonce=challenge,
        ),
    )


def _request(
    *,
    capability: str = "read",
    sealed: bytes | None = None,
    caller_offer: ChannelOffer | None = None,
) -> PeerRequest:
    return PeerRequest(
        chain=_chain(),
        requested_capability=capability,
        record_id="r0",
        sealed_payload=sealed,
        caller_offer=caller_offer,
    )


# --------------------------------------------------------------------------
# The ordering property. This is the whole point of the change.
# --------------------------------------------------------------------------


class _OpenSpy:
    """Stands in for ``open_sealed`` and remembers whether it ran."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self, sealed: bytes, key: object) -> bytes:
        self.calls += 1
        return b"opened"


@pytest.mark.parametrize(
    ("requirement", "offer_for"),
    [
        # required and absent
        (REQUIRE_ANY, None),
        # required, present, and forged under a secret the callee never held
        (REQUIRE_ANY, "forged"),
        # present and valid, but below the floor the callee set
        (REQUIRE_HARDWARE, "valid"),
    ],
)
def test_sealed_payload_is_never_opened_when_appraisal_refuses(
    monkeypatch: pytest.MonkeyPatch, requirement: str, offer_for: str | None
) -> None:
    """Swap the appraisal and open_sealed calls and this test fails.

    The payload is sealed to the callee's own channel key, so the callee *can*
    read it the moment it arrives. Appraising after opening would mean the
    unattested caller had already had its work done, and every guarantee would be
    a report on something that already happened.
    """
    secret = challenge_mod.generate_secret()
    spy = _OpenSpy()
    monkeypatch.setattr(peer_mod, "open_sealed", spy)

    offer = None
    if offer_for == "forged":
        other_secret = challenge_mod.generate_secret()
        offer = _caller_offer(challenge_mod.issue_challenge(other_secret))
    elif offer_for == "valid":
        offer = _caller_offer(challenge_mod.issue_challenge(secret))

    with pytest.raises(AttestationFailed):
        handle_peer_request(
            _request(sealed=b"ciphertext", caller_offer=offer),
            policy=POLICY,
            enclave_private_key=object(),  # never reached, so never used
            challenge_secret=secret,
            require_caller_attestation=requirement,
            caller_verifier=lambda report, nonce: "m",
        )

    assert spy.calls == 0, "the callee opened the payload before appraising the caller"


def test_payload_is_opened_once_the_caller_does_appraise(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The mirror of the above: appraisal passing must not block the real work."""
    secret = challenge_mod.generate_secret()
    spy = _OpenSpy()
    monkeypatch.setattr(peer_mod, "open_sealed", spy)

    result = handle_peer_request(
        _request(
            sealed=b"ciphertext",
            caller_offer=_caller_offer(challenge_mod.issue_challenge(secret)),
        ),
        policy=POLICY,
        enclave_private_key=object(),
        challenge_secret=secret,
        require_caller_attestation=REQUIRE_ANY,
    )
    assert spy.calls == 1
    assert result.payload == b"opened"
    assert result.caller_attestation == CALLER_SOFTWARE_ONLY


# --------------------------------------------------------------------------
# The requirement ladder
# --------------------------------------------------------------------------


def test_default_serves_a_caller_that_offers_nothing() -> None:
    """The common case. A callee that refused this by default is one nobody can use."""
    result = handle_peer_request(_request(), policy=POLICY)
    assert result.caller_attestation == CALLER_NOT_OFFERED
    assert result.record.caller_attestation == CALLER_NOT_OFFERED
    assert result.record.decision == "allow"


def test_default_records_a_software_caller_that_does_attest() -> None:
    secret = challenge_mod.generate_secret()
    result = handle_peer_request(
        _request(caller_offer=_caller_offer(challenge_mod.issue_challenge(secret))),
        policy=POLICY,
        challenge_secret=secret,
    )
    assert result.caller_attestation == CALLER_SOFTWARE_ONLY
    assert result.record.caller_attestation == CALLER_SOFTWARE_ONLY


def test_require_any_refuses_a_caller_that_offers_nothing() -> None:
    secret = challenge_mod.generate_secret()
    with pytest.raises(AttestationFailed) as exc_info:
        handle_peer_request(
            _request(),
            policy=POLICY,
            challenge_secret=secret,
            require_caller_attestation=REQUIRE_ANY,
        )
    record = exc_info.value.record
    assert record is not None
    assert record.decision == "deny"
    assert record.caller_attestation == CALLER_NOT_OFFERED


def test_require_hardware_refuses_a_software_caller_and_says_what_it_found() -> None:
    """The refusal records "software-only", not "failed": the appraisal worked."""
    secret = challenge_mod.generate_secret()
    with pytest.raises(AttestationFailed) as exc_info:
        handle_peer_request(
            _request(caller_offer=_caller_offer(challenge_mod.issue_challenge(secret))),
            policy=POLICY,
            challenge_secret=secret,
            require_caller_attestation=REQUIRE_HARDWARE,
            caller_verifier=lambda report, nonce: "m",
        )
    assert exc_info.value.record.caller_attestation == CALLER_SOFTWARE_ONLY


def test_require_hardware_accepts_a_verified_hardware_caller() -> None:
    secret = challenge_mod.generate_secret()
    offer = _caller_offer(challenge_mod.issue_challenge(secret), platform="sev-snp")
    result = handle_peer_request(
        _request(caller_offer=offer),
        policy=POLICY,
        challenge_secret=secret,
        require_caller_attestation=REQUIRE_HARDWARE,
        caller_verifier=lambda report, nonce: "caller-measurement",
    )
    assert result.caller_attestation == CALLER_HARDWARE
    assert result.record.caller_attestation == CALLER_HARDWARE


def test_unknown_requirement_value_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="require_caller_attestation"):
        handle_peer_request(_request(), policy=POLICY, require_caller_attestation="strict-ish")


# --------------------------------------------------------------------------
# A broken proof is not the same fact as no proof
# --------------------------------------------------------------------------


@pytest.mark.parametrize("requirement", [REQUIRE_NONE, REQUIRE_ANY, REQUIRE_HARDWARE])
def test_a_forged_challenge_is_refused_at_every_rung(requirement: str) -> None:
    """Including at "none". Demanding nothing means accepting a caller that proves
    nothing; it does not mean accepting a broken proof."""
    secret = challenge_mod.generate_secret()
    forged = challenge_mod.issue_challenge(challenge_mod.generate_secret())
    with pytest.raises(AttestationFailed) as exc_info:
        handle_peer_request(
            _request(caller_offer=_caller_offer(forged)),
            policy=POLICY,
            challenge_secret=secret,
            require_caller_attestation=requirement,
            caller_verifier=lambda report, nonce: "m",
        )
    assert exc_info.value.record.caller_attestation == CALLER_FAILED


def test_an_expired_challenge_is_refused() -> None:
    secret = challenge_mod.generate_secret()
    expired = challenge_mod.issue_challenge(secret, ttl_seconds=1)
    # Rather than sleeping: the challenge encodes its own expiry, so verifying it
    # against a later clock is the same code path a real timeout takes.
    with pytest.raises(AttestationFailed, match="expired"):
        challenge_mod.verify_challenge(secret, expired, now=int(time.time()) + 5)


def test_a_challenge_from_another_instance_does_not_verify() -> None:
    """The per-process secret, stated as a test: two nodes do not share challenges.

    This is the cost of the stateless scheme that was chosen deliberately. A
    deployment behind a load balancer must either pin the handshake and the task
    to one instance or share a secret between them.
    """
    node_a, node_b = PeerNode(POLICY), PeerNode(POLICY)
    offer = _caller_offer(node_a.issue_challenge())
    message = a2a_adapter.attach_ca2a_metadata({}, _request(caller_offer=offer))
    node_b.require_caller_attestation = REQUIRE_ANY
    with pytest.raises(AttestationFailed):
        node_b.handle(message)


def test_an_offer_to_a_callee_that_issues_no_challenges_is_refused() -> None:
    """Present-but-unappraisable must not be silently downgraded to absent."""
    with pytest.raises(AttestationFailed, match="issues no challenges") as exc_info:
        handle_peer_request(
            _request(caller_offer=_caller_offer("some.challenge.value.here")),
            policy=POLICY,
            challenge_secret=None,
        )
    assert exc_info.value.record.caller_attestation == CALLER_FAILED


def test_appraise_caller_rejects_a_report_that_binds_a_different_key() -> None:
    secret = challenge_mod.generate_secret()
    good = _caller_offer(challenge_mod.issue_challenge(secret))
    swapped = ChannelOffer(channel_public_key="a-different-key", report=good.report)
    with pytest.raises(AttestationFailed, match="does not bind"):
        appraise_caller(swapped, challenge_secret=secret)


def test_a_hardware_caller_report_without_a_verifier_fails_closed() -> None:
    """The callee must not take a hardware claim on trust just because it is bold."""
    secret = challenge_mod.generate_secret()
    offer = _caller_offer(challenge_mod.issue_challenge(secret), platform="tdx")
    with pytest.raises(AttestationFailed, match="requires a hardware verifier"):
        appraise_caller(offer, challenge_secret=secret, verifier=None)


# --------------------------------------------------------------------------
# Configuration that could only ever fail should fail at construction
# --------------------------------------------------------------------------


def test_node_rejects_hardware_requirement_without_a_verifier() -> None:
    with pytest.raises(ConfigError, match="caller_verifier"):
        PeerNode(POLICY, require_caller_attestation=REQUIRE_HARDWARE)


def test_node_rejects_an_unknown_requirement() -> None:
    with pytest.raises(ConfigError):
        PeerNode(POLICY, require_caller_attestation="yes-please")


# --------------------------------------------------------------------------
# Wire format
# --------------------------------------------------------------------------


def test_caller_offer_round_trips_through_a2a_metadata() -> None:
    offer = _caller_offer("v1.123.abc.def")
    request = _request(caller_offer=offer)
    parsed = a2a_adapter.parse_peer_request(a2a_adapter.attach_ca2a_metadata({}, request))
    assert parsed.caller_offer is not None
    assert parsed.caller_offer.channel_public_key == offer.channel_public_key
    assert parsed.caller_offer.report.nonce == "v1.123.abc.def"
    assert parsed.caller_offer.report.platform == offer.report.platform


def test_absent_caller_offer_parses_as_no_offer() -> None:
    parsed = a2a_adapter.parse_peer_request(a2a_adapter.attach_ca2a_metadata({}, _request()))
    assert parsed.caller_offer is None


def test_a_malformed_caller_offer_fails_closed() -> None:
    """A caller cannot get itself treated as unattested by sending rubbish."""
    message = a2a_adapter.attach_ca2a_metadata({}, _request())
    message["metadata"][KEY_CALLER_OFFER] = {"channel_public_key": "k"}  # no attestation
    with pytest.raises(TransportError, match="malformed channel offer"):
        a2a_adapter.parse_peer_request(message)


def test_challenge_rides_the_handshake_response() -> None:
    node = PeerNode(POLICY)
    body = wire.serialize_channel_offer(node.offer("n"), challenge=node.issue_challenge())
    assert wire.parse_challenge(body) is not None
    # and the offer still parses exactly as it did before the field existed
    assert wire.parse_channel_offer(body).channel_public_key == node.channel_public_key


def test_a_handshake_without_a_challenge_is_not_an_error() -> None:
    """A one-directional callee stays usable; the caller simply does not attest."""
    node = PeerNode(POLICY)
    assert wire.parse_challenge(wire.serialize_channel_offer(node.offer("n"))) is None


@pytest.mark.parametrize("bad", [42, "", None, {"nested": True}])
def test_a_present_but_unusable_challenge_is_malformed(bad: object) -> None:
    with pytest.raises(TransportError, match="challenge must be"):
        wire.parse_challenge({"challenge": bad})


def test_result_states_the_outcome_at_the_top_level_and_in_the_record() -> None:
    secret = challenge_mod.generate_secret()
    result = handle_peer_request(
        _request(caller_offer=_caller_offer(challenge_mod.issue_challenge(secret))),
        policy=POLICY,
        challenge_secret=secret,
    )
    body = wire.serialize_peer_result(result)
    assert body["caller_attestation"] == CALLER_SOFTWARE_ONLY
    assert body["record"]["caller_attestation"] == CALLER_SOFTWARE_ONLY


# --------------------------------------------------------------------------
# End to end over the reference HTTP transport
# --------------------------------------------------------------------------


def _serve(node: PeerNode):
    srv = server.serve(node, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_http_mutual_call_end_to_end() -> None:
    """The caller attests to the callee's challenge, over the real transport."""
    node = PeerNode(POLICY, require_caller_attestation=REQUIRE_ANY)
    srv, base = _serve(node)
    try:
        body = client.send_task(
            base,
            _chain(),
            "read",
            "r0",
            payload=b"confidential",
            caller_provider=SoftwareProvider(),
        )
        assert body["accepted"] is True
        assert body["caller_attestation"] == CALLER_SOFTWARE_ONLY
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_unattested_caller_is_refused_by_a_callee_that_requires_one() -> None:
    node = PeerNode(POLICY, require_caller_attestation=REQUIRE_ANY)
    srv, base = _serve(node)
    try:
        with pytest.raises(CA2AError) as exc_info:
            client.send_task(base, _chain(), "read", "r0", payload=b"confidential")
        assert exc_info.value.code == "ATTESTATION_FAILED"
        assert exc_info.value.http_status == 412
    finally:
        srv.shutdown()
        srv.server_close()


def test_http_unattested_caller_is_served_by_default() -> None:
    """The adoption case: an old caller against a new callee, unchanged."""
    srv, base = _serve(PeerNode(POLICY))
    try:
        body = client.send_task(base, _chain(), "read", "r0", payload=b"confidential")
        assert body["accepted"] is True
        assert body["caller_attestation"] == CALLER_NOT_OFFERED
    finally:
        srv.shutdown()
        srv.server_close()


def test_client_refuses_to_fake_mutuality_against_a_silent_callee() -> None:
    """A caller that opted in must not quietly fall back to a nonce it chose itself."""
    node = PeerNode(POLICY)
    srv = server.serve(node, host="127.0.0.1", port=0)
    # Serve a handshake with the challenge stripped, as an older callee would.
    original = wire.serialize_channel_offer

    def _no_challenge(offer, *, challenge=None):
        return original(offer)

    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        wire.serialize_channel_offer = _no_challenge  # type: ignore[assignment]
        with pytest.raises(AttestationFailed, match="issued no challenge"):
            client.send_task(base, _chain(), "read", "r0", caller_provider=SoftwareProvider())
    finally:
        wire.serialize_channel_offer = original  # type: ignore[assignment]
        srv.shutdown()
        srv.server_close()


def test_sealed_payload_still_reaches_a_callee_that_appraises_the_caller() -> None:
    """Mutual attestation must not break the thing it wraps."""
    node = PeerNode(POLICY, require_caller_attestation=REQUIRE_ANY)
    peer = verify_offer(node.offer("n"), expected_nonce="n")
    sealed = seal_to_peer(peer, b"confidential task input")
    offer = _caller_offer(node.issue_challenge())
    result = node.handle(
        a2a_adapter.attach_ca2a_metadata({}, _request(sealed=sealed, caller_offer=offer))
    )
    assert result.payload == b"confidential task input"
    assert result.caller_attestation == CALLER_SOFTWARE_ONLY
