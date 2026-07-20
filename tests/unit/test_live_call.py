"""End-to-end tests for the live-call wiring: attestation handshake, A2A wire
binding, and the full inbound pipeline through a PeerNode (software mode)."""

from __future__ import annotations

import threading

import pytest

from ca2a_runtime.attestation import seal_to_peer, verify_offer
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.errors import (
    AttestationFailed,
    CA2AError,
    ScopeNotPermitted,
    SealedChannelError,
)
from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport import a2a, client, server


def _chain() -> list[DelegationCredential]:
    root_priv, root_pub = new_keypair()
    callee_pub = new_keypair()[1]
    cred = DelegationCredential(
        credential_id="c0",
        issuer=root_pub,
        subject=callee_pub,
        scope=frozenset({"read", "write"}),
        depth=0,
    ).sign(root_priv)
    return [cred]


def test_live_inbound_flow_software_mode() -> None:
    chain = _chain()
    node = PeerNode(LocalPolicy.of({"read"}))

    nonce = "nonce-abc"
    offer = node.offer(nonce)
    peer = verify_offer(offer, expected_nonce=nonce)
    assert peer.assurance == "none"
    assert peer.public_key == node.channel_public_key

    sealed = seal_to_peer(peer, b"confidential task input")
    message = a2a.build_task_message(chain, "read", "r0", sealed_payload=sealed)
    result = node.handle(message)

    assert result.payload == b"confidential task input"
    assert result.granted_capability == "read"
    assert result.effective_scope == frozenset({"read"})
    assert result.record.credential_id == "c0"
    assert result.record.parent_record_hash is None


def test_over_scope_capability_is_denied() -> None:
    chain = _chain()
    node = PeerNode(LocalPolicy.of({"read"}))  # policy does not allow "write"
    message = a2a.build_task_message(chain, "write", "r1")
    with pytest.raises(ScopeNotPermitted):
        node.handle(message)


def test_tampered_sealed_payload_fails_closed() -> None:
    chain = _chain()
    node = PeerNode(LocalPolicy.of({"read"}))
    nonce = "nonce-xyz"
    peer = verify_offer(node.offer(nonce), expected_nonce=nonce)
    sealed = bytearray(seal_to_peer(peer, b"payload"))
    sealed[-1] ^= 0x01
    message = a2a.build_task_message(chain, "read", "r2", sealed_payload=bytes(sealed))
    with pytest.raises(SealedChannelError):
        node.handle(message)


def test_stale_offer_nonce_is_rejected() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    offer = node.offer("nonce-1")
    with pytest.raises(AttestationFailed):
        verify_offer(offer, expected_nonce="a-different-nonce")


def test_wire_roundtrip_parses_chain() -> None:
    chain = _chain()
    message = a2a.build_task_message(chain, "read", "r0")
    request = a2a.parse_peer_request(message)
    assert request.requested_capability == "read"
    assert len(request.chain) == 1
    assert request.chain[0].credential_id == "c0"
    assert request.sealed_payload is None


def test_serialize_result_and_error_shapes() -> None:
    chain = _chain()
    node = PeerNode(LocalPolicy.of({"read"}))
    result = node.handle(a2a.build_task_message(chain, "read", "r0"))
    wire = a2a.serialize_peer_result(result)
    assert wire["accepted"] is True
    assert wire["granted_capability"] == "read"
    assert wire["record"]["credential_id"] == "c0"
    assert "record_hash" in wire["record"]

    err = ScopeNotPermitted("nope", detail="d")
    err_wire = a2a.serialize_error(err)
    assert err_wire["error"]["code"] == "SCOPE_NOT_PERMITTED"
    assert err_wire["error"]["http_status"] == 403


def test_http_live_call_end_to_end() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    srv = server.serve(node, host="127.0.0.1", port=0)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        chain = _chain()

        body = client.send_task(base, chain, "read", "r0", payload=b"hello over the wire")
        assert body["accepted"] is True
        assert body["granted_capability"] == "read"
        assert body["record"]["credential_id"] == "c0"

        with pytest.raises(CA2AError) as exc_info:
            client.send_task(base, chain, "write", "r1")
        assert exc_info.value.code == "SCOPE_NOT_PERMITTED"
    finally:
        srv.shutdown()
        srv.server_close()
