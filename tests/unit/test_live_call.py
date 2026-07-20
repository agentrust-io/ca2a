"""End-to-end tests for the live-call wiring: attestation handshake, the HTTP
transport, and the full inbound pipeline through a PeerNode (software mode). The
A2A metadata binding itself is covered by test_a2a_adapter.py; here it is used
via ``attach_ca2a_metadata`` to build real messages."""

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
    TransportError,
)
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import PeerRequest
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport import a2a_adapter, client, server, wire


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "gopher://host"])
def test_client_rejects_non_http_url(url: str) -> None:
    with pytest.raises(TransportError, match="non-HTTP"):
        client._get_json(url)


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


def _message(
    chain: list[DelegationCredential],
    capability: str,
    record_id: str,
    *,
    sealed: bytes | None = None,
    parent: str | None = None,
) -> dict[str, object]:
    request = PeerRequest(
        chain=chain,
        requested_capability=capability,
        record_id=record_id,
        sealed_payload=sealed,
        parent_record_hash=parent,
    )
    return a2a_adapter.attach_ca2a_metadata({}, request)


def test_live_inbound_flow_software_mode() -> None:
    chain = _chain()
    node = PeerNode(LocalPolicy.of({"read"}))

    nonce = "nonce-abc"
    peer = verify_offer(node.offer(nonce), expected_nonce=nonce)
    assert peer.assurance == "none"
    assert peer.public_key == node.channel_public_key

    sealed = seal_to_peer(peer, b"confidential task input")
    result = node.handle(_message(chain, "read", "r0", sealed=sealed))

    assert result.payload == b"confidential task input"
    assert result.granted_capability == "read"
    assert result.effective_scope == frozenset({"read"})
    assert result.record.credential_id == "c0"
    assert result.record.parent_record_hash is None


def test_over_scope_capability_is_denied() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))  # policy does not allow "write"
    with pytest.raises(ScopeNotPermitted):
        node.handle(_message(_chain(), "write", "r1"))


def test_tampered_sealed_payload_fails_closed() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    peer = verify_offer(node.offer("n"), expected_nonce="n")
    sealed = bytearray(seal_to_peer(peer, b"payload"))
    sealed[-1] ^= 0x01
    with pytest.raises(SealedChannelError):
        node.handle(_message(_chain(), "read", "r2", sealed=bytes(sealed)))


def test_stale_offer_nonce_is_rejected() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    with pytest.raises(AttestationFailed):
        verify_offer(node.offer("nonce-1"), expected_nonce="a-different-nonce")


def test_channel_offer_wire_roundtrip() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    offer = node.offer("nonce-1")
    parsed = wire.parse_channel_offer(wire.serialize_channel_offer(offer))
    assert parsed.channel_public_key == offer.channel_public_key
    peer = verify_offer(parsed, expected_nonce="nonce-1")
    assert peer.public_key == node.channel_public_key


def test_serialize_result_shape() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    result = node.handle(_message(_chain(), "read", "r0"))
    body = wire.serialize_peer_result(result)
    assert body["accepted"] is True
    assert body["granted_capability"] == "read"
    assert body["record"]["credential_id"] == "c0"
    assert "record_hash" in body["record"]

    err_body = wire.serialize_error(ScopeNotPermitted("nope", detail="d"))
    assert err_body["error"]["code"] == "SCOPE_NOT_PERMITTED"
    assert err_body["error"]["http_status"] == 403


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
