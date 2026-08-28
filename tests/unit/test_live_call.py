"""End-to-end tests for the live-call wiring: attestation handshake, the HTTP
transport, and the full inbound pipeline through a PeerNode (software mode). The
A2A metadata binding itself is covered by test_a2a_adapter.py; here it is used
via ``attach_ca2a_metadata`` to build real messages."""

from __future__ import annotations

import dataclasses
import json
import socket
import threading
import urllib.error
import urllib.request

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ca2a_runtime.attestation import ChannelOffer, seal_to_peer, verify_offer
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.delegation.holder import build_holder_proof
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
from ca2a_runtime.tee.base import AttestationReport
from ca2a_runtime.transport import a2a_adapter, client, server, wire

PUBLIC_KEY = "aa" * 32
NONCE = "nonce-1"


def _post_bytes(url: str, raw: bytes) -> tuple[int, dict]:
    """POST raw bytes, bypassing the client's JSON encoding.

    The client only ever sends well-formed messages, so testing what the server
    does with a body it should refuse needs to go around it.
    """
    req = urllib.request.Request(
        url, data=raw, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "gopher://host"])
def test_client_rejects_non_http_url(url: str) -> None:
    with pytest.raises(TransportError, match="non-HTTP"):
        client._get_json(url)


def _chain() -> tuple[list[DelegationCredential], Ed25519PrivateKey]:
    """A one-hop chain plus the leaf subject's private key, which the delegate holds."""
    root_priv, root_pub = new_keypair()
    subject_priv, subject_pub = new_keypair()
    cred = DelegationCredential(
        credential_id="c0",
        issuer=root_pub,
        subject=subject_pub,
        scope=frozenset({"read", "write"}),
        depth=0,
    ).sign(root_priv)
    return [cred], subject_priv


def _message(
    node: PeerNode,
    chain: list[DelegationCredential],
    leaf_key: Ed25519PrivateKey,
    capability: str,
    record_id: str,
    *,
    sealed: bytes | None = None,
    parent: str | None = None,
) -> dict[str, object]:
    """An A2A message carrying a holder proof against a challenge ``node`` issued."""
    request = PeerRequest(
        chain=chain,
        requested_capability=capability,
        record_id=record_id,
        sealed_payload=sealed,
        parent_record_hash=parent,
        holder_proof=build_holder_proof(
            leaf_key,
            chain[-1],
            audience=node.channel_public_key,
            challenge=node.issue_challenge(),
            requested_capability=capability,
            record_id=record_id,
            sealed_payload=sealed,
        ),
    )
    return a2a_adapter.attach_ca2a_metadata({}, request)


def test_live_inbound_flow_software_mode() -> None:
    chain, leaf_key = _chain()
    node = PeerNode(LocalPolicy.of({"read"}), trusted_root_issuers={chain[0].issuer})

    nonce = "nonce-abc"
    peer = verify_offer(node.offer(nonce), expected_nonce=nonce)
    assert peer.assurance == "none"
    assert peer.public_key == node.channel_public_key

    sealed = seal_to_peer(peer, b"confidential task input")
    result = node.handle(_message(node, chain, leaf_key, "read", "r0", sealed=sealed))

    assert result.payload == b"confidential task input"
    assert result.granted_capability == "read"
    assert result.effective_scope == frozenset({"read"})
    assert result.record.credential_id == "c0"
    assert result.record.parent_record_hash is None


def test_over_scope_capability_is_denied() -> None:
    chain, leaf_key = _chain()
    node = PeerNode(
        LocalPolicy.of({"read"}), trusted_root_issuers={chain[0].issuer}
    )  # policy does not allow "write"
    with pytest.raises(ScopeNotPermitted):
        node.handle(_message(node, chain, leaf_key, "write", "r1"))


def test_tampered_sealed_payload_fails_closed() -> None:
    chain, leaf_key = _chain()
    node = PeerNode(LocalPolicy.of({"read"}), trusted_root_issuers={chain[0].issuer})
    peer = verify_offer(node.offer("n"), expected_nonce="n")
    sealed = bytearray(seal_to_peer(peer, b"payload"))
    sealed[-1] ^= 0x01
    with pytest.raises(SealedChannelError):
        node.handle(_message(node, chain, leaf_key, "read", "r2", sealed=bytes(sealed)))


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


def test_wire_carries_every_attestation_report_field() -> None:
    """The claim/evidence field lists in wire.py are hand-written and read back
    with getattr, so a field added to AttestationReport without a matching
    entry in one of the two tuples would be silently dropped on the wire again
    -- which is exactly the shape of the bug this module exists to fix. Pinning
    the two tuples against dataclasses.fields makes that impossible to miss.
    """
    covered = set(wire._CLAIM_FIELDS) | set(wire._EVIDENCE_FIELDS)
    declared = {f.name for f in dataclasses.fields(AttestationReport)}
    assert covered == declared


def test_software_only_offer_wire_body_has_no_evidence_keys() -> None:
    """The evidence fields must be omitted, not sent as null, when absent -- so
    a software-only offer's JSON is unchanged from before evidence traveled."""
    bare = AttestationReport(
        platform="software-only",
        measurement="software-only-no-hardware-guarantee",
        public_key=PUBLIC_KEY,
        nonce=NONCE,
    )
    offer = ChannelOffer(channel_public_key=PUBLIC_KEY, report=bare)
    body = wire.serialize_channel_offer(offer)
    assert set(body["attestation"]) == {"platform", "measurement", "public_key", "nonce"}


def test_parse_channel_offer_rejects_evidence_with_invalid_alphabet() -> None:
    """A malformed peer (or an attacker) can put anything in the JSON body.
    A character outside the base64url alphabet (here "!") must fail closed
    with a clear TransportError, not an uncaught exception."""
    body = {
        "channel_public_key": PUBLIC_KEY,
        "attestation": {
            "platform": "tpm",
            "measurement": "sha256:" + ("11" * 32),
            "public_key": PUBLIC_KEY,
            "nonce": NONCE,
            "raw_evidence": "not-valid-base64url!!",
        },
    }
    with pytest.raises(TransportError, match="raw_evidence is not valid base64url"):
        wire.parse_channel_offer(body)


def test_parse_channel_offer_rejects_evidence_with_bad_length() -> None:
    """A string that only uses base64url-alphabet characters can still be an
    invalid length (e.g. a single character can never be valid base64). That
    must also fail closed with a TransportError, not a raw binascii.Error."""
    body = {
        "channel_public_key": PUBLIC_KEY,
        "attestation": {
            "platform": "tpm",
            "measurement": "sha256:" + ("11" * 32),
            "public_key": PUBLIC_KEY,
            "nonce": NONCE,
            "quote_signature": "A",
        },
    }
    with pytest.raises(TransportError, match="quote_signature is not valid base64url"):
        wire.parse_channel_offer(body)


def test_parse_channel_offer_rejects_evidence_that_is_the_empty_string() -> None:
    """"" passes a `*`-quantified base64url check and decodes to b"", which is
    not None -- letting a peer put a field there that is present but empty
    (see AttestationReport.raw_evidence's `is None` presence check). The regex
    requires at least one character, so this must fail closed instead."""
    body = {
        "channel_public_key": PUBLIC_KEY,
        "attestation": {
            "platform": "tpm",
            "measurement": "sha256:" + ("11" * 32),
            "public_key": PUBLIC_KEY,
            "nonce": NONCE,
            "raw_evidence": "",
        },
    }
    with pytest.raises(TransportError, match="raw_evidence is not valid base64url"):
        wire.parse_channel_offer(body)


def test_oversized_channel_response_is_refused_by_the_client() -> None:
    """The client-side mirror of test_oversized_body_is_refused_at_the_declared_bound.

    Once a channel offer can carry base64-encoded evidence, its size is no
    longer bounded by its shape the way four short claim strings were. A
    hostile or broken callee returning an oversized handshake response must be
    refused by the caller rather than buffered into memory in full.
    """
    big_evidence = "A" * (client._MAX_RESPONSE + 1)

    class _Hostile(server._PeerHandler):  # type: ignore[misc]  # private class, test-only
        def do_GET(self) -> None:  # noqa: N802
            self._send_json(
                200,
                {
                    "channel_public_key": PUBLIC_KEY,
                    "attestation": {
                        "platform": "tpm",
                        "measurement": "sha256:" + ("11" * 32),
                        "public_key": PUBLIC_KEY,
                        "nonce": "n",
                        "raw_evidence": big_evidence,
                    },
                },
            )

    srv = server.PeerHTTPServer(("127.0.0.1", 0), PeerNode(LocalPolicy.of({"read"})))
    srv.RequestHandlerClass = _Hostile
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{port}{server.CHANNEL_PATH}?nonce=n"
        with pytest.raises(TransportError, match="exceeds the maximum allowed size"):
            client._get_json(url)
    finally:
        srv.shutdown()
        srv.server_close()


def test_response_under_the_cap_is_read_normally() -> None:
    """The boundary still opens: a response under the cap is read in full."""
    node = PeerNode(LocalPolicy.of({"read"}))
    srv = server.serve(node, host="127.0.0.1", port=0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        hs = client.handshake(f"http://127.0.0.1:{port}")
        assert hs.peer.assurance == "none"
    finally:
        srv.shutdown()
        srv.server_close()


def test_serialize_result_shape() -> None:
    chain, leaf_key = _chain()
    node = PeerNode(LocalPolicy.of({"read"}), trusted_root_issuers={chain[0].issuer})
    result = node.handle(_message(node, chain, leaf_key, "read", "r0"))
    body = wire.serialize_peer_result(result)
    assert body["accepted"] is True
    assert body["granted_capability"] == "read"
    assert body["record"]["credential_id"] == "c0"
    assert "record_hash" in body["record"]

    err_body = wire.serialize_error(ScopeNotPermitted("nope", detail="d"))
    assert err_body["error"]["code"] == "SCOPE_NOT_PERMITTED"
    assert err_body["error"]["http_status"] == 403


def test_http_live_call_end_to_end() -> None:
    chain, leaf_key = _chain()
    node = PeerNode(LocalPolicy.of({"read"}), trusted_root_issuers={chain[0].issuer})
    srv = server.serve(node, host="127.0.0.1", port=0)
    port = srv.server_address[1]
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{port}"
        body = client.send_task(
            base, chain, "read", "r0", holder_key=leaf_key, payload=b"hello over the wire"
        )
        assert body["accepted"] is True
        assert body["granted_capability"] == "read"
        assert body["record"]["credential_id"] == "c0"

        with pytest.raises(CA2AError) as exc_info:
            client.send_task(base, chain, "write", "r1", holder_key=leaf_key)
        assert exc_info.value.code == "SCOPE_NOT_PERMITTED"
    finally:
        srv.shutdown()
        srv.server_close()


def test_oversized_body_is_refused_at_the_declared_bound() -> None:
    """The 1 MiB cap, exercised rather than asserted in a comment.

    A bound with no test above it is a bound nobody has ever crossed. This one
    declares an oversized ``Content-Length`` and sends only a few bytes, which is
    what the guard actually inspects: the server refuses on the declared length
    *before* reading, so an oversized body is never buffered at all. That is also
    why the check has to go through a raw socket -- sending a real 1 MiB body
    races the server's early refusal and the client sees a connection abort
    rather than the 400 it sent.
    """
    node = PeerNode(LocalPolicy.of({"read"}))
    srv = server.serve(node, host="127.0.0.1", port=0)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        request = (
            f"POST {server.TASK_PATH} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {server._MAX_BODY + 1}\r\n"
            "Connection: close\r\n\r\n"
        ).encode() + b'{"a":1}'

        with socket.create_connection(("127.0.0.1", port), timeout=10) as sock:
            sock.sendall(request)
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        assert b"400" in response.split(b"\r\n", 1)[0]
        assert b"BAD_REQUEST" in response

        # and the boundary still opens: a body under the cap is read and parsed,
        # then fails for its own reasons rather than for its size
        url = f"http://127.0.0.1:{port}{server.TASK_PATH}"
        status, body = _post_bytes(url, b'{"not":"a ca2a message"}')
        assert status == 400
        assert body["error"]["code"] == "TRANSPORT_ERROR"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("content_length", ["not-a-number", "+1", "-1", "1.5"])
def test_malformed_content_length_gets_a_bounded_error(content_length: str) -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    srv = server.serve(node, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        request = (
            f"POST {server.TASK_PATH} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{srv.server_address[1]}\r\n"
            f"Content-Length: {content_length}\r\n"
            "Connection: close\r\n\r\n{}"
        ).encode()
        with socket.create_connection(srv.server_address, timeout=10) as sock:
            sock.sendall(request)
            chunks = []
            while chunk := sock.recv(4096):
                chunks.append(chunk)
            response = b"".join(chunks)
        assert b" 400 " in response
        assert b"invalid body length" in response
    finally:
        srv.shutdown()
        srv.server_close()


def test_invalid_utf8_gets_a_structured_error() -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    srv = server.serve(node, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}{server.TASK_PATH}"
        status, body = _post_bytes(url, b"\xff")
        assert status == 400
        assert body["error"]["code"] == "BAD_REQUEST"
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("query", ["", "nonce=", "nonce=a&nonce=b", "nonce=" + "x" * 257])
def test_handshake_requires_one_bounded_nonce(query: str) -> None:
    node = PeerNode(LocalPolicy.of({"read"}))
    srv = server.serve(node, host="127.0.0.1", port=0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{srv.server_address[1]}{server.CHANNEL_PATH}?{query}"
        with pytest.raises(urllib.error.HTTPError) as exc:
            urllib.request.urlopen(url, timeout=10)  # noqa: S310
        assert exc.value.code == 400
    finally:
        srv.shutdown()
        srv.server_close()
