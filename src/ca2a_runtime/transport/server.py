"""Reference HTTP transport for the cA2A peer path (standard library only).

A minimal A2A server that runs the full inbound pipeline over the wire:

- ``GET /.well-known/ca2a/channel?nonce=<n>`` returns the callee's attested
  channel key (the attestation handshake);
- ``POST /ca2a/task`` accepts a cA2A-profile A2A message, parses it into a
  PeerRequest, runs verify + policy + enforce + open-sealed + provenance, and
  returns the result, or a structured error at the error's own HTTP status.

It is a reference, not the only transport: any A2A server can call
:mod:`ca2a_runtime.transport.a2a_adapter` and a :class:`~ca2a_runtime.node.PeerNode`
the same way. Standard library only, so it runs anywhere Python does, including a
plain container platform.
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, cast
from urllib.parse import parse_qs, urlparse

from ca2a_runtime.errors import CA2AError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.transport import wire

CHANNEL_PATH = "/.well-known/ca2a/channel"
TASK_PATH = "/ca2a/task"
_MAX_BODY = 1 << 20  # 1 MiB; fail closed on larger bodies
_MAX_NONCE = 256
_READ_TIMEOUT_SECONDS = 10.0


class PeerHTTPServer(ThreadingHTTPServer):
    """A threading HTTP server carrying the PeerNode its handler serves."""

    def __init__(self, address: tuple[str, int], node: PeerNode) -> None:
        super().__init__(address, _PeerHandler)
        self.node = node


class _PeerHandler(BaseHTTPRequestHandler):
    server_version = "ca2a-ref/0.1"

    def setup(self) -> None:
        super().setup()
        # A client that declares a body and never sends it must not retain an
        # unbounded worker thread. This is a reference server, but it still fails
        # closed under slow or incomplete unauthenticated requests.
        self.connection.settimeout(_READ_TIMEOUT_SECONDS)

    def _node(self) -> PeerNode:
        return cast(PeerHTTPServer, self.server).node

    def _send_json(self, status: int, body: dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, format: str, *args: Any) -> None:
        # Silence default stderr access logging; a real deployment wires logging.
        return

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path != CHANNEL_PATH:
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "unknown path"}})
            return
        try:
            nonces = parse_qs(parsed.query, max_num_fields=1).get("nonce", [])
        except ValueError:
            nonces = []
        if len(nonces) != 1 or not nonces[0] or len(nonces[0]) > _MAX_NONCE:
            self._send_json(
                400,
                {
                    "error": {
                        "code": "BAD_REQUEST",
                        "message": "exactly one bounded nonce is required",
                    }
                },
            )
            return
        node = self._node()
        try:
            offer = node.offer(nonces[0])
        except CA2AError as exc:
            self._send_json(exc.http_status, wire.serialize_error(exc))
            return
        # The handshake is where both directions get what they need in one round
        # trip: the caller gets the key to seal to, and the challenge it must bind
        # its own key into if it wants to be appraised. Issuing one costs nothing
        # and stores nothing, so it is offered unconditionally; a caller that
        # ignores it is still served.
        self._send_json(
            200,
            wire.serialize_channel_offer(offer, challenge=node.issue_challenge()),
        )

    def do_POST(self) -> None:
        if urlparse(self.path).path != TASK_PATH:
            self._send_json(404, {"error": {"code": "NOT_FOUND", "message": "unknown path"}})
            return
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isascii() or not raw_length.isdecimal():
            self._send_json(
                400, {"error": {"code": "BAD_REQUEST", "message": "invalid body length"}}
            )
            return
        length = int(raw_length)
        if length <= 0 or length > _MAX_BODY:
            self._send_json(
                400, {"error": {"code": "BAD_REQUEST", "message": "invalid body length"}}
            )
            return
        try:
            message = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError, TimeoutError):
            self._send_json(400, {"error": {"code": "BAD_REQUEST", "message": "invalid JSON"}})
            return
        if not isinstance(message, dict):
            self._send_json(400, {"error": {"code": "BAD_REQUEST", "message": "object required"}})
            return
        try:
            result = self._node().handle(message)
        except CA2AError as exc:
            self._send_json(exc.http_status, wire.serialize_error(exc))
            return
        self._send_json(200, wire.serialize_peer_result(result))


def serve(node: PeerNode, host: str = "127.0.0.1", port: int = 8443) -> PeerHTTPServer:
    """Create a server bound to (host, port) serving ``node``. Call serve_forever()."""
    return PeerHTTPServer((host, port), node)
