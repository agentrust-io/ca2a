"""Live A2A JSON-RPC peer listener.

Wires ``parse_peer_request`` into ``handle_peer_request`` on an inbound
``message/send`` call. This is the Tier 2 live-serving slice: an HTTP listener
and ``ca2a start``. It does **not** perform an attestation handshake or bind
the sealed channel to a verified measurement; sealed open uses a configured
software/enclave key only.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import CA2AError, ConfigError, TransportError
from ca2a_runtime.peer import PeerResult, handle_peer_request
from ca2a_runtime.policy import Policy
from ca2a_runtime.transport import EXTENSION_URI, parse_peer_request

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_APPLICATION_ERROR = -32000

SUPPORTED_METHODS = frozenset({"message/send", "SendMessage"})


@dataclass(frozen=True)
class PeerRuntime:
    """Runtime context for a live cA2A peer listener."""

    config: Ca2aConfig
    policy: Policy
    enclave_private_key: X25519PrivateKey | None = None


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _result_payload(result: PeerResult) -> dict[str, Any]:
    body: dict[str, Any] = {
        "granted_capability": result.granted_capability,
        "effective_scope": sorted(result.effective_scope),
        "record": result.record.body(),
        "record_hash": result.record.record_hash(),
    }
    if result.payload is not None:
        body["payload"] = _b64url_encode(result.payload)
    return {"ca2a": body}


def _jsonrpc_error(
    request_id: Any,
    *,
    code: int,
    message: str,
    data: dict[str, Any] | None = None,
    http_status: int = 200,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return JSONResponse(
        {"jsonrpc": "2.0", "id": request_id, "error": error},
        status_code=http_status,
    )


def _jsonrpc_result(request_id: Any, result: dict[str, Any]) -> JSONResponse:
    return JSONResponse({"jsonrpc": "2.0", "id": request_id, "result": result})


def handle_jsonrpc(runtime: PeerRuntime, body: dict[str, Any]) -> JSONResponse:
    """Handle one JSON-RPC request body against the peer runtime."""
    request_id = body.get("id")
    if body.get("jsonrpc") != "2.0":
        return _jsonrpc_error(
            request_id,
            code=JSONRPC_INVALID_REQUEST,
            message="jsonrpc must be '2.0'",
        )

    method = body.get("method")
    if not isinstance(method, str):
        return _jsonrpc_error(
            request_id,
            code=JSONRPC_INVALID_REQUEST,
            message="method must be a string",
        )
    if method not in SUPPORTED_METHODS:
        return _jsonrpc_error(
            request_id,
            code=JSONRPC_METHOD_NOT_FOUND,
            message=f"method not found: {method}",
        )

    params = body.get("params")
    if params is None:
        params = {}
    if not isinstance(params, dict):
        return _jsonrpc_error(
            request_id,
            code=JSONRPC_INVALID_PARAMS,
            message="params must be an object",
        )

    try:
        peer_request = parse_peer_request(body)
    except TransportError as exc:
        return _jsonrpc_error(
            request_id,
            code=JSONRPC_APPLICATION_ERROR,
            message=str(exc),
            data={"ca2a_code": exc.code, "detail": exc.detail},
            http_status=exc.http_status,
        )

    if peer_request is None:
        # Ordinary A2A: no cA2A trust envelope. Do not invent a partial trust state.
        return _jsonrpc_result(
            request_id,
            {
                "ca2a": None,
                "note": "ordinary A2A input; no cA2A extension metadata present",
            },
        )

    try:
        result = handle_peer_request(
            peer_request,
            policy=runtime.policy,
            enclave_private_key=runtime.enclave_private_key,
            max_depth=runtime.config.max_delegation_depth,
        )
    except CA2AError as exc:
        return _jsonrpc_error(
            request_id,
            code=JSONRPC_APPLICATION_ERROR,
            message=str(exc),
            data={"ca2a_code": exc.code, "detail": exc.detail},
            http_status=exc.http_status,
        )

    return _jsonrpc_result(request_id, _result_payload(result))


def create_app(runtime: PeerRuntime) -> Starlette:
    """Build the Starlette ASGI app for a peer runtime."""

    async def rpc(request: Request) -> Response:
        try:
            body = await request.json()
        except Exception:
            return _jsonrpc_error(
                None,
                code=JSONRPC_PARSE_ERROR,
                message="parse error",
                http_status=400,
            )
        if not isinstance(body, dict):
            return _jsonrpc_error(
                None,
                code=JSONRPC_INVALID_REQUEST,
                message="request body must be a JSON object",
                http_status=400,
            )
        return handle_jsonrpc(runtime, body)

    async def health(_: Request) -> JSONResponse:
        return JSONResponse(
            {
                "status": "ok",
                "extension": EXTENSION_URI,
                "provider": runtime.config.provider,
                "enforcement_mode": runtime.config.enforcement_mode,
            }
        )

    return Starlette(
        routes=[
            Route("/", rpc, methods=["POST"]),
            Route("/rpc", rpc, methods=["POST"]),
            Route("/health", health, methods=["GET"]),
        ]
    )


def parse_listen_addr(listen_addr: str) -> tuple[str, int]:
    """Split ``host:port`` into a host string and port int."""
    host, sep, port_str = listen_addr.rpartition(":")
    if not sep or not port_str:
        raise ConfigError(
            f"listen_addr must be host:port, got {listen_addr!r}",
        )
    try:
        port = int(port_str)
    except ValueError as exc:
        raise ConfigError(
            f"listen_addr port must be an integer, got {port_str!r}",
        ) from exc
    if not (1 <= port <= 65535):
        raise ConfigError(f"listen_addr port out of range: {port}")
    if not host:
        host = "0.0.0.0"
    return host, port


def load_enclave_private_key(hex_key: str | None) -> X25519PrivateKey | None:
    """Load an X25519 private key from raw hex, or return None."""
    if hex_key is None or hex_key == "":
        return None
    try:
        raw = bytes.fromhex(hex_key.strip())
        if len(raw) != 32:
            raise ValueError(f"expected 32 bytes, got {len(raw)}")
        return X25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise ConfigError("invalid enclave_private_key_hex", detail=str(exc)) from exc
