"""Unit tests for the live A2A JSON-RPC peer listener."""

from __future__ import annotations

import base64
import json

import httpx
import pytest
from starlette.testclient import TestClient

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import ConfigError
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.server import (
    PeerRuntime,
    create_app,
    handle_jsonrpc,
    load_enclave_private_key,
    parse_listen_addr,
)
from ca2a_runtime.transport import (
    KEY_DELEGATION_CHAIN,
    KEY_PARENT_RECORD_HASH,
    KEY_RECORD_ID,
    KEY_REQUESTED_CAPABILITY,
    KEY_SEALED_PAYLOAD,
)
from tests.unit.conftest import build_chain


def _cred_dicts(scopes: list[frozenset[str]]) -> list[dict]:
    chain = build_chain(scopes)
    return [{**c.body(), "signature": c.signature} for c in chain]


def _envelope(
    *,
    capability: str = "read",
    record_id: str = "rec-live",
    sealed_b64: str | None = None,
    include_ca2a: bool = True,
) -> dict:
    message: dict = {
        "messageId": "msg-1",
        "role": "user",
        "parts": [{"text": "task"}],
        "metadata": {},
    }
    if include_ca2a:
        meta = {
            KEY_DELEGATION_CHAIN: _cred_dicts(
                [frozenset({"read", "write"}), frozenset({"read"})]
            ),
            KEY_REQUESTED_CAPABILITY: capability,
            KEY_RECORD_ID: record_id,
            KEY_PARENT_RECORD_HASH: None,
        }
        if sealed_b64 is not None:
            meta[KEY_SEALED_PAYLOAD] = sealed_b64
        message["metadata"] = meta
    else:
        message["metadata"] = {"https://example.com/ext/other/v1/note": "keep"}

    return {
        "jsonrpc": "2.0",
        "id": "1",
        "method": "message/send",
        "params": {"message": message},
    }


def _runtime(
    *,
    allow: list[str] | None = None,
    enclave_key_hex: str | None = None,
) -> PeerRuntime:
    cfg = Ca2aConfig(
        provider="software-only",
        enforcement_mode="enforcing",
        local_policy=frozenset(allow or ["read", "write"]),
        listen_addr="127.0.0.1:8443",
        enclave_private_key_hex=enclave_key_hex,
    )
    return PeerRuntime(
        config=cfg,
        policy=LocalPolicy(allow=cfg.local_policy or frozenset()),
        enclave_private_key=load_enclave_private_key(enclave_key_hex),
    )


def test_parse_listen_addr() -> None:
    assert parse_listen_addr("127.0.0.1:9443") == ("127.0.0.1", 9443)
    assert parse_listen_addr("0.0.0.0:8443") == ("0.0.0.0", 8443)


def test_parse_listen_addr_rejects_bad() -> None:
    with pytest.raises(ConfigError):
        parse_listen_addr("no-port")
    with pytest.raises(ConfigError):
        parse_listen_addr("host:abc")


def test_live_inbound_grants_and_emits_record() -> None:
    runtime = _runtime()
    resp = handle_jsonrpc(runtime, _envelope())
    assert resp.status_code == 200
    data = json.loads(resp.body)
    assert "result" in data
    ca2a = data["result"]["ca2a"]
    assert ca2a["granted_capability"] == "read"
    assert ca2a["effective_scope"] == ["read"]
    assert ca2a["record"]["record_id"] == "rec-live"
    assert isinstance(ca2a["record_hash"], str) and len(ca2a["record_hash"]) == 64


def test_live_inbound_denies_out_of_scope() -> None:
    runtime = _runtime(allow=["audit"])
    resp = handle_jsonrpc(runtime, _envelope(capability="read"))
    data = json.loads(resp.body)
    assert "error" in data
    assert data["error"]["data"]["ca2a_code"] == "SCOPE_NOT_PERMITTED"
    assert resp.status_code == 403


def test_ordinary_a2a_returns_null_ca2a() -> None:
    runtime = _runtime()
    resp = handle_jsonrpc(runtime, _envelope(include_ca2a=False))
    data = json.loads(resp.body)
    assert data["result"]["ca2a"] is None


def test_malformed_ca2a_metadata_fails_closed() -> None:
    runtime = _runtime()
    envelope = _envelope()
    envelope["params"]["message"]["metadata"][KEY_DELEGATION_CHAIN] = "not-a-list"
    resp = handle_jsonrpc(runtime, envelope)
    data = json.loads(resp.body)
    assert data["error"]["data"]["ca2a_code"] == "TRANSPORT_ERROR"
    assert resp.status_code == 400


def test_sealed_payload_opens_with_configured_key() -> None:
    priv, pub_hex = generate_channel_keypair()
    sealed = SealedChannel(pub_hex).seal(b"secret-task")
    sealed_b64 = base64.urlsafe_b64encode(sealed).decode("ascii").rstrip("=")
    key_hex = priv.private_bytes_raw().hex()
    runtime = _runtime(enclave_key_hex=key_hex)

    resp = handle_jsonrpc(runtime, _envelope(sealed_b64=sealed_b64))
    data = json.loads(resp.body)
    assert data["result"]["ca2a"]["payload"] == base64.urlsafe_b64encode(b"secret-task").decode(
        "ascii"
    ).rstrip("=")


def test_sealed_payload_without_key_fails_closed() -> None:
    priv, pub_hex = generate_channel_keypair()
    sealed = SealedChannel(pub_hex).seal(b"secret-task")
    sealed_b64 = base64.urlsafe_b64encode(sealed).decode("ascii").rstrip("=")
    runtime = _runtime()  # no enclave key

    resp = handle_jsonrpc(runtime, _envelope(sealed_b64=sealed_b64))
    data = json.loads(resp.body)
    assert data["error"]["data"]["ca2a_code"] == "SEALED_CHANNEL_ERROR"


def test_asgi_app_health_and_rpc() -> None:
    app = create_app(_runtime())
    client = TestClient(app)
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["status"] == "ok"

    rpc = client.post("/rpc", json=_envelope())
    assert rpc.status_code == 200
    assert rpc.json()["result"]["ca2a"]["granted_capability"] == "read"


@pytest.mark.asyncio
async def test_asgi_via_httpx() -> None:
    app = create_app(_runtime())
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/", json=_envelope())
    assert resp.status_code == 200
    assert resp.json()["result"]["ca2a"]["granted_capability"] == "read"


def test_method_not_found() -> None:
    runtime = _runtime()
    resp = handle_jsonrpc(
        runtime,
        {"jsonrpc": "2.0", "id": "1", "method": "tasks/get", "params": {}},
    )
    data = json.loads(resp.body)
    assert data["error"]["code"] == -32601
