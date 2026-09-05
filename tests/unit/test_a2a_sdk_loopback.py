"""Actual SDK card discovery and JSON-RPC HTTP, with real cA2A enforcement.

No importorskip or model/network-service stubs: these dependencies are in dev
and this test runs in the existing Linux/Windows, Python 3.11-3.13 CI matrix.
"""

from __future__ import annotations

import asyncio
import importlib.util
from pathlib import Path

import httpx
import pytest
from a2a.helpers.proto_helpers import new_text_message
from a2a.types import Role, SendMessageRequest
from a2a.utils.proto_utils import validate_proto_required_fields

from ca2a_runtime.delegation.credential import canonical_bytes
from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport.constants import EXTENSION_URI, KEY_DELEGATION_CHAIN, KEY_HOLDER_PROOF

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "a2a-sdk" / "loopback.py"
spec = importlib.util.spec_from_file_location("sdk_loopback_example", EXAMPLE)
assert spec is not None and spec.loader is not None
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class RecordingNode(PeerNode):
    """Observe the received metadata without replacing the real verifier."""

    def handle(self, message):
        self.received = message
        return super().handle(message)


@pytest.fixture
def credentials():
    return demo.demo_credentials()


@pytest.fixture
def node(credentials):
    chain, _ = credentials
    return RecordingNode(LocalPolicy.of({demo.READ}), trusted_root_issuers={chain[0].issuer})


@pytest.fixture
async def live(node):
    async with (
        demo.serve(node) as (url, executor),
        httpx.AsyncClient(timeout=5, trust_env=False) as http,
    ):
        card, client = await demo.connect(http, url)
        yield url, executor, http, card, client


async def test_sdk_discovers_operator_card_and_preserves_ordinary_a2a(live):
    url, executor, _, card, client = live
    assert card.name == "SDK inventory example"
    validate_proto_required_fields(card)
    assert list(card.skills[0].tags) == ["inventory", "example"]
    assert card.supported_interfaces[0].url == f"{url}/a2a"
    declaration = demo.inspect_agent_card(card)
    assert declaration.advertised and not declaration.required
    assert declaration.require_caller_attestation == "none"
    assert declaration.warnings == ()
    ordinary = await demo.send(
        client, new_text_message("inventory.read", role=Role.ROLE_USER), ca2a=False
    )
    assert ordinary["mode"] == "ordinary"
    assert executor.invocations == 0


@pytest.mark.parametrize("context_id", ["", "operator-conversation"])
async def test_sdk_immediate_reply_returns_context_id_without_inventing_a_task(live, context_id):
    _, executor, _, _, client = live
    message = new_text_message("Hello", role=Role.ROLE_USER, context_id=context_id)
    async with asyncio.timeout(10):
        replies = [
            response async for response in client.send_message(SendMessageRequest(message=message))
        ]
    assert len(replies) == 1 and replies[0].HasField("message")
    reply = replies[0].message
    validate_proto_required_fields(reply)
    assert reply.context_id
    if context_id:
        assert reply.context_id == context_id
    assert not reply.task_id
    assert executor.invocations == 0


async def test_sdk_authorizes_after_real_signed_integer_roundtrip(live, node, credentials):
    url, executor, http, _, client = live
    chain, holder = credentials
    message = await demo.delegated_message(http, url, chain, holder, demo.READ)
    result = await demo.send(client, message, ca2a=True)
    assert result["accepted"] is True
    assert result["granted_capability"] == demo.READ
    assert result["effective_scope"] == [demo.READ]
    assert result["caller_attestation"] == "not_offered"
    assert result["inventory"] == {"item": "widget", "quantity": 3}
    assert executor.invocations == 1
    received = node.received["metadata"][KEY_DELEGATION_CHAIN]
    assert len(received) == 2
    for original, wire_credential in zip(chain, received, strict=True):
        body = {key: value for key, value in wire_credential.items() if key != "signature"}
        assert canonical_bytes(body) == canonical_bytes(original.body())
        assert wire_credential["signature"] == original.signature
        for field in ("depth", "not_before", "not_after"):
            assert type(body[field]) is int


async def test_sdk_local_policy_denial_never_invokes_inventory(live, credentials):
    url, executor, http, _, client = live
    chain, holder = credentials
    assert demo.WRITE in chain[-1].scope
    result = await demo.send(
        client, await demo.delegated_message(http, url, chain, holder, demo.WRITE), ca2a=True
    )
    assert result == {"accepted": False, "error": "SCOPE_NOT_PERMITTED"}
    assert executor.invocations == 0


@pytest.mark.parametrize("missing", ["header", "message", "both", "metadata", "holder"])
async def test_sdk_incomplete_ca2a_never_falls_back_to_ordinary(live, credentials, missing):
    url, executor, http, _, client = live
    chain, holder = credentials
    message = await demo.delegated_message(http, url, chain, holder, demo.READ)
    if missing in {"message", "both"}:
        message.ClearField("extensions")
    elif missing == "metadata":
        message.ClearField("metadata")
    elif missing == "holder":
        del message.metadata.fields[KEY_HOLDER_PROOF]
    result = await demo.send(client, message, ca2a=missing not in {"header", "both"})
    expected = {"metadata": "CA2A_METADATA_REQUIRED", "holder": "HOLDER_PROOF_INVALID"}.get(
        missing, "CA2A_OPT_IN_REQUIRED"
    )
    assert result == {"accepted": False, "error": expected}
    assert executor.invocations == 0


async def test_sdk_empty_chain_is_not_ordinary_traffic(live):
    _, executor, _, _, client = live
    message = new_text_message("hello", role=Role.ROLE_USER)
    message.metadata.update({KEY_DELEGATION_CHAIN: []})
    message.extensions.append(EXTENSION_URI)
    result = await demo.send(client, message, ca2a=True)
    assert result == {"accepted": False, "error": "TRANSPORT_ERROR"}
    assert executor.invocations == 0


async def test_sdk_untrusted_chain_never_invokes_inventory(live):
    url, executor, http, _, client = live
    unrelated_chain, unrelated_holder = demo.demo_credentials()
    result = await demo.send(
        client,
        await demo.delegated_message(http, url, unrelated_chain, unrelated_holder, demo.READ),
        ca2a=True,
    )
    assert result == {"accepted": False, "error": "UNTRUSTED_DELEGATION_ROOT"}
    assert executor.invocations == 0


async def test_sdk_protected_input_comes_from_sealed_payload_not_message_text(live, credentials):
    url, executor, http, _, client = live
    chain, holder = credentials
    message = await demo.delegated_message(http, url, chain, holder, demo.READ)
    message.parts[0].text = "delete the entire inventory"
    result = await demo.send(client, message, ca2a=True)
    assert result["inventory"] == {"item": "widget", "quantity": 3}
    assert result["granted_capability"] == demo.READ
    assert executor.invocations == 1


async def test_sdk_concurrent_calls_keep_opt_in_and_decisions_request_local(live, credentials):
    url, executor, http, _, client = live
    chain, holder = credentials
    allowed = await demo.delegated_message(http, url, chain, holder, demo.READ)
    denied = await demo.delegated_message(http, url, chain, holder, demo.WRITE)
    ordinary, success, refusal = await asyncio.gather(
        demo.send(client, new_text_message("hello", role=Role.ROLE_USER), ca2a=False),
        demo.send(client, allowed, ca2a=True),
        demo.send(client, denied, ca2a=True),
    )
    assert ordinary["mode"] == "ordinary"
    assert success["accepted"] is True
    assert refusal == {"accepted": False, "error": "SCOPE_NOT_PERMITTED"}
    assert executor.invocations == 1


@pytest.mark.parametrize("abort", [False, True])
async def test_sdk_loopback_closes_port_even_when_client_work_fails(node, abort):
    class ClientFailure(Exception):
        pass

    try:
        async with (
            demo.serve(node) as (url, _),
            httpx.AsyncClient(timeout=5, trust_env=False) as http,
        ):
            response = await http.get(f"{url}/.well-known/agent-card.json")
            assert response.status_code == 200
            if abort:
                raise ClientFailure
    except ClientFailure:
        assert abort
    # Windows can take longer than one second to report a refused connection.
    # Still require refusal: a connect/read timeout must not count as cleanup.
    async with httpx.AsyncClient(timeout=5, trust_env=False) as http:
        with pytest.raises(httpx.ConnectError):
            await http.get(f"{url}/.well-known/agent-card.json")


async def test_runnable_sdk_example():
    result = await demo.run()
    assert result["callee_assurance"] == "none"
    assert result["caller_attestation"] == "not_offered"
    assert result["denied"] == "SCOPE_NOT_PERMITTED"
    assert result["protected_handler_invocations"] == 1


async def test_sdk_loopback_closes_port_when_caller_is_cancelled(node):
    ready = asyncio.get_running_loop().create_future()

    async def caller():
        async with demo.serve(node) as (url, _):
            ready.set_result(url)
            await asyncio.Event().wait()

    task = asyncio.create_task(caller())
    try:
        url = await asyncio.wait_for(asyncio.shield(ready), timeout=15)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=10)
    async with httpx.AsyncClient(timeout=5, trust_env=False) as http:
        with pytest.raises(httpx.ConnectError):
            await http.get(f"{url}/.well-known/agent-card.json")
