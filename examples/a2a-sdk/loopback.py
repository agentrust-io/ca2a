"""Official A2A SDK JSON-RPC loopback; software-only, no external services.

The application owns card serving, extension opt-in and the protected handler.
cA2A supplies the existing chain/proof/policy/sealing pipeline. This is an
integration example, not a production server or an A2A conformance harness.
"""

from __future__ import annotations

import asyncio
import json
import socket
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from typing import Any
from uuid import uuid4

import httpx
import uvicorn
from a2a.client import A2ACardResolver, Client, ClientConfig, ClientFactory
from a2a.client.client import ClientCallContext
from a2a.client.service_parameters import ServiceParametersFactory, with_a2a_extensions
from a2a.helpers.proto_helpers import new_data_message, new_text_message
from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.routes import create_agent_card_routes, create_jsonrpc_routes
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentInterface,
    AgentSkill,
    Message,
    Role,
    SendMessageRequest,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from google.protobuf import json_format
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from ca2a_runtime.attestation import seal_to_peer, verify_offer
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.delegation.holder import build_holder_proof
from ca2a_runtime.errors import CA2AError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import PeerRequest
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport.a2a_adapter import has_ca2a_metadata
from ca2a_runtime.transport.a2a_sdk import (
    attach_to_sdk_message,
    inspect_agent_card,
    merge_agent_card,
    metadata_from_sdk_message,
)
from ca2a_runtime.transport.constants import EXTENSION_URI
from ca2a_runtime.transport.wire import (
    parse_challenge,
    parse_channel_offer,
    serialize_channel_offer,
    serialize_peer_result,
)

READ = "inventory.read"
WRITE = "inventory.write"


def demo_credentials() -> tuple[list[DelegationCredential], Ed25519PrivateKey]:
    """Generate two signed hops; no long-lived keys or credentials on disk."""
    issuer_key, issuer = new_keypair()
    chain: list[DelegationCredential] = []
    now = int(time.time())
    for depth in range(2):
        holder_key, subject = new_keypair()
        credential = DelegationCredential(
            credential_id=uuid4().hex,
            issuer=issuer,
            subject=subject,
            scope=frozenset({READ, WRITE}),
            depth=depth,
            parent_id=chain[-1].credential_id if chain else None,
            not_before=now - 1,
            not_after=now + 300,
        ).sign(issuer_key)
        chain.append(credential)
        issuer_key, issuer = holder_key, subject
    return chain, holder_key


class InventoryExecutor(AgentExecutor):
    """The ordinary branch has no route to the protected inventory handler."""

    def __init__(self, node: PeerNode) -> None:
        self.node = node
        self.invocations = 0

    def reply(self, message: Message, requested_extensions: set[str]) -> dict[str, Any]:
        metadata = metadata_from_sdk_message(message)
        declared = EXTENSION_URI in message.extensions
        requested = EXTENSION_URI in requested_extensions
        carries_ca2a = has_ca2a_metadata(metadata)
        if not carries_ca2a and not declared and not requested:
            return {"mode": "ordinary", "message": "Public demo information; no inventory access."}
        # Both opt-in surfaces are this example's operator policy. Metadata
        # cannot silently fall back to the ordinary handler when opt-in is absent.
        if not declared or not requested:
            return {"accepted": False, "error": "CA2A_OPT_IN_REQUIRED"}
        if not carries_ca2a:
            return {"accepted": False, "error": "CA2A_METADATA_REQUIRED"}
        try:
            result = self.node.handle({"metadata": metadata})
        except CA2AError as exc:
            return {"accepted": False, "error": exc.code}
        # Holder proofs bind the sealed payload, NOT arbitrary A2A message.parts.
        # Only the returned, authorized plaintext can select the demo input.
        if result.granted_capability != READ or result.payload != b"widget":
            return {"accepted": False, "error": "UNSUPPORTED_DEMO_INPUT"}
        body = serialize_peer_result(result)
        body["inventory"] = self._lookup()
        return body

    def _lookup(self) -> dict[str, Any]:
        self.invocations += 1
        return {"item": "widget", "quantity": 3}

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.message is None:
            body = {"accepted": False, "error": "MESSAGE_REQUIRED"}
        else:
            body = self.reply(context.message, context.requested_extensions)
        await event_queue.enqueue_event(new_data_message(body, context_id=context.context_id))

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        # This immediate-message example creates no cancellable long-lived tasks.
        raise NotImplementedError("The demo has no long-lived tasks")


def operator_card(base_url: str, node: PeerNode) -> AgentCard:
    return merge_agent_card(
        AgentCard(
            name="SDK inventory example",
            description="Public information plus cA2A-authorized demo inventory reads",
            version="1.0.0",
            supported_interfaces=[
                AgentInterface(
                    url=f"{base_url}/a2a", protocol_binding="JSONRPC", protocol_version="1.0"
                )
            ],
            capabilities=AgentCapabilities(streaming=False),
            default_input_modes=["text/plain"],
            default_output_modes=["application/json"],
            skills=[
                AgentSkill(
                    id="inventory",
                    name="Demo inventory",
                    description="Read widget stock",
                    tags=["inventory", "example"],
                )
            ],
        ),
        node,
    )


@asynccontextmanager
async def serve(node: PeerNode) -> AsyncIterator[tuple[str, InventoryExecutor]]:
    """Start one real SDK HTTP server on a reserved loopback socket; always stop."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    handler: DefaultRequestHandler | None = None
    server_task: asyncio.Task[None] | None = None
    try:
        sock.bind(("127.0.0.1", 0))
        base_url = f"http://127.0.0.1:{sock.getsockname()[1]}"
        executor = InventoryExecutor(node)
        card = operator_card(base_url, node)
        handler = DefaultRequestHandler(executor, InMemoryTaskStore(), card)

        async def channel(request: Request) -> JSONResponse:
            nonce = request.query_params.get("nonce", "")
            if not nonce or len(nonce) > 128:
                return JSONResponse({"error": "NONCE_REQUIRED"}, status_code=400)
            return JSONResponse(
                serialize_channel_offer(node.offer(nonce), challenge=node.issue_challenge())
            )

        app = Starlette(
            routes=[
                *create_agent_card_routes(card),
                *create_jsonrpc_routes(handler, rpc_url="/a2a"),
                # Demo bootstrap, not an upstream A2A or cA2A-profile endpoint.
                Route("/demo/channel", channel),
            ]
        )
        server = uvicorn.Server(
            uvicorn.Config(
                app,
                log_config=None,
                access_log=False,
                lifespan="on",
                loop="asyncio",
                http="h11",
                ws="none",
                workers=1,
                timeout_graceful_shutdown=2,
            )
        )
        server_task = asyncio.create_task(server.serve(sockets=[sock]))
        async with asyncio.timeout(10):
            while not server.started:
                if server_task.done():
                    await server_task
                    raise RuntimeError("SDK server stopped before startup")
                await asyncio.sleep(0.01)
        try:
            yield base_url, executor
        finally:
            server.should_exit = True
            await asyncio.wait_for(asyncio.shield(server_task), timeout=5)
    finally:
        if server_task is not None and not server_task.done():
            server_task.cancel()
            with suppress(asyncio.CancelledError):
                await server_task
        sock.close()
        if handler is not None:
            await asyncio.wait_for(handler.aclose(), timeout=5)


async def connect(http: httpx.AsyncClient, base_url: str) -> tuple[AgentCard, Client]:
    card = await A2ACardResolver(http, base_url).get_agent_card()
    discovery = inspect_agent_card(card)
    if not discovery.advertised or discovery.warnings:
        raise RuntimeError("The demo requires an unambiguous cA2A declaration")
    client = ClientFactory(ClientConfig(httpx_client=http, streaming=False)).create(card)
    return card, client


async def delegated_message(
    http: httpx.AsyncClient,
    base_url: str,
    chain: list[DelegationCredential],
    holder_key: Ed25519PrivateKey,
    capability: str,
) -> Message:
    nonce = uuid4().hex
    response = await http.get(f"{base_url}/demo/channel", params={"nonce": nonce})
    response.raise_for_status()
    exchange = response.json()
    peer = verify_offer(parse_channel_offer(exchange), expected_nonce=nonce)
    if peer.assurance != "none":
        raise RuntimeError("This example intentionally uses software-only assurance")
    challenge = parse_challenge(exchange)
    if challenge is None:
        raise RuntimeError("The demo server did not issue a holder challenge")
    sealed = seal_to_peer(peer, b"widget")
    record_id = uuid4().hex
    proof = build_holder_proof(
        holder_key,
        chain[-1],
        audience=peer.public_key,
        challenge=challenge,
        requested_capability=capability,
        record_id=record_id,
        sealed_payload=sealed,
    )
    request = PeerRequest(
        chain=chain,
        requested_capability=capability,
        record_id=record_id,
        sealed_payload=sealed,
        holder_proof=proof,
    )
    return attach_to_sdk_message(
        new_text_message("Use only the bound sealed payload", role=Role.ROLE_USER), request
    )


async def send(client: Client, message: Message, *, ca2a: bool) -> dict[str, Any]:
    context = ClientCallContext(timeout=5)
    if ca2a:
        context.service_parameters = ServiceParametersFactory.create(
            [with_a2a_extensions([EXTENSION_URI])]
        )
    replies = []
    async with asyncio.timeout(10):
        async for response in client.send_message(
            SendMessageRequest(message=message), context=context
        ):
            if not response.HasField("message"):
                raise RuntimeError("Expected an immediate SDK message, not a task")
            replies.append(response.message)
    if len(replies) != 1 or len(replies[0].parts) != 1 or not replies[0].parts[0].HasField("data"):
        raise RuntimeError("Expected exactly one structured SDK reply")
    return json_format.MessageToDict(replies[0].parts[0].data)


async def run() -> dict[str, Any]:
    chain, holder_key = demo_credentials()
    node = PeerNode(LocalPolicy.of({READ}), trusted_root_issuers={chain[0].issuer})
    async with (
        serve(node) as (base_url, executor),
        httpx.AsyncClient(timeout=5, trust_env=False) as http,
    ):
        card, client = await connect(http, base_url)
        ordinary = await send(client, new_text_message("Hello", role=Role.ROLE_USER), ca2a=False)
        allowed = await send(
            client, await delegated_message(http, base_url, chain, holder_key, READ), ca2a=True
        )
        denied = await send(
            client, await delegated_message(http, base_url, chain, holder_key, WRITE), ca2a=True
        )
        if ordinary.get("mode") != "ordinary" or allowed.get("accepted") is not True:
            raise RuntimeError("Ordinary or delegated SDK call failed")
        if denied.get("error") != "SCOPE_NOT_PERMITTED" or executor.invocations != 1:
            raise RuntimeError("Local policy refusal did not preserve the handler boundary")
        return {
            "agent": card.name,
            "transport": "a2a-sdk JSON-RPC loopback",
            "callee_assurance": "none",
            "caller_attestation": allowed["caller_attestation"],
            "ordinary": ordinary["mode"],
            "allowed": allowed["inventory"],
            "denied": denied["error"],
            "protected_handler_invocations": executor.invocations,
        }


if __name__ == "__main__":
    print(json.dumps(asyncio.run(run()), indent=2))
