"""Python-issued ephemeral proofs through the official TS SDK into Python.

This supplemental JSON-RPC probe is separate from ITK traversal. It does not
claim TypeScript credential issuance or hardware attestation interoperability.
"""

import argparse
import asyncio
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

import httpx
from a2a.helpers.proto_helpers import new_text_message
from a2a.types import Role
from google.protobuf import json_format

from ca2a_runtime.delegation.credential import canonical_bytes
from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.transport.constants import EXTENSION_URI, KEY_DELEGATION_CHAIN

parser = argparse.ArgumentParser()
parser.add_argument("--workspace", type=Path, required=True)
parser.add_argument("--node", required=True)
args = parser.parse_args()
root = args.workspace.resolve()
here = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location(
    "demo", here.parents[1] / "examples/a2a-sdk/loopback.py"
)
demo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(demo)


class RecordingNode(PeerNode):
    def handle(self, message):
        self.received = message
        return super().handle(message)


async def main():
    chain, holder = demo.demo_credentials()
    node = RecordingNode(LocalPolicy.of({demo.READ}), trusted_root_issuers={chain[0].issuer})
    results = {}
    async with (
        demo.serve(node) as (url, executor),
        httpx.AsyncClient(timeout=5, trust_env=False) as http,
    ):

        async def send(message, opt_in=True):
            payload = json.dumps(
                {
                    "url": url,
                    "message": json_format.MessageToDict(message),
                    "extension": EXTENSION_URI,
                    "optIn": opt_in,
                }
            )
            proc = await asyncio.create_subprocess_exec(
                args.node,
                "--import",
                (root / "node_modules/tsx/dist/loader.mjs").as_uri(),
                str(here / "ts_client.mts"),
                str(root / "a2a-js"),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0,
            )
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(payload.encode()), timeout=20
                )
            except BaseException:
                if proc.returncode is None:
                    proc.kill()
                    await proc.wait()
                raise
            if proc.returncode:
                raise RuntimeError(stderr.decode())
            response = json.loads(stdout)
            return response["parts"][0]["data"]

        ordinary = await send(new_text_message("Hello", role=Role.ROLE_USER), False)
        assert ordinary["mode"] == "ordinary" and executor.invocations == 0
        results["ordinary"] = {"passed": True, "mode": ordinary["mode"]}
        message = await demo.delegated_message(http, url, chain, holder, demo.READ)
        allowed = await send(message)
        assert allowed["accepted"] is True and allowed["granted_capability"] == demo.READ
        assert allowed["caller_attestation"] == "not_offered" and executor.invocations == 1
        received = node.received["metadata"][KEY_DELEGATION_CHAIN]
        for original, wire in zip(chain, received, strict=True):
            assert wire["signature"] == original.signature
            assert canonical_bytes(
                {k: v for k, v in wire.items() if k != "signature"}
            ) == canonical_bytes(original.body())
            assert all(type(wire[k]) is int for k in ["depth", "not_before", "not_after"])
        results["signed_read"] = {
            "passed": True,
            "canonical_credentials_preserved": True,
            "hops": len(received),
            "caller_attestation": allowed["caller_attestation"],
        }
        replay = await send(message)
        results["duplicate_message_observation"] = {
            "accepted": replay.get("accepted"),
            "error": replay.get("error"),
            "protected_handler_invocations": executor.invocations,
        }
        assert replay.get("accepted") is True and executor.invocations == 2
        message.message_id = uuid4().hex
        replay = await send(message)
        assert replay.get("accepted") is True and executor.invocations == 3, (
            replay,
            executor.invocations,
        )
        results["replay_observation"] = {
            "accepted": True,
            "protected_handler_invocations": executor.invocations,
            "limit": "Stateless challenge permits reuse before expiry, even with a new A2A message ID.",
        }
        for name, capability, opt_in, mutate, expected in [
            ("policy_denial", demo.WRITE, True, None, "SCOPE_NOT_PERMITTED"),
            ("missing_header", demo.READ, False, None, "CA2A_OPT_IN_REQUIRED"),
            ("fractional_depth", demo.READ, True, "fraction", None),
            ("tampered_signature", demo.READ, True, "signature", None),
        ]:
            message = await demo.delegated_message(http, url, chain, holder, capability)
            if mutate:
                metadata = json_format.MessageToDict(message.metadata)
                credential = metadata[KEY_DELEGATION_CHAIN][0]
                if mutate == "fraction":
                    credential["depth"] = 0.5
                else:
                    signature = credential["signature"]
                    credential["signature"] = ("a" if signature[0] != "a" else "b") + signature[1:]
                message.metadata.Clear()
                message.metadata.update(metadata)
            reply = await send(message, opt_in)
            assert reply.get("accepted") is False and executor.invocations == 3, (name, reply)
            if expected:
                assert reply["error"] == expected, (name, reply)
            results[name] = {"passed": True, "error": reply["error"]}
    report = {
        "transport": "JSONRPC",
        "direction": "TypeScript SDK client to Python SDK 1.1.5 server",
        "credentials_issued_by": "Python cA2A",
        "callee_assurance": "none",
        "protected_handler_invocations": executor.invocations,
        "results": results,
    }
    (here / "results/protected-ts.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))


asyncio.run(main())
