#!/usr/bin/env python3
"""cA2A peer B, inside a real Intel TDX confidential VM (GCP C3).

Serves an attestation offer and an inbound cA2A peer call over HTTP. The offer
binds this enclave's X25519 channel public key into a genuine TDX quote's
REPORTDATA under the caller's nonce, so the caller can appraise the quote and
seal a task payload to a key only this measured guest holds.

Non-paravisor TDX, so REPORTDATA is guest-controlled: reportdata =
sha256(channel_pub || nonce). Quote via configfs-tsm.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, os.path.expanduser("~/src"))

from ca2a_runtime.channel import generate_channel_keypair, open_sealed  # noqa: E402
from ca2a_runtime.delegation import DelegationCredential  # noqa: E402
from ca2a_runtime.errors import CA2AError  # noqa: E402
from ca2a_runtime.peer import PeerRequest, handle_peer_request  # noqa: E402
from ca2a_runtime.policy import LocalPolicy  # noqa: E402

TSM = Path("/sys/kernel/config/tsm/report")
POLICY = LocalPolicy.of(["task:read", "tool:search", "tool:purchase"])

CHANNEL_PRIV, CHANNEL_PUB = generate_channel_keypair()


def tdx_quote(reportdata: bytes) -> bytes:
    """Generate a real TDX quote binding reportdata, via configfs-tsm."""
    d = TSM / f"r{uuid.uuid4().hex[:8]}"
    import subprocess

    subprocess.run(["sudo", "mkdir", "-p", str(d)], check=True)
    subprocess.run(
        ["sudo", "tee", str(d / "inblob")],
        input=reportdata.ljust(64, b"\x00"),
        check=True,
        capture_output=True,
    )
    out = subprocess.run(
        ["sudo", "cat", str(d / "outblob")], check=True, capture_output=True
    ).stdout
    subprocess.run(["sudo", "rmdir", str(d)], check=False)
    return out


def build_offer(nonce_hex: str) -> dict:
    """Channel key + a TDX quote that commits to it under the caller's nonce."""
    binding = hashlib.sha256(bytes.fromhex(CHANNEL_PUB) + bytes.fromhex(nonce_hex)).digest()
    quote = tdx_quote(binding)
    return {
        "platform": "tdx",
        "channel_public_key": CHANNEL_PUB,
        "nonce": nonce_hex,
        "reportdata_binding": "sha256(channel_pub || nonce)",
        "quote_b64": base64.b64encode(quote).decode(),
    }


class Handler(BaseHTTPRequestHandler):
    def _send(self, code: int, body: dict) -> None:
        raw = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, *a):  # quiet
        pass

    def do_GET(self):
        if self.path.startswith("/attest"):
            nonce = self.path.split("nonce=")[-1]
            try:
                self._send(200, build_offer(nonce))
            except Exception as exc:  # noqa: BLE001
                self._send(500, {"error": str(exc)})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        msg = json.loads(self.rfile.read(n) or b"{}")
        try:
            chain = [DelegationCredential.from_dict(c) for c in msg["delegation_chain"]]
            sealed = base64.b64decode(msg["sealed_payload"])
            request = PeerRequest(
                chain=chain,
                requested_capability=msg["requested_capability"],
                record_id=msg["record_id"],
                sealed_payload=sealed,
                parent_record_hash=msg.get("parent_record_hash"),
            )
            result = handle_peer_request(
                request, policy=POLICY, enclave_private_key=CHANNEL_PRIV
            )
            self._send(200, {
                "outcome": "allow",
                "granted": result.granted_capability,
                "effective_scope": sorted(result.effective_scope),
                "payload_opened_in_enclave": result.payload.decode(),
                "record": result.record.body(),
            })
        except CA2AError as exc:
            record = getattr(exc, "record", None)
            self._send(403, {
                "outcome": "deny",
                "code": exc.code,
                "error": str(exc),
                "record": record.body() if record is not None else None,
            })
        except Exception as exc:  # noqa: BLE001
            self._send(400, {"outcome": "error", "error": repr(exc)})


if __name__ == "__main__":
    print(f"channel_pub={CHANNEL_PUB}", flush=True)
    HTTPServer(("0.0.0.0", 8443), Handler).serve_forever()
