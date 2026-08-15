#!/usr/bin/env python3
"""cA2A peer A, inside a real AMD SEV-SNP confidential VM (Azure DCasv5).

Calls peer B, which runs inside a real Intel TDX confidential VM in a different
cloud under a different operator. A appraises B's genuine TDX quote before
sealing anything to it, then makes a delegated cA2A call across the two trust
domains and checks that an over-scoped call is refused with evidence.

This is the cross-operator, cross-TEE-family case: neither side trusts the other's
operator, and the two attestation formats are unrelated (AMD VCEK chain versus
Intel PCK chain).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
import urllib.request

sys.path.insert(0, os.path.expanduser("~/src"))

from cryptography import x509  # noqa: E402

from ca2a_runtime.channel import SealedChannel  # noqa: E402
from ca2a_runtime.delegation import DelegationCredential, new_keypair  # noqa: E402
from ca2a_verify.tdx import verify_tdx_quote  # noqa: E402

PEER = os.environ["PEER_URL"]
INTEL_ROOT = os.path.expanduser("~/src/../intel_root.pem")
out: dict[str, object] = {"peer": PEER}


def http(method: str, path: str, body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        PEER + path, data=data, method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=60) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def build_chain(scopes):
    chain, parent = [], None
    priv, pub = new_keypair()
    for depth, scope in enumerate(scopes):
        npriv, npub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{depth}", issuer=pub, subject=npub,
            scope=scope, depth=depth, parent_id=parent,
        ).sign(priv)
        chain.append(cred)
        parent = cred.credential_id
        priv, pub = npriv, npub
    return chain


def main() -> int:
    # 1. Appraise peer B's TDX attestation under a nonce we choose.
    nonce = hashlib.sha256(b"cross-tee-run").hexdigest()
    status, offer = http("GET", f"/attest?nonce={nonce}")
    out["offer_status"] = status
    out["peer_platform"] = offer.get("platform")

    quote = base64.b64decode(offer["quote_b64"])
    out["tdx_quote_bytes"] = len(quote)

    with open(INTEL_ROOT, "rb") as f:
        intel_root = x509.load_pem_x509_certificates(f.read())[0]

    expected = hashlib.sha256(
        bytes.fromhex(offer["channel_public_key"]) + bytes.fromhex(nonce)
    ).digest()
    parsed = verify_tdx_quote(
        quote, trusted_roots=[intel_root], expected_report_data=expected.ljust(64, b"\x00")
    )
    out["tdx_verified"] = True
    out["peer_mrtd"] = parsed.measurement.hex()
    out["peer_channel_key_bound_to_quote"] = True

    # A wrong nonce must not appraise: freshness is enforced, not assumed.
    try:
        verify_tdx_quote(
            quote, trusted_roots=[intel_root],
            expected_report_data=hashlib.sha256(b"wrong").digest().ljust(64, b"\x00"),
        )
        out["stale_nonce_rejected"] = False
    except Exception:  # noqa: BLE001
        out["stale_nonce_rejected"] = True

    # 2. Seal a delegated task to the key that quote vouches for.
    peer_pub = offer["channel_public_key"]
    chain = build_chain([
        frozenset({"task:read", "tool:search", "tool:purchase"}),
        frozenset({"task:read", "tool:search"}),
    ])
    payload = b'{"task":"search","q":"confidential cross-TEE"}'
    sealed = SealedChannel(peer_pub).seal(payload)
    out["sealed_bytes"] = len(sealed)

    status, res = http("POST", "/call", {
        "delegation_chain": [{**c.body(), "signature": c.signature} for c in chain],
        "requested_capability": "tool:search",
        "record_id": "rec-xtee-0",
        "sealed_payload": base64.b64encode(sealed).decode(),
    })
    out["allowed_call"] = {"status": status, **res}

    # 3. An over-scoped call must be refused, with a record explaining why.
    sealed2 = SealedChannel(peer_pub).seal(b'{"task":"buy"}')
    status, res = http("POST", "/call", {
        "delegation_chain": [{**c.body(), "signature": c.signature} for c in chain],
        "requested_capability": "tool:purchase",
        "record_id": "rec-xtee-1",
        "sealed_payload": base64.b64encode(sealed2).decode(),
    })
    out["denied_call"] = {"status": status, **res}

    print(json.dumps(out, indent=2, default=str))
    ok = (
        out.get("tdx_verified")
        and out.get("stale_nonce_rejected")
        and out["allowed_call"].get("outcome") == "allow"
        and out["denied_call"].get("outcome") == "deny"
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
