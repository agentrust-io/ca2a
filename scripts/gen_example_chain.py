#!/usr/bin/env python3
"""Generate examples/minimal/chain.json: a valid three-hop delegation chain.

Deterministic keys are not used; a fresh chain is produced each run. The output
is what `ca2a verify-chain --chain examples/minimal/chain.json` verifies.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from ca2a_runtime.delegation import DelegationCredential, new_keypair  # noqa: E402

REPO_ROOT = Path(__file__).parent.parent


def build() -> list[dict[str, object]]:
    scopes = [
        frozenset({"cap:read", "cap:write", "cap:admin"}),
        frozenset({"cap:read", "cap:write"}),
        frozenset({"cap:read"}),
    ]
    out: list[dict[str, object]] = []
    priv, pub = new_keypair()
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{depth}",
            issuer=pub,
            subject=next_pub,
            scope=scope,
            depth=depth,
            parent_id=parent_id,
        ).sign(priv)
        out.append(cred.body() | {"signature": cred.signature})
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return out


def main() -> None:
    chain = build()
    dest = REPO_ROOT / "examples" / "minimal" / "chain.json"
    dest.write_text(json.dumps({"chain": chain}, indent=2), encoding="utf-8")
    print(f"wrote {dest}")


if __name__ == "__main__":
    main()
