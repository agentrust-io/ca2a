#!/usr/bin/env python3
"""Claim 3: effective permission is the delegated scope intersected with the
callee's local policy. A peer can exercise a capability only if BOTH its
delegation chain granted it AND the callee's local policy allows it.

Software experiment using the enforcement decision core in ca2a_runtime.peer.
This uses LocalPolicy; tests/unit/test_cedar.py exercises the Cedar engine.
"""
# ruff: noqa: T201
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ca2a_runtime.delegation import DelegationCredential, new_keypair  # noqa: E402
from ca2a_runtime.errors import ScopeNotPermitted  # noqa: E402
from ca2a_runtime.peer import effective_scope, enforce_peer_call  # noqa: E402
from ca2a_runtime.policy import LocalPolicy  # noqa: E402


def build_chain(scopes: list[frozenset[str]]) -> tuple[list[DelegationCredential], str]:
    chain: list[DelegationCredential] = []
    priv, pub = new_keypair()
    trusted_root = pub  # Retain the local fixture authority separately.
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{depth}", issuer=pub, subject=next_pub,
            scope=scope, depth=depth, parent_id=parent_id,
        ).sign(priv)
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain, trusted_root


def main() -> int:
    # Delegated down to a leaf scope of {read, write}; the root held admin too.
    chain, trusted_root = build_chain([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])
    # The callee's local policy allows {read, audit}. Note write is delegated but
    # not locally allowed, and audit is locally allowed but never delegated.
    policy = LocalPolicy.of(["read", "audit"])

    eff = effective_scope(chain, policy, trusted_root_issuers={trusted_root})
    print("Claim 3: effective permission = delegated scope INTERSECT local policy")
    print(f"  leaf delegated scope: {sorted(chain[-1].scope)}")
    print(f"  local policy allows:  {sorted(policy.allow)}")
    print(f"  effective scope:      {sorted(eff)}")

    cases = {
        "read": True,    # delegated and allowed
        "write": False,  # delegated but not locally allowed
        "audit": False,  # locally allowed but not delegated
        "admin": False,  # neither at the leaf nor allowed
    }
    allowed = denied = 0
    for cap, expect_allowed in cases.items():
        try:
            enforce_peer_call(chain, cap, policy=policy, record_id="rec-0",
                              trusted_root_issuers={trusted_root})
            got = True
        except ScopeNotPermitted:
            got = False
        ok = got == expect_allowed
        print(f"  request {cap:<6} -> {'ALLOW' if got else 'DENY '}  {'OK' if ok else 'WRONG'}")
        if not ok:
            print("KEY RESULT: FAIL (enforcement did not match the intersection)")
            return 1
        allowed += got
        denied += not got

    print(f"KEY RESULT: effective scope {sorted(eff)}; {allowed}/1 allowed, {denied}/3 denied; "
          "capability granted only when delegated AND locally permitted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
