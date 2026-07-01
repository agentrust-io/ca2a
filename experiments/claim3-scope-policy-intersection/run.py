"""
Delegated scope intersected with local Cedar policy (cA2A Claim 3).

STATUS: SKIP (gated on Tier 2).

The effective capability set a caller may exercise against a peer is the
intersection of its verified delegated scope with the callee's local Cedar
policy. This experiment cannot run yet because two runtime pieces are missing:

  1. Runtime peer-delegation enforcement. ca2a_runtime.delegation.verify_chain
     validates a delegation chain (signature, continuity, attenuation,
     anti-replay), but nothing gates an actual peer-to-peer call at request
     time, so there is no enforcement point at which to apply a local decision.
  2. Cedar intersection. There is no wiring from a verified delegated scope to a
     local Cedar policy engine, so the effective-permission computation
     (delegated scope AND local policy) does not exist.

Both land in Tier 2. See ROADMAP.md.

This script is safe to run anywhere: it prints a SKIP banner and exits 0, so it
never breaks CI or a laptop. It also prints a tiny illustrative set-intersection
against a mock local policy to show the intended shape. That block is
illustrative only and is NOT the Cedar engine.

Running:
  pip install -e .
  python experiments/claim3-scope-policy-intersection/run.py
"""

from __future__ import annotations

import sys

# Imported to prove the delegation primitive this claim will build on exists and
# resolves, even though the enforcement/intersection path around it is not built.
from ca2a_runtime.delegation import DelegationCredential, new_keypair  # noqa: F401


def _illustrative_intersection() -> None:
    """Show the intended effective-permission shape. NOT the Cedar engine.

    Real Tier 2 code would compute this from a verified delegated scope and a
    Cedar policy decision, not from two hard-coded literal sets.
    """
    delegated = frozenset({"cap:read", "cap:write", "cap:admin"})
    local_policy = frozenset({"cap:read", "cap:write", "cap:audit"})
    effective = delegated & local_policy

    print("Illustrative only (NOT the Cedar engine):")
    print(f"  delegated scope       : {{{', '.join(sorted(delegated))}}}")
    print(f"  local policy          : {{{', '.join(sorted(local_policy))}}}")
    print(f"  effective (intersect) : {{{', '.join(sorted(effective))}}}")
    print(f"  dropped by policy     : {{{', '.join(sorted(delegated - local_policy))}}}")
    print(f"  dropped by delegation : {{{', '.join(sorted(local_policy - delegated))}}}")


def main() -> int:
    print()
    print("Delegated scope intersected with local Cedar policy | Claim 3")
    print("=" * 72)
    print()
    print("SKIP: Tier 2 runtime scope-policy intersection is not implemented.")
    print("  - runtime peer-delegation enforcement not built (no call-time gate)")
    print("  - Cedar intersection not wired (no delegated-scope AND local-policy path)")
    print("See ROADMAP.md. Exiting 0 so CI and dev hosts pass.")
    print()
    _illustrative_intersection()
    print()
    print("KEY RESULT: SKIP (gated on Tier 2). Effective permission = delegated scope")
    print("            intersected with local Cedar policy; enforcement path not built.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
