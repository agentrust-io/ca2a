#!/usr/bin/env python3
"""C1 at scale: attenuation soundness over many narrowing chains and escalation
attempts, swept across delegation-chain depth.

Extends experiments/claim1-attenuation-soundness/run.py from the shipped
ca2a_runtime package. For each depth d in a sweep, we generate TRIALS narrowing
chains (each hop a strict subset of its parent) and TRIALS escalation chains
(one interior hop adds a capability no ancestor held). We assert:

  * every narrowing chain is accepted by verify_chain;
  * every escalation chain is rejected, and rejected specifically with
    ScopeEscalation (not by some unrelated continuity error).

Writes a JSON summary to results/c1_attenuation_scale.json. Real numbers only:
every count is what verify_chain returned on this run.

Run from the paper directory, with CA2A_ROOT set to a ca2a checkout:
  PYTHONUTF8=1 python experiments/c1_attenuation_scale.py
"""
# ruff: noqa: T201
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

# CA2A_ROOT points at a ca2a checkout. This edition's rerun used the v0.3.1
# release, commit 7d90823142dda1be589def3b22a3099581c7df7a.
_CA2A_ROOT = Path(os.environ.get("CA2A_ROOT", "ca2a"))
_CODE_SRC = _CA2A_ROOT / "src"
if not (_CODE_SRC / "ca2a_runtime").is_dir():
    raise SystemExit("Set CA2A_ROOT to a ca2a checkout containing src/ca2a_runtime.")
sys.path.insert(0, str(_CODE_SRC))

from ca2a_runtime.delegation import (  # noqa: E402
    DelegationCredential,
    new_keypair,
    verify_chain,
)
from ca2a_runtime.errors import ScopeEscalation  # noqa: E402

TRIALS = 500
DEPTHS = [2, 3, 4, 6, 8]
# Root capability universe; wide enough to narrow across the deepest chain.
ROOT_CAPS = [f"cap:{i}" for i in range(16)]


def build_signed_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    chain: list[DelegationCredential] = []
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
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain


def narrowing_scopes(depth: int) -> list[frozenset[str]]:
    """A `depth`-hop strictly narrowing ladder: each hop drops one capability."""
    return [frozenset(ROOT_CAPS[: len(ROOT_CAPS) - i]) for i in range(depth)]


def escalating_scopes(depth: int, trial: int) -> list[frozenset[str]]:
    """Narrowing ladder whose penultimate hop adds a never-held capability."""
    ladder = narrowing_scopes(depth)
    inject = depth - 1 if depth > 1 else 1
    escalated = list(ladder)
    escalated[inject] = frozenset(ladder[inject] | {f"cap:escalate-{trial}"})
    return escalated


def main() -> int:
    print("=" * 64)
    print("C1 at scale: attenuation soundness vs delegation-chain depth")
    print("=" * 64)

    rows = []
    all_ok = True
    for depth in DEPTHS:
        accepted = 0
        rejected_escalation = 0
        rejected_other = 0
        for trial in range(TRIALS):
            good = build_signed_chain(narrowing_scopes(depth))
            try:
                verify_chain(good, max_depth=64, trusted_root_issuers={good[0].issuer})
                accepted += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  depth={depth} trial={trial} UNEXPECTED reject: {type(exc).__name__}")
        for trial in range(TRIALS):
            bad = build_signed_chain(escalating_scopes(depth, trial))
            try:
                verify_chain(bad, max_depth=64, trusted_root_issuers={bad[0].issuer})
                print(f"  depth={depth} trial={trial} ESCALATION NOT CAUGHT")
            except ScopeEscalation:
                rejected_escalation += 1
            except Exception:  # noqa: BLE001
                rejected_other += 1
        ok = accepted == TRIALS and rejected_escalation == TRIALS and rejected_other == 0
        all_ok = all_ok and ok
        rows.append(
            {
                "depth": depth,
                "trials": TRIALS,
                "narrowing_accepted": accepted,
                "escalation_rejected": rejected_escalation,
                "rejected_other_error": rejected_other,
            }
        )
        print(
            f"  depth={depth:>2}: {accepted}/{TRIALS} narrowing accepted; "
            f"{rejected_escalation}/{TRIALS} escalations -> ScopeEscalation; "
            f"{rejected_other} wrong-error"
        )

    total_narrow = sum(r["narrowing_accepted"] for r in rows)
    total_escal = sum(r["escalation_rejected"] for r in rows)
    n = len(DEPTHS) * TRIALS
    summary = {
        "trials_per_depth": TRIALS,
        "depths": DEPTHS,
        "root_universe": len(ROOT_CAPS),
        "rows": rows,
        "total_narrowing_accepted": total_narrow,
        "total_narrowing": n,
        "total_escalation_rejected": total_escal,
        "total_escalation": n,
        "all_ok": all_ok,
    }
    out = Path(__file__).parent / "results" / "c1_attenuation_scale.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, indent=2))

    print("\n" + "=" * 64)
    print(
        f"KEY RESULT: {total_narrow}/{n} narrowing chains accepted; "
        f"{total_escal}/{n} escalation attempts rejected with ScopeEscalation "
        f"across depths {DEPTHS}"
    )
    print(f"wrote {out}")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
