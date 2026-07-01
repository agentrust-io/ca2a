"""
Experiment: Attenuation Soundness
cA2A Claim 1: A child grant can never exceed its parent.

Proves two properties over many independently generated chains:
  1. Every strictly narrowing chain is accepted by verify_chain.
  2. Every escalating variant (one child adds a capability its parent never
     held) is rejected with ScopeEscalation.

Run from repo root:
  pip install -e .
  python experiments/claim1-attenuation-soundness/run.py
"""

# This is a standalone experiment script; console output is the deliverable.
# ruff: noqa: T201
from __future__ import annotations

import sys
from pathlib import Path

# Allow running from repo root without install.
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from ca2a_runtime.delegation import (  # noqa: E402
    DelegationCredential,
    new_keypair,
    verify_chain,
)
from ca2a_runtime.errors import ScopeEscalation  # noqa: E402

TRIALS = 200
# Root scope large enough to narrow across several hops.
ROOT_CAPS = [f"cap:{c}" for c in "abcdef"]


def build_signed_chain(
    scopes: list[frozenset[str]],
) -> list[DelegationCredential]:
    """Build a correctly signed root-to-leaf chain granting scopes[i] at hop i.

    Continuity holds: each hop's issuer is the previous hop's subject, depth
    increments from 0, and parent_id links to the previous credential_id.
    """
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


def narrowing_scopes(trial: int) -> list[frozenset[str]]:
    """A four-hop strictly narrowing scope ladder.

    Each hop drops exactly one capability from its parent, so every hop is a
    strict subset of the one above it.
    """
    return [
        frozenset(ROOT_CAPS),
        frozenset(ROOT_CAPS[:5]),
        frozenset(ROOT_CAPS[:4]),
        frozenset(ROOT_CAPS[:3]),
    ]


def escalating_scopes(trial: int) -> list[frozenset[str]]:
    """A narrowing ladder in which the third hop adds a fresh capability.

    The added capability was never held by any ancestor, so it is a genuine
    escalation rather than a re-grant of something the parent had.
    """
    ladder = narrowing_scopes(trial)
    escalated = frozenset(ladder[3] | {f"cap:escalate-{trial}"})
    return [ladder[0], ladder[1], ladder[2], escalated]


def section(title: str) -> None:
    print(f"\n{title}")


def main() -> int:
    print("=" * 60)
    print("Experiment: Attenuation Soundness (cA2A Claim 1)")
    print("=" * 60)

    # ------------------------------------------------------------------
    # Property 1: narrowing chains are accepted.
    # ------------------------------------------------------------------
    section("[1] Narrowing chains accepted")
    accepted = 0
    for trial in range(TRIALS):
        chain = build_signed_chain(narrowing_scopes(trial))
        try:
            verify_chain(chain)
            accepted += 1
        except Exception as exc:  # noqa: BLE001
            print(f"    trial {trial} UNEXPECTED rejection: {type(exc).__name__}: {exc}")
    print(f"    trials: {TRIALS}")
    print(f"    accepted: {accepted}/{TRIALS}")

    # ------------------------------------------------------------------
    # Property 2: escalation attempts are rejected with ScopeEscalation.
    # ------------------------------------------------------------------
    section("[2] Escalation attempts rejected")
    rejected = 0
    other = 0
    example = ""
    for trial in range(TRIALS):
        chain = build_signed_chain(escalating_scopes(trial))
        try:
            verify_chain(chain)
            print(f"    trial {trial} ESCALATION NOT CAUGHT: chain verified")
        except ScopeEscalation as exc:
            rejected += 1
            if not example:
                detail = f" ({exc.detail})" if exc.detail else ""
                example = f"{exc}{detail}"
        except Exception as exc:  # noqa: BLE001
            other += 1
            print(f"    trial {trial} rejected by WRONG error: {type(exc).__name__}: {exc}")
    print(f"    trials: {TRIALS}")
    print(f"    rejected with ScopeEscalation: {rejected}/{TRIALS}")
    if other:
        print(f"    rejected with other error (unexpected): {other}")
    if example:
        print(f"    example: {example}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    ok = accepted == TRIALS and rejected == TRIALS
    print(
        f"KEY RESULT: {accepted}/{TRIALS} narrowing chains accepted; "
        f"{rejected}/{TRIALS} escalation attempts rejected (ScopeEscalation)"
    )
    if not ok:
        print("Result: FAILED, see output above")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
