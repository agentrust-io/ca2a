# ruff: noqa: T201
"""
Experiment: Cross-Chain Replay Rejection
Claim 2: a credential replayed within a chain or spliced from another chain is
rejected by verify_chain.

Proves three properties:
  1. Two independent, well-formed chains both verify (control).
  2. Duplicating a credential_id inside a chain raises CredentialReplay.
  3. Splicing a credential minted for chain A into chain B is rejected
     (BrokenDelegationLink: the spliced hop breaks B's continuity).

Run from repo root (package installed editable):
  python experiments/claim2-cross-chain-replay/run.py
"""

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
from ca2a_runtime.errors import (  # noqa: E402
    BrokenDelegationLink,
    CA2AError,
    CredentialReplay,
)


def build_chain(
    scopes: list[frozenset[str]], *, prefix: str
) -> list[DelegationCredential]:
    """Build a correctly signed root-to-leaf chain with unique credential ids.

    Each hop's issuer is the previous hop's subject, depth increments from 0,
    and parent_id links to the previous credential_id.
    """
    chain: list[DelegationCredential] = []
    priv, pub = new_keypair()
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"{prefix}-{depth}",
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


def section(title: str) -> None:
    print(f"\n[{title}]")


def result(label: str, value: str, ok: bool | None = None) -> None:
    if ok is None:
        print(f"    {label}: {value}")
    elif ok:
        print(f"    {label}: {value}  OK")
    else:
        print(f"    {label}: {value}  FAIL")


def main() -> int:
    print("=" * 60)
    print("Experiment: Cross-Chain Replay Rejection")
    print("Claim 2: replayed or spliced credentials are rejected")
    print("=" * 60)

    failures = 0
    rejected = 0

    # Two independent chains, each with its own key material and id namespace.
    chain_a = build_chain(
        [
            frozenset({"cap:a", "cap:b", "cap:c"}),
            frozenset({"cap:a", "cap:b"}),
            frozenset({"cap:a"}),
        ],
        prefix="a",
    )
    chain_b = build_chain(
        [
            frozenset({"cap:x", "cap:y", "cap:z"}),
            frozenset({"cap:x", "cap:y"}),
            frozenset({"cap:x"}),
        ],
        prefix="b",
    )

    # ------------------------------------------------------------------
    # Property 1: control, both chains verify
    # ------------------------------------------------------------------
    section("1. Control: two independent valid chains verify")
    for name, chain in (("A", chain_a), ("B", chain_b)):
        try:
            verify_chain(chain)
            result(f"chain {name} ({len(chain)} hops)", "VALID", True)
        except CA2AError as exc:
            result(f"chain {name} ({len(chain)} hops)", f"rejected: {exc}", False)
            failures += 1

    # ------------------------------------------------------------------
    # Property 2: intra-chain replay (duplicate credential_id)
    # ------------------------------------------------------------------
    section("2. Intra-chain replay: duplicate a credential_id")
    # Re-insert hop 1 a second time so its credential_id repeats in the chain.
    replay_chain = [chain_a[0], chain_a[1], chain_a[1]]
    duped = chain_a[1].credential_id
    result("duplicated credential_id", duped)
    try:
        verify_chain(replay_chain)
        result("verify_chain raised", "nothing: replay NOT caught", False)
        failures += 1
    except CredentialReplay as exc:
        rejected += 1
        result("verify_chain raised", "CredentialReplay", True)
        result("error detail", str(exc))
    except CA2AError as exc:
        # Any rejection is safe, but we assert the specific type here.
        result("verify_chain raised", f"{type(exc).__name__} (expected CredentialReplay)", False)
        failures += 1

    # ------------------------------------------------------------------
    # Property 3: cross-chain splice
    # ------------------------------------------------------------------
    section("3. Cross-chain splice: hop from chain A dropped into chain B")
    # Take a signed credential minted for chain A (hop 1) and splice it into
    # chain B at position 1. Its signature is valid, but its issuer is chain A's
    # hop-0 subject, which is not chain B's hop-0 subject, so continuity breaks.
    spliced = chain_a[1]
    splice_chain = [chain_b[0], spliced, chain_b[2]]
    result("spliced credential_id", f"{spliced.credential_id} (from chain A)")
    try:
        verify_chain(splice_chain)
        result("verify_chain raised", "nothing: splice NOT caught", False)
        failures += 1
    except (BrokenDelegationLink, CredentialReplay) as exc:
        rejected += 1
        result("verify_chain raised", type(exc).__name__, True)
        result("error detail", str(exc))
    except CA2AError as exc:
        result("verify_chain raised", f"{type(exc).__name__} (unexpected)", False)
        failures += 1

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    controls_ok = failures == 0
    if controls_ok and rejected == 2:
        print(
            "KEY RESULT: 2/2 replay attacks rejected "
            "(1 CredentialReplay, 1 BrokenDelegationLink); "
            "2/2 control chains valid"
        )
        return 0
    print(
        f"KEY RESULT: FAILED, {rejected}/2 attacks rejected, "
        f"{failures} property failures, see output above"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
