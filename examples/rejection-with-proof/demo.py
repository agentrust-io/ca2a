#!/usr/bin/env python3
"""Rejection with proof: an agent exceeds its delegated authority and is refused.

Story: an orchestrator (A) delegates a narrowed scope to a researcher (B), which
delegates a narrower scope still to a retriever (C). C then asks for a capability
nobody ever delegated to it. The call is refused, and the refusal is not a log
line or a stack trace: it is a linked provenance record that an auditor verifies
offline, from the committed artifacts, without trusting the operator that
produced them.

Two things make the refusal checkable by a third party:

  1. the delegation chain is signed and attenuating, so the effective scope at
     each hop is a provable subset of its parent's; and
  2. the denial record states what was requested and what the effective scope
     actually was, and links into the same hash-chained DAG as the allowed hops,
     so it cannot be dropped without breaking the chain.

Run (from the repo root):

    python examples/rejection-with-proof/demo.py

Then re-verify what it wrote, as an auditor would, with no access to the runtime:

    ca2a verify-chain --chain examples/rejection-with-proof/chain.json \
        --trusted-root-issuer <trusted-root-issuer-hex>
    ca2a verify-dag --dag examples/rejection-with-proof/dag.json \
        --chain examples/rejection-with-proof/chain.json \
        --trusted-root-issuer <trusted-root-issuer-hex>

HONEST LABELING (see LIMITATIONS.md): everything here is real and
hardware-independent. Chain verification, scope attenuation, the scope-intersect-
policy decision and DAG verification need no TEE. This example makes no
attestation claim: it does not seal a payload, does not attest a peer, and proves
nothing about where the code ran. It proves what was authorized and what was
refused.
"""

# ruff: noqa: T201
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from ca2a_runtime.delegation import DelegationCredential, new_keypair  # noqa: E402
from ca2a_runtime.errors import ScopeNotPermitted  # noqa: E402
from ca2a_runtime.peer import enforce_peer_call  # noqa: E402
from ca2a_runtime.policy import LocalPolicy  # noqa: E402
from ca2a_runtime.provenance import DelegationRecord, record_for, verify_dag  # noqa: E402

HERE = Path(__file__).resolve().parent

# A delegates to B delegates to C, narrowing at every hop.
SCOPES = [
    frozenset({"task:read", "task:write", "tool:search", "tool:purchase"}),
    frozenset({"task:read", "tool:search", "tool:purchase"}),
    frozenset({"tool:search"}),
]
NAMES = ["orchestrator", "researcher", "retriever"]

# What the retriever actually asks the callee for. It was never delegated this.
REQUESTED = "tool:purchase"

# The callee's own policy. Deliberately permissive about purchase: the point is
# that a locally allowed capability is still refused when it was not delegated,
# so the refusal cannot be dismissed as "the callee just did not support it".
CALLEE_POLICY = LocalPolicy.of(["task:read", "tool:search", "tool:purchase"])


def build_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    """A correctly signed, narrowing root-to-leaf chain (one hop per scope)."""
    chain: list[DelegationCredential] = []
    priv, pub = new_keypair()
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{depth}-{NAMES[depth]}",
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


def dump(obj: object, name: str) -> Path:
    path = HERE / name
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")
    return path


def main() -> int:
    chain = build_chain(SCOPES)

    print("Delegation chain, narrowing at every hop")
    for cred, name in zip(chain, NAMES, strict=True):
        print(f"  depth {cred.depth}  {name:<13} scope={sorted(cred.scope)}")
    print()

    # Each delegation hop emits a record as it is taken, so the DAG mirrors the
    # chain. record_for is what enforce_peer_call emits on an allowed call.
    records: list[DelegationRecord] = []
    parent_hash: str | None = None
    for depth, cred in enumerate(chain):
        rec = record_for(
            cred, record_id=f"rec-{depth}-{NAMES[depth]}", parent_record_hash=parent_hash
        )
        records.append(rec)
        parent_hash = rec.record_hash()

    # The retriever asks for something it was delegated. Allowed.
    granted = enforce_peer_call(
        chain,
        "tool:search",
        policy=CALLEE_POLICY,
        record_id="rec-check",
        parent_record_hash=parent_hash,
        trusted_root_issuers={chain[0].issuer},
    )
    print(f"ALLOW  tool:search    effective scope {sorted(granted.effective_scope)}")

    # Then it asks for a capability its grant never carried.
    try:
        enforce_peer_call(
            chain,
            REQUESTED,
            policy=CALLEE_POLICY,
            record_id="rec-denied-purchase",
            parent_record_hash=parent_hash,
            trusted_root_issuers={chain[0].issuer},
        )
    except ScopeNotPermitted as exc:
        denial = exc.record
        records.append(denial)
        print(f"DENY   {REQUESTED}  {exc}")
        print(f"       requested   {denial.requested_capability}")
        print(f"       effective   {sorted(denial.effective_scope or frozenset())}")
        print(
            "       why         the leaf grant carries "
            f"{sorted(chain[-1].scope)}; the callee's own policy would have "
            "permitted it, but nobody delegated it"
        )
    else:  # pragma: no cover - the demo is meaningless if this path is taken
        print("ERROR: the over-scoped call was NOT refused")
        return 1
    print()

    chain_path = dump(
        {"chain": [{**c.body(), "signature": c.signature} for c in chain]}, "chain.json"
    )
    dag_path = dump({"records": [r.body() for r in records]}, "dag.json")

    # An auditor's view: verify the DAG from the records alone.
    verify_dag(records)
    print(f"DAG verifies offline: {len(records)} records, leaf documents a {records[-1].decision}")
    print(f"  wrote {chain_path.relative_to(REPO_ROOT)}")
    print(f"  wrote {dag_path.relative_to(REPO_ROOT)}")
    print()

    # And the same check through the shipped CLI, which is what a third party
    # actually runs. No runtime, no operator, just the committed files.
    print("Re-verified through the CLI, as a third party would:")
    for argv in (
        [
            "verify-chain",
            "--chain",
            str(chain_path),
            "--trusted-root-issuer",
            chain[0].issuer,
        ],
        [
            "verify-dag",
            "--dag",
            str(dag_path),
            "--chain",
            str(chain_path),
            "--trusted-root-issuer",
            chain[0].issuer,
        ],
    ):
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
        proc = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "ca2a_runtime.cli", *argv],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            env=env,
            check=False,
        )
        print(f"  $ ca2a {' '.join(argv[:1])} ...")
        print(f"    {proc.stdout.strip() or proc.stderr.strip()}")
        if proc.returncode != 0:
            return proc.returncode

    print()
    print("Tamper check: reparenting the denial breaks the DAG.")
    forged = DelegationRecord(
        record_id=records[-1].record_id,
        credential_id=records[-1].credential_id,
        subject=records[-1].subject,
        scope=records[-1].scope,
        parent_record_hash="0" * 64,
        decision=records[-1].decision,
        requested_capability=records[-1].requested_capability,
        effective_scope=records[-1].effective_scope,
        denial_reason=records[-1].denial_reason,
    )
    try:
        verify_dag([records[0], forged])
    except Exception as exc:  # noqa: BLE001 - any link failure is the point
        print(f"  rejected: {exc}")
    else:  # pragma: no cover
        print("  ERROR: a reparented denial record was accepted")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
