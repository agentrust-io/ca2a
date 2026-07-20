"""Emit a TRACE delegation DAG from a cA2A chain and verify it offline.

Run:  python examples/trace-dag/demo.py

Builds a three-hop delegation chain (A -> B -> C), lifts each hop into a signed
TRACE Trust Record carrying the A2A ``delegation`` block, verifies the resulting
DAG from the signed records alone, cross-checks it against the chain, confirms
each record passes the TRACE conformance suite at Level 0, and writes the DAG to
``dag.json``. This is the software-attestation path: records are honestly Level 0
(platform ``software-only``); a hardware TEE run is what lifts them to Level 1.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from agentrust_trace import generate_key
from trace_tests.runner import run as run_conformance

from ca2a_runtime.delegation import DelegationCredential, new_keypair
from ca2a_runtime.trace_binding import HopContext, HopSpec, digest, emit_dag
from ca2a_verify import cross_check_trace_dag, verify_trace_dag

SUBJECTS = [
    "spiffe://ca2a.example/agent/orchestrator",
    "spiffe://ca2a.example/agent/researcher",
    "spiffe://ca2a.example/agent/retriever",
]
SCOPES = [
    frozenset({"task:read", "task:write", "tool:search"}),
    frozenset({"task:read", "tool:search"}),
    frozenset({"tool:search"}),
]


def build_chain(scopes: list[frozenset[str]]) -> list[DelegationCredential]:
    """A correctly signed, narrowing root-to-leaf chain (one hop per scope)."""
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


def main() -> None:
    now = int(time.time())
    chain = build_chain(SCOPES)
    keys = [generate_key() for _ in chain]

    hops = [
        HopSpec(
            subject=SUBJECTS[i],
            signing_key=keys[i],
            context=HopContext.software(
                model_provider="anthropic",
                model_id="claude-opus-4-8",
                image_label=f"ca2a-peer:{SUBJECTS[i].rsplit('/', 1)[-1]}",
                policy_bundle_hash=digest(b"demo-policy-bundle"),
            ),
            iat=now,
            credential_id=cred.credential_id,
        )
        for i, cred in enumerate(chain)
    ]

    records = emit_dag(hops)
    print(f"emitted {len(records)} linked TRACE records (root -> leaf)")

    trusted = [k.public_key() for k in keys]
    result = verify_trace_dag(records, trusted_keys=trusted)
    cross_check_trace_dag(records, chain)
    print(f"DAG verified offline: {result.hops} hops, {result.root_subject} -> {result.leaf_subject}")

    for i, record in enumerate(records):
        findings = run_conformance(record, "trace", level=0)
        failed = [f for group in findings.values() for f in group if f.failed()]
        status = "PASS" if not failed else f"FAIL {failed}"
        block = "root (no delegation block)" if i == 0 else record["delegation"]["credential_id"]
        print(f"  record {i}: TRACE Level 0 {status}  [{block}]")

    out = Path(__file__).parent / "dag.json"
    out.write_text(json.dumps(records, indent=2), encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
