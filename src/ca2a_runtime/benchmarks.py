"""Delegation-chain verification microbenchmark.

Software-only path: measures per-hop verify latency so CI can gate regressions.
Real attestation and sealed-channel costs are added once Tier 2/3 land.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from ca2a_runtime.delegation import DelegationCredential, new_keypair, verify_chain


def _build_chain(hops: int) -> list[DelegationCredential]:
    scope = frozenset(f"cap:{i}" for i in range(16))
    priv, pub = new_keypair()
    chain: list[DelegationCredential] = []
    parent_id: str | None = None
    for depth in range(hops):
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


def run(hops: int, out: Path | None) -> dict[str, float]:
    latencies: list[float] = []
    for _ in range(hops):
        chain = _build_chain(2)
        start = time.perf_counter()
        verify_chain(chain, max_depth=64)
        latencies.append((time.perf_counter() - start) * 1000.0)
    latencies.sort()
    p99 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.99))]
    result = {"hops": float(hops), "p99_ms": p99, "mean_ms": sum(latencies) / len(latencies)}
    if out is not None:
        out.mkdir(parents=True, exist_ok=True)
        (out / "delegation-verify.json").write_text(json.dumps(result, indent=2))
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ca2a-benchmarks")
    parser.add_argument("--provider", default="software-only")
    parser.add_argument("--hops", type=int, default=10000)
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)
    result = run(args.hops, args.out)
    print(json.dumps(result))
    if result["p99_ms"] >= 5.0:
        print("p99 gate exceeded (>= 5ms)")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
