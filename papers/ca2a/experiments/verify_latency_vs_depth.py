#!/usr/bin/env python3
"""Verification latency vs delegation-chain depth.

Measures the wall-clock cost of verify_chain (signature + continuity +
attenuation + anti-replay over every hop) as the chain deepens. This is the
per-inbound-call cost a callee pays before it acts, so its scaling in depth
matters for A2A workloads with long delegation chains.

For each depth we build one signed chain, then time verify_chain over REPEATS
iterations and report mean / p50 / p99 in milliseconds. Chains are signed once
up front so the measurement isolates verification, not key generation.

Writes results/verify_latency_vs_depth.json and the plot
figures/verify_latency_vs_depth.pdf.

Run from the paper directory, with CA2A_ROOT set to a ca2a checkout:
  PYTHONUTF8=1 python experiments/verify_latency_vs_depth.py
"""
# ruff: noqa: T201
from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

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

DEPTHS = [1, 2, 4, 8, 16, 32, 64]
REPEATS = 2000
WARMUP = 200
ROOT_CAPS = frozenset(f"cap:{i}" for i in range(16))


def build_chain(depth: int) -> list[DelegationCredential]:
    """A fixed-scope, correctly signed chain of `depth` hops."""
    chain: list[DelegationCredential] = []
    priv, pub = new_keypair()
    parent_id: str | None = None
    for d in range(depth):
        next_priv, next_pub = new_keypair()
        cred = DelegationCredential(
            credential_id=f"cred-{d}",
            issuer=pub,
            subject=next_pub,
            scope=ROOT_CAPS,
            depth=d,
            parent_id=parent_id,
        ).sign(priv)
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain


def percentile(sorted_vals: list[float], q: float) -> float:
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * q))
    return sorted_vals[idx]


def main() -> int:
    print("=" * 64)
    print("Verification latency vs delegation-chain depth")
    print("=" * 64)

    rows = []
    for depth in DEPTHS:
        chain = build_chain(depth)
        roots = {chain[0].issuer}
        for _ in range(WARMUP):
            verify_chain(chain, max_depth=128, trusted_root_issuers=roots)
        samples: list[float] = []
        for _ in range(REPEATS):
            start = time.perf_counter()
            verify_chain(chain, max_depth=128, trusted_root_issuers=roots)
            samples.append((time.perf_counter() - start) * 1000.0)
        samples.sort()
        mean = sum(samples) / len(samples)
        row = {
            "depth": depth,
            "repeats": REPEATS,
            "mean_ms": mean,
            "p50_ms": percentile(samples, 0.50),
            "p99_ms": percentile(samples, 0.99),
            "per_hop_us": (mean / depth) * 1000.0,
        }
        rows.append(row)
        print(
            f"  depth={depth:>3}: mean={row['mean_ms']:.4f} ms  "
            f"p50={row['p50_ms']:.4f} ms  p99={row['p99_ms']:.4f} ms  "
            f"per-hop={row['per_hop_us']:.2f} us"
        )

    out = Path(__file__).parent / "results" / "verify_latency_vs_depth.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"repeats": REPEATS, "rows": rows}, indent=2))

    # Plot: mean and p99 latency vs depth.
    depths = [r["depth"] for r in rows]
    means = [r["mean_ms"] for r in rows]
    p99s = [r["p99_ms"] for r in rows]
    fig, ax = plt.subplots(figsize=(5.2, 3.2))
    ax.plot(depths, means, marker="o", label="mean")
    ax.plot(depths, p99s, marker="s", linestyle="--", label="p99")
    ax.set_xlabel("delegation-chain depth (hops)")
    ax.set_ylabel("verify_chain latency (ms)")
    ax.set_xscale("log", base=2)
    ax.set_xticks(depths)
    ax.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax.grid(True, which="both", linewidth=0.3, alpha=0.5)
    ax.legend(frameon=False)
    fig.tight_layout()
    fig_path = Path(__file__).parent.parent / "figures" / "verify_latency_vs_depth.pdf"
    fig_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(fig_path, metadata={"CreationDate": None, "ModDate": None})
    print(f"\nwrote {out}")
    print(f"wrote {fig_path}")

    slope = (rows[-1]["mean_ms"] - rows[0]["mean_ms"]) / (rows[-1]["depth"] - rows[0]["depth"])
    print(
        f"KEY RESULT: verify latency is linear in depth at ~{slope*1000:.1f} us/hop; "
        f"a {rows[-1]['depth']}-hop chain verifies in {rows[-1]['mean_ms']:.3f} ms mean "
        f"(p99 {rows[-1]['p99_ms']:.3f} ms)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
