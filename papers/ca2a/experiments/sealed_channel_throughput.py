#!/usr/bin/env python3
"""Sealed peer channel throughput and latency vs payload size.

Measures the cost of the C4 sealed channel (HPKE-style X25519 -> HKDF-SHA256 ->
ChaCha20-Poly1305) as implemented in ca2a_runtime.channel. For a range of
payload sizes we time seal (sender side: ephemeral keygen + ECDH + HKDF + AEAD
encrypt) and open (receiver side: ECDH + HKDF + AEAD decrypt), then report mean
seal/open latency (ms), the round-trip mean, and end-to-end throughput (MiB/s)
derived from the round trip. A correctness pass first confirms every opened
payload equals the original, so the timing only covers genuinely valid
seal/open pairs.

Every number is what this run measured; nothing is synthesized. Payloads are
random bytes so the AEAD does real work on every iteration.

Writes results/sealed_channel_throughput.json and the plot
figures/sealed_channel_throughput.pdf.

Run from the paper directory, with CA2A_ROOT set to a ca2a checkout:
  PYTHONUTF8=1 python experiments/sealed_channel_throughput.py
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

from ca2a_runtime.channel import (  # noqa: E402
    SealedChannel,
    generate_channel_keypair,
    open_sealed,
)

# Payload sizes in bytes: from a small task envelope to a large document blob.
SIZES = [64, 256, 1024, 4096, 16384, 65536, 262144]
REPEATS = 2000
WARMUP = 200


def percentile(sorted_vals: list[float], q: float) -> float:
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * q))
    return sorted_vals[idx]


def main() -> int:
    print("=" * 64)
    print("Sealed peer channel: throughput and latency vs payload size")
    print("=" * 64)

    priv, pub_hex = generate_channel_keypair()
    channel = SealedChannel(pub_hex)

    rows = []
    all_ok = True
    for size in SIZES:
        payload = os.urandom(size)

        # Correctness gate: seal/open must round-trip before we time it.
        blob = channel.seal(payload)
        recovered = open_sealed(blob, priv)
        ok = recovered == payload
        all_ok = all_ok and ok
        if not ok:
            print(f"  size={size} ROUND-TRIP MISMATCH")

        for _ in range(WARMUP):
            b = channel.seal(payload)
            open_sealed(b, priv)

        seal_ms: list[float] = []
        open_ms: list[float] = []
        for _ in range(REPEATS):
            t0 = time.perf_counter()
            b = channel.seal(payload)
            t1 = time.perf_counter()
            open_sealed(b, priv)
            t2 = time.perf_counter()
            seal_ms.append((t1 - t0) * 1000.0)
            open_ms.append((t2 - t1) * 1000.0)

        seal_ms.sort()
        open_ms.sort()
        seal_mean = sum(seal_ms) / len(seal_ms)
        open_mean = sum(open_ms) / len(open_ms)
        rt_mean = seal_mean + open_mean
        # End-to-end throughput from the round-trip mean (seal + open).
        mib_per_s = (size / (1024 * 1024)) / (rt_mean / 1000.0)
        row = {
            "size_bytes": size,
            "repeats": REPEATS,
            "seal_mean_ms": seal_mean,
            "seal_p99_ms": percentile(seal_ms, 0.99),
            "open_mean_ms": open_mean,
            "open_p99_ms": percentile(open_ms, 0.99),
            "roundtrip_mean_ms": rt_mean,
            "throughput_mib_s": mib_per_s,
            "roundtrip_ok": ok,
        }
        rows.append(row)
        print(
            f"  size={size:>7}B: seal={seal_mean:.4f} ms  open={open_mean:.4f} ms  "
            f"rt={rt_mean:.4f} ms  thr={mib_per_s:8.2f} MiB/s  ok={ok}"
        )

    out = Path(__file__).parent / "results" / "sealed_channel_throughput.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {"repeats": REPEATS, "sizes": SIZES, "all_roundtrips_ok": all_ok, "rows": rows},
            indent=2,
        )
    )

    # Plot: left axis round-trip latency (ms), right axis throughput (MiB/s), vs size.
    sizes = [r["size_bytes"] for r in rows]
    rt = [r["roundtrip_mean_ms"] for r in rows]
    thr = [r["throughput_mib_s"] for r in rows]

    fig, ax1 = plt.subplots(figsize=(5.4, 3.2))
    color1 = "tab:blue"
    ax1.plot(sizes, rt, marker="o", color=color1, label="round-trip latency")
    ax1.set_xlabel("payload size (bytes)")
    ax1.set_ylabel("seal+open round-trip (ms)", color=color1)
    ax1.tick_params(axis="y", labelcolor=color1)
    ax1.set_xscale("log", base=2)
    ax1.set_xticks(sizes)
    ax1.get_xaxis().set_major_formatter(matplotlib.ticker.ScalarFormatter())
    ax1.tick_params(axis="x", labelrotation=45)
    ax1.grid(True, which="both", linewidth=0.3, alpha=0.5)

    ax2 = ax1.twinx()
    color2 = "tab:red"
    ax2.plot(sizes, thr, marker="s", linestyle="--", color=color2, label="throughput")
    ax2.set_ylabel("throughput (MiB/s)", color=color2)
    ax2.tick_params(axis="y", labelcolor=color2)

    fig.tight_layout()
    fig_path = Path(__file__).parent.parent / "figures" / "sealed_channel_throughput.pdf"
    fig_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(fig_path, metadata={"CreationDate": None, "ModDate": None})

    print(f"\nwrote {out}")
    print(f"wrote {fig_path}")

    small = rows[0]
    large = rows[-1]
    print(
        f"KEY RESULT: a {small['size_bytes']}-byte task envelope seals+opens in "
        f"{small['roundtrip_mean_ms']:.4f} ms (setup-dominated); at "
        f"{large['size_bytes']} bytes the AEAD reaches {large['throughput_mib_s']:.1f} MiB/s; "
        f"{'all round-trips verified' if all_ok else 'ROUND-TRIP FAILURE'}"
    )
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
