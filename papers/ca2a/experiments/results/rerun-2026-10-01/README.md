# cA2A rerun, 2026-10-01

Audit rerun of every software experiment the report cites, against the same pin as version 2.

- ca2a: tag v0.3.1, commit 7d90823142dda1be589def3b22a3099581c7df7a, from a git clone (not a source archive).
- Python 3.12.10, x86-64 build (MSC v.1943 AMD64) under emulation on Windows 11, Snapdragon X1E80100,
  64 GB. Same machine type as the 2026-09-27 rerun.
- Fresh venv. Runtime lock `requirements/runtime.txt` at the pin, installed without hashes. No deviation
  this time: cbor2 6.1.4 loaded. Resolved: agent-manifest 0.12.0, agentrust-trace 0.10.0, cedarpy 4.8.7,
  cryptography 50.0.1, pydantic 2.13.5, rfc8785 0.1.4, cbor2 6.1.4; test-only a2a-sdk 1.1.4, pytest 9.1.1,
  agentrust-trace-tests 0.5.1, matplotlib 3.11.2.
- Paper scripts run from a copy of this directory with `CA2A_ROOT` set to the pin and `PYTHONUTF8=1`.
  Repository claim scripts run from the pin as `python experiments/claimN-*/run.py`.
- No hardware run was repeated. The 2026-07-27 SEV-SNP to TDX run and the 2026-09-17 mutual SEV-SNP
  diagnostic used deleted cloud VMs and unpublished raw evidence; they cannot be repeated here.

Files: `rerun.log` (all output, local paths replaced), `c1_attenuation_scale.json`, and three runs each
of `verify_latency_vs_depth.runN.json` and `sealed_channel_throughput.runN.json`.

## Correctness results: all reproduced

| Item | Paper (v2) | This rerun |
|---|---|---|
| C1 repo experiment | 200/200 accepted, 200/200 ScopeEscalation | same |
| C1 at scale, depths 2,3,4,6,8 | 2500/2500 and 2500/2500, 0 wrong-error | same |
| C2 | CredentialReplay, BrokenDelegationLink, 2/2 controls | same |
| C3 | effective scope {read}, 1/1 allowed, 3/3 denied | same |
| C4 | 4/4 | 4/4 |
| C5 hash bits changed | 119 and 138 of 256 | 128 of 256 (random key material; expected near 128) |
| C6 synthetic | 4/4 | 4/4 |
| pytest | 779 passed, 11 skipped (archive) | 788 passed, 2 skipped (git clone runs the 9 git-dependent tests) |
| TDX tests with public GCP quote (SHA-256 f9efbac1...) | 17 passed | 17 passed |

The six claim scripts were also run against ca2a main 19407fb (0.4.0): all six reproduce. The delegation,
channel and provenance modules are unchanged between the pin and main.

## Timing results: shape reproduced, absolute values not

All three timing runs overlapped with an unrelated CPU-heavy job on the same host, so they are contended.
The paper's own caveat applies: single runs under emulation, compare shape.

| Measurement | July 2026 | Paper (2026-09-27) | Run 1 | Run 2 | Run 3 |
|---|---|---|---|---|---|
| verify_chain depth 1, mean (ms) | 0.14 | 0.25 | 0.45 | 0.28 | 0.32 |
| verify_chain depth 1, p50 (ms) | | 0.27 | 0.28 | 0.18 | 0.21 |
| verify_chain depth 8, mean (ms) | 1.73 | 2.07 | 3.98 | 2.27 | 3.31 |
| verify_chain depth 64, mean / p99 (ms) | 12.45 / 22.15 | 13.87 / 26.08 | 29.21 / 392.3 | 22.85 / 49.1 | 26.08 / 64.8 |
| verify_chain depth 64, p50 (ms) | | 13.71 | 18.63 | 20.75 | 23.49 |
| Slope depth 1 to 64, mean (us per hop) | 195 | 216 | 457 | 358 | 409 |
| Slope depth 1 to 64, p50 (us per hop) | | 213 | 291 | 327 | 370 |
| Seal and open, 64 B, round trip (ms) | 0.21 | 0.17 | 0.43 | 0.44 | 0.33 |
| Seal and open, 256 KiB, throughput (MiB/s) | 266 | 212 | 161 | 110 | 157 |

Holds: verification cost grows linearly with depth; small sealed payloads are dominated by fixed X25519
and HKDF setup and large ones by the AEAD; every round trip verified. Does not hold as a number: the
abstract's "about 0.22 ms per hop" and the 212 MiB/s figure were not reproduced on a contended host. The
depth 1 p50 matched the paper (0.27 vs 0.28 ms in run 1), which points at contention in the tail and
mean rather than a code regression. A quiet-host rerun with repeated trials and confidence intervals is
needed before any of these numbers is quoted.

Note: `verify_chain` defaults to `max_depth=8`; the scale and latency scripts raise it to 64 and 128, so
the 16 to 64 hop points are outside the default configuration.
