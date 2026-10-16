# cA2A: Confidential Agent-to-Agent Delegation as a Profile on A2A

Technical report, version 3, October 1, 2026. Not peer reviewed. Patent Pending.
Version 3 adds the caller-attestation relay that ca2a 0.4.0 fixed (GHSA-xxj2-p57x-x954), which
affects the evaluated release, corrects four statements and restores bold and italic type.
Results are unchanged.

Build: `tectonic paper.tex` (prepared with Tectonic 0.16.9; set SOURCE_DATE_EPOCH=1790812800
to reproduce the published PDF byte for byte).

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/ca2a.

This package contains the manuscript source, figures, the three scale and cost experiment
scripts and their results. The evaluated code is ca2a 0.3.1, tag v0.3.1, commit
7d90823142dda1be589def3b22a3099581c7df7a. `experiments/results/rerun-2026-09-27.txt` records the
September 27 rerun and `experiments/results/rerun-2026-10-01/` the October 1 rerun at the same
commit: correctness results reproduced; timings were taken on a contended host.
`experiments/results/original-2026-07-01/` keeps the July 2026 results unchanged. Run the scripts
with CA2A_ROOT set to a ca2a checkout at that tag. No hardware run was repeated.
Current implementation guidance: https://ca2a.agentrust-io.com/
