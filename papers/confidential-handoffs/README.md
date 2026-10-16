# Confidentiality Across Agent Handoffs: source package, version 3

Technical report, version 3, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.
Patent Pending. Version 3 qualifies the section 7.6 mutual-appraisal result after advisory
GHSA-xxj2-p57x-x954, notes in section 8.3 that ca2a-runtime 0.3.1 is affected, and updates two
redirected links; results are unchanged.
The PDF is published separately at
https://agentrust-io.com/research/confidential-handoffs/v3/paper.pdf.

Build: `python build_paper.py --source . --output paper.pdf` (ReportLab 5.0.1 and PyMuPDF
1.28.2). It reads Times New Roman, Arial and Courier New TrueType files from `--fonts`
(default `C:/Windows/Fonts`); fonts are not bundled. `manifest.json` lists the SHA-256 of
every other file in this package.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/weight-custody-manifest/tree/main/python/composed.

## Contents

- `paper.md`: manuscript source.
- `experiments/reference-2026-09-19/`: minimized evidence from the recorded run (WCM tested
  merge 15e67c2, GitHub Actions run 35469947313).
- `experiments/rerun-2026-09-27.txt` and `experiments/rerun-2026-09-27/`: the September 27
  rerun at WCM main 94d5519.
- `experiments/results/rerun-2026-10-01/`: the October 1 rerun of the 32 portable composed
  cases from the same launcher, plus four component counts. All matched.
- `experiments/compare_observations.py`: compares observation records across runs.
- `launcher/composed-reproduction.zip`: the WCM reproduction launcher built by hosted run
  36272971255 (SHA-256 a209faca6139cd3c02b554edae0d9702af4f1932ae19fca939ce4e4229829ef4),
  with its Apache-2.0 LICENSE and NOTICE.

## Reproduce

Extract `launcher/composed-reproduction.zip` and run
`python reproduce.py --workspace <new directory>` with Python 3.12, Git and network access to
GitHub and PyPI. The portable profile runs 32 cases. Add `--confined` on native Linux with
Docker for all 36. Then compare with `experiments/compare_observations.py`.

## Limits

Attestation is synthetic, signed by test-owned roots. One operator runs every party. No
hardware protects the model key or computation, and no GPU path is exercised. The GCP and Azure
hardware diagnostics summarized in section 7 are not reproducible from this package; their raw
captures contain device-identifying data and are not included.
