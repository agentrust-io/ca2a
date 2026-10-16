# Authenticating the Answer in an Agent Handoff

Technical report, version 1, October 1, 2026. Imran Siddique, OPAQUE Systems. Not peer reviewed.

Build: `python build_paper.py --source . --output paper.pdf` (ReportLab 5.0.1 and PyMuPDF
1.28.2). It reads Times New Roman, Arial and Courier New TrueType files from `--fonts`
(default `C:/Windows/Fonts`); fonts are not bundled. `manifest.json` lists the SHA-256 of
every other file in this package.

Paper text is licensed CC BY 4.0: https://creativecommons.org/licenses/by/4.0/
Project code retains its existing project license; see https://github.com/agentrust-io/ca2a.

The report evaluates cA2A fc22c644846111c7f375446399e9097a73f93214 (head of PR 187; its squash
merge 762f329 on main has the identical tree). Reproduce with Python 3.12 from this directory:

    git clone https://github.com/agentrust-io/ca2a.git subjects/ca2a
    git -C subjects/ca2a fetch origin fc22c644846111c7f375446399e9097a73f93214
    git -C subjects/ca2a checkout --detach fc22c644846111c7f375446399e9097a73f93214
    python -m venv .venv
    .venv/Scripts/python -m pip install --require-hashes -r subjects/ca2a/requirements/dev.txt
    .venv/Scripts/python -B experiments/run.py --source subjects/ca2a --output fresh-results

If the PR head commit is unavailable, pass `--commit 762f329aeae589c28219b2cdc2d4a5d6e41407be`.
`experiments/results/rerun-2026-10-01/` holds the October 1 rerun and
`experiments/results/main-19407fb-2026-10-01/` the same run against cA2A main.

Not run: peer-key rotation on attested hardware and Internet transport.
Current implementation guidance: https://ca2a.agentrust-io.com/
