Composed software harness and component reruns, 2026-10-01
==========================================================

Host: Windows 11 (10.0.26200), Python 3.12.10. Native Linux with Docker is not
available here, so the 4 native confinement cases were not run.

A. Composed harness, fresh environment from the hosted bundle
   Bundle: composed-reproduction.zip downloaded from GitHub Actions run
   36272971255 (WCM main 94d5519, artifact composed-reproduction-bundle),
   sha256 a209faca6139cd3c02b554edae0d9702af4f1932ae19fca939ce4e4229829ef4,
   identical to the digest recorded on 2026-09-27.
   Command: python reproduce.py --workspace <new directory>
   Sources fetched by the launcher: WCM 94d5519fd604, cMCP 2cdb168ce520,
   cA2A fc22c6448461 (the paper's revisions).
   Result: 32 passed in 43.19s, exit 0.            windows-fresh-bundle/
   Installed dependency list, harness file hashes, policy, trust, principals,
   limits and mutation targets are identical to the 2026-09-27 Windows run.

   python ../../compare_observations.py \
       ../../reference-2026-09-19/observations.jsonl \
       windows-fresh-bundle/observations.jsonl
   -> 32 records, 0 oracle failures, 0 not in reference,
      4 reference records absent (the 4 native cases)

   Paper section 8 numbers: 32 portable cases (1 valid, 13 refusals,
   2 unknown-outcome, 16 mutations) reproduce. Only wall time differs
   (18.56s on 2026-09-27, 43.19s here). The 36-case hosted results (runs
   35469947313 and 36272971255) were not re-executed; both runs are
   recorded as success at the stated head revisions.

B. Component experiments (section 7), rerun at the pinned revisions
   cA2A fc22c6448461  tests/unit/test_response_authentication.py   57 passed  (paper: 57)
   cMCP 2cdb168ce520  tests/unit/test_disclosure.py
                      + tests/unit/test_sink_policy.py              77 passed  (paper: 77)
                      (needs pytest-asyncio, which the bundle venv omits;
                      without it 22 sink tests fail on the missing plugin)
   WCM db8f10638bb9   python/tests/test_provisioning_lifecycle.py   18 passed  (paper: 18 new cases)
                      full suite                                    995 passed, 32 skipped (paper: same)

   Full-suite counts for cA2A (691 passed, 2 skipped) and cMCP (2,046 passed,
   20 skipped) were not rerun. The 118 "existing focused controls" in 7.3 are
   not named by file in the paper, so the 136 total was not reconstructed.

Not repeated: the cMCP confinement suite (61 native Linux tests, Docker),
firmware TCG cases (edk2/QEMU), the Azure and GCP SEV-SNP diagnostics and the
September 17 live cA2A handoff. These need hardware or native Linux and the
raw captures are private.
