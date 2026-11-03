# Experimental SUT dependency triage — 3 November 2026

An installed-environment audit with pip-audit 2.10.1 on Linux/Python 3.12.14
reproduced 15 advisory findings in four packages from `environment.txt` at
`3fbd9a3f2a7b3a65a1f2c59651df202614f8d0f1`. No pyasn1 finding remained.
This is dependency exposure triage, not a demonstrated cA2A exploit.

| Package | Previous pin | Replacement | Findings | Relevant boundary |
| --- | --- | --- | --- | --- |
| filelock | 3.32.5 | 4.2.1 | 12 | Local filesystem/lock-directory attacks across several lock implementations; some are Windows-specific. CacheControl's file-cache extra declares this dependency. Shared writable directories are not treated as safe. |
| msgpack | 1.2.2 | 1.2.3 | 1 | Repeated rejected map keys can leak memory in the C decoder. CacheControl declares msgpack. No attacker-controlled MessagePack path was demonstrated in this experiment. |
| opentelemetry-api | 1.44.0 | 1.45.1 | 1 | Excessive CPU in malformed inbound tracestate parsing. google-api-core declares it; A2A also exposes optional telemetry dependencies. No remote exploit test was performed. |
| setuptools | 84.0.0 | 84.1.0 | 1 | Windows legacy wheel installation can escape the destination through namespace metadata. This Linux experiment does not demonstrate that path; grpcio-tools declares setuptools. |

The installed metadata dependency edges above explain why simply deleting these
pins is not a complete repair. All four pins move to the versions identified as
fixed by the audit. filelock crosses a major-version boundary, so installation
consistency and experiment validation are required; this is not a claim of
universal compatibility. Runtime dependency declarations and upstream TCK's
independent lock are unchanged.

## Advisory inventory

Filelock findings (all addressed by 4.2.1; GHSA-j8f7-rjxc-mr56 also lists 4.0.9):

- [GHSA-v4x8-3wr5-3wq8](https://github.com/tox-dev/filelock/security/advisories/GHSA-v4x8-3wr5-3wq8)
- [GHSA-9vhv-jxww-xfm5](https://github.com/tox-dev/filelock/security/advisories/GHSA-9vhv-jxww-xfm5)
- [GHSA-567q-5qvw-pf92](https://github.com/tox-dev/filelock/security/advisories/GHSA-567q-5qvw-pf92)
- [GHSA-m462-7rxw-wvpg](https://github.com/tox-dev/filelock/security/advisories/GHSA-m462-7rxw-wvpg)
- [GHSA-j8f7-rjxc-mr56](https://github.com/tox-dev/filelock/security/advisories/GHSA-j8f7-rjxc-mr56)
- [GHSA-8mx5-7m5m-r77g](https://github.com/tox-dev/filelock/security/advisories/GHSA-8mx5-7m5m-r77g)
- [GHSA-69hj-f68j-2879](https://github.com/tox-dev/filelock/security/advisories/GHSA-69hj-f68j-2879)
- [GHSA-9c4x-gm8v-wgc4](https://github.com/tox-dev/filelock/security/advisories/GHSA-9c4x-gm8v-wgc4)
- [GHSA-rfpc-qcw5-3pc4](https://github.com/tox-dev/filelock/security/advisories/GHSA-rfpc-qcw5-3pc4)
- [GHSA-cwqr-hh33-gh44](https://github.com/tox-dev/filelock/security/advisories/GHSA-cwqr-hh33-gh44)
- [GHSA-fq56-3cx3-fjxp](https://github.com/tox-dev/filelock/security/advisories/GHSA-fq56-3cx3-fjxp)
- [GHSA-6627-m3xw-93mp](https://github.com/tox-dev/filelock/security/advisories/GHSA-6627-m3xw-93mp)

Other findings:

- msgpack: [GHSA-j586-36cw-2gc2](https://github.com/msgpack/msgpack-python/security/advisories/GHSA-j586-36cw-2gc2)
- opentelemetry-api: [GHSA-xcq7-p3pf-p88h](https://github.com/open-telemetry/opentelemetry-python/security/advisories/GHSA-xcq7-p3pf-p88h)
- setuptools: [GHSA-xmj3-9gf7-h52w](https://github.com/pypa/setuptools/security/advisories/GHSA-xmj3-9gf7-h52w)

## Reproduction and limits

Install the current `environment.txt` in a new Python 3.12 virtual environment,
then run that environment's `python -m pip check` and `python -m pip_audit`.
The TCK workflow now runs both before the paired experiment. Neither check
disables findings or exempts these dependencies. Audit results are dated
observations of the advisory database, not a permanent clean bill of health.

The README's original TCK table remains historical. Current-environment runs
must retain their own source revision and dependency provenance. This change
does not establish protected-path certification, Windows execution, a full
hash lock, or an audit of the separately installed upstream TCK environment.

## Validation on the updated environment

At local source `29d0d5087ed46ecd17dafd5a945bd76a7386b7f1`, a newly created SUT
virtual environment installed all 97 pinned packages. `pip check` passed and
`pip-audit` reported zero known findings. The 15 comparator and 55 bridge/loopback
tests passed. Both fresh official TCK JSON-RPC MUST runs produced 79 passed,
156 skipped and 30 deselected. The comparator accepted identical per-test
outcomes and integer-zero protected-handler counts on both sides. Neither run
timed out; both recorded clean tracked cA2A source.

The published equivalent source commit is
`98f4fd69d789509ea81be8aa2a43870d586d91cb`; its tree
`71ae1b78eacbb3f74b0e680ed1948ab876c136b5` exactly matches the locally
tested tree. The retained manifests identify the local commit. In a separate
hash-locked development environment, 796 unit tests passed and two skipped;
Ruff, mypy (47 files) and configured Bandit passed.

The SDK emitted context-detach and pending-task cleanup diagnostics during the
runs. This is a passing test/comparator result, not a warning-free execution or
proof those diagnostics are harmless. Structured revision, environment digest,
audit and result observations are retained in
[dependency-validation-2026-11-03.json](dependency-validation-2026-11-03.json).
These observations do not replace the original historical table.

Prepared with OpenAI Codex.
