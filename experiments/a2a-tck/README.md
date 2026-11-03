# Pinned A2A ordinary-path compatibility experiment

The runner serves the existing cA2A SDK loopback adapter with the official TCK's
scenario executor for ordinary messages. Protected messages retain the existing
cA2A executor. Both modes are cA2A-aware, and both enable streaming for the pinned scenario executor.
The differential between the two modes is only the extension advertisement. This isolates advertisement compatibility; it is not a comparison
against a separate, unmodified SDK server or a protected-path TCK certification.

Test dependencies and upstream scenario code are isolated from runtime packages.
Linux and Python 3.12 are required. From the repository root:

```sh
git clone https://github.com/a2aproject/a2a-tck.git ../a2a-tck
git -C ../a2a-tck checkout 5daf0144b4a4adbdefb62180739b13c5bd7d8196
uv venv --python 3.12 ../ca2a-tck-sut
uv pip install --python ../ca2a-tck-sut/bin/python -r experiments/a2a-tck/environment.txt
export UV_PROJECT_ENVIRONMENT="$(cd .. && pwd)/tck-clean-env"
(cd ../a2a-tck && uv sync --frozen)
PYTHONPATH=src ../ca2a-tck-sut/bin/python experiments/a2a-tck/run.py --tck ../a2a-tck --output ../tck-baseline-results --mode baseline
PYTHONPATH=src ../ca2a-tck-sut/bin/python experiments/a2a-tck/run.py --tck ../a2a-tck --output ../tck-extension-results --mode extension
python experiments/a2a-tck/compare.py ../tck-baseline-results ../tck-extension-results
PYTHONPATH=src ../ca2a-tck-sut/bin/python -m pytest tests/unit/test_a2a_sdk_bridge.py tests/unit/test_a2a_sdk_loopback.py
```

Output directories must be new. Each run retains logs, JUnit, HTML, compatibility
report, dependency/source identifiers, timeout status and protected-handler count.
The comparison rejects unsuccessful runs, changed test identities/outcomes and
mismatched provenance, modified tracked cA2A source, and any protected-handler
count other than integer zero on either side. The counter measures successful
protected `_lookup()` invocations after authentication and payload checks; it
does not count early protected-path refusals or prove that path was never entered.
Skips remain skips. The TCK checkout must have no tracked or untracked changes.
Inherited proxies and `PYTEST_*` settings are cleared for the local TCK child. Timeout cleanup terminates its process group.

## Observed result

On cA2A `806d1147c0bc834ee8aabb698b341c926cd8531e`, A2A SDK 1.2.2,
Python 3.12.14 and the pinned TCK above:

| Check | Result |
| --- | --- |
| Baseline JSON-RPC MUST | 79 passed, 156 skipped, 30 deselected |
| Extension-advertised JSON-RPC MUST | 79 passed, 156 skipped, 30 deselected |
| Per-test identity/outcome comparison | identical |
| Protected handler calls in either TCK run | 0 |
| Separate cA2A bridge + signed loopback suite | 55 passed |
| Dependency consistency | `uv pip check` passed |

Initial runs using the immediate-response inventory demo instead of the upstream
scenario executor had five task/artifact/text failures in both modes. They were
fixture coverage gaps; this change makes no production compatibility fix.

This does not cover HTTP+JSON, gRPC, SHOULD/MAY, real hardware attestation,
independent Go/JavaScript SDKs or cross-language cryptographic interoperability.
The existing signed loopback tests are separate evidence, not TCK coverage.

The environment and action pins remain the historical experiment's fixed inputs,
except that `environment.txt` now pins `pyasn1==0.6.5` to carry the security fix
into the SUT interpreter installed by the TCK workflow. The #303 dependency-floor
update did not cover this experimental installation path. Other pins, including
`cedarpy` and action SHAs, are unchanged; updating them and remeasuring remains a
separate comparison. These pins are not claims to track the latest versions.
This security update and the current comparator controls do not re-date the
historical observed TCK results above, measured at cA2A
`806d1147c0bc834ee8aabb698b341c926cd8531e`; they are not results for the updated
environment.
