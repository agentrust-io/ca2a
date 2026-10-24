# Pinned A2A ordinary-path compatibility experiment

The runner serves the existing cA2A SDK loopback adapter with the official TCK's
scenario executor for ordinary messages. Protected messages retain the existing
cA2A executor. Both modes are cA2A-aware: `baseline` only removes the extension
advertisement. This isolates advertisement compatibility; it is not a comparison
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
mismatched provenance. Skips remain skips. Inherited proxies are cleared only for
the local TCK child. Timeout cleanup terminates its process group.

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
