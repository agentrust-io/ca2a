# October 5 A2A interoperability experiment

Read [the report](../../docs/interop-report.md) before interpreting results. These are bounded experiments, not a certification suite. The Python SDK sources and tests are unchanged; wrappers attach optional cA2A discovery and parsing to official peers.

Use a workspace containing `ca2a-interop` (this repository), `a2a-tck`, `a2a-itk`, `a2a-python` and `a2a-js`, checked out at the exact revisions in `results/environment.json`. Run the commands below from that workspace. Examples are PowerShell for the measured Windows host. `uv` must be installed; its executable may be invoked by its full path.

```powershell
uv venv ca2a-env --python 3.12
$env:CBOR2_BUILD_C_EXTENSION = '0'
uv pip install --python ca2a-env/Scripts/python.exe --no-binary cbor2 cbor2==5.7.1 -e 'ca2a-interop[dev]' -e a2a-tck 'a2a-sdk[http-server,grpc,sqlite]==1.1.5' packaging pytest-timeout
uv venv itk-env --python 3.12
uv pip install --python itk-env/Scripts/python.exe --no-binary cbor2 cbor2==5.7.1 -e ca2a-interop -e 'a2a-python[http-server,grpc,sqlite]' fastapi uvicorn grpcio-tools grpcio-reflection packaging pyyaml httpx-sse
npm install --prefix . --no-save --ignore-scripts tsx @bufbuild/buf @bufbuild/protobuf @grpc/grpc-js express jose ts-proto@2.11.0
```

The install lines express the dependency set; pin all resolved versions to `results/environment.json` to reproduce the measured environment. The original run used a wrapper that sets `windowsHide: true` for npm child processes. `--ignore-scripts` avoids package lifecycle scripts. esbuild itself sets `windowsHide: true` when starting its service. The controllers set `CREATE_NO_WINDOW` for owned Windows processes.

Run the TCK controller with a Python that has the `uv` module installed. It runs pytest through `uv run --no-project --python ...`, in the TCK checkout, selecting `-m must`. This is the upstream compatibility suite; the stock `run_tck.py` launcher is not used. Its exit results are stored in each run's `command.json`.

```powershell
python ca2a-interop/experiments/a2a-interop/run_tck.py --workspace .
python ca2a-interop/experiments/a2a-interop/generate_ts.py --workspace .
itk-env/Scripts/python.exe ca2a-interop/experiments/a2a-interop/run_itk.py --workspace . --node 'C:/Program Files/nodejs/node.exe'
ca2a-env/Scripts/python.exe ca2a-interop/experiments/a2a-interop/protected_ts.py --workspace . --node 'C:/Program Files/nodejs/node.exe'
```

`generate_ts.py` invokes the Windows ARM64 buf binary installed above and the same remote `ts-proto:v2.11.0` generator/options as the official TypeScript peer. It writes generated bindings under that peer's `itk/pb`. Adjust the buf binary path for another architecture. The ITK controller logs outcomes to JSON; capture its stdout/stderr to retain the engine trace.

From the cA2A repository, the existing bridge and protected HTTP tests were run with:

```powershell
../ca2a-env/Scripts/python.exe -m pytest tests/unit/test_a2a_sdk_bridge.py tests/unit/test_a2a_sdk_loopback.py -q --tb=short --junitxml=experiments/a2a-interop/results/sdk-tests.xml
```

The controllers use local ports 18991–18992 and 19001–19004. Start only when these ports are free. They stop only their own processes and do not kill port owners. The protected-message probe reserves an ephemeral loopback port, creates keys in memory and passes payloads to Node over stdin.

Do not point the official TCK at `ca2a start`, whose reference transport is not the normative A2A SDK transport. Do not treat the ordinary ITK traversal as a test of delegation metadata. Replays are observations of the documented stateless challenge behavior, not successful rejection tests.
