import argparse
import json
import os
import subprocess
import time
import urllib.request
from pathlib import Path

import uv

parser = argparse.ArgumentParser()
parser.add_argument("--workspace", type=Path, required=True)
args = parser.parse_args()
ROOT = args.workspace.resolve()
CA = Path(__file__).resolve().parents[2]
TCK = ROOT / "a2a-tck"
PYTHON = ROOT / "ca2a-env/Scripts/python.exe"
OUT = CA / "experiments/a2a-interop/results"
OUT.mkdir(parents=True, exist_ok=True)
FLAGS = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0

for mode in ["baseline", "ca2a"]:
    dest = OUT / mode
    dest.mkdir(exist_ok=True)
    env = os.environ.copy()
    env.update(SUT_HOST="127.0.0.1:18991", GRPC_PORT="18992", PYTHONUTF8="1")
    command = [str(PYTHON), str(CA / "experiments/a2a-interop/tck_sut.py"), "--tck", str(TCK)]
    if mode == "ca2a":
        command += ["--ca2a"]
    with (dest / "server.log").open("w", encoding="utf-8") as log:
        server = subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT, env=env, creationflags=FLAGS
        )
        try:
            for _ in range(50):
                if server.poll() is not None:
                    raise RuntimeError((dest / "server.log").read_text())
                try:
                    with urllib.request.urlopen(
                        "http://127.0.0.1:18991/.well-known/agent-card.json", timeout=1
                    ) as response:
                        card = json.load(response)
                    (dest / "agent-card.json").write_text(
                        json.dumps(card, indent=2), encoding="utf-8"
                    )
                    break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError("SUT did not become healthy")
            test = [
                str(uv.find_uv_bin()),
                "run",
                "--no-project",
                "--python",
                str(PYTHON),
                "python",
                "-m",
                "pytest",
                "tests/compatibility/",
                "--sut-host=http://127.0.0.1:18991",
                "-m",
                "must",
                "-q",
                "--tb=short",
                "--timeout=45",
                f"--compatibility-report={dest / 'compatibility'}",
                f"--junitxml={dest / 'junit.xml'}",
            ]
            with (dest / "pytest.log").open("w", encoding="utf-8") as test_log:
                result = subprocess.run(
                    test,
                    cwd=TCK,
                    env=env,
                    stdout=test_log,
                    stderr=subprocess.STDOUT,
                    creationflags=FLAGS,
                    timeout=1200,
                )
            (dest / "command.json").write_text(
                json.dumps({"command": test, "exit": result.returncode}, indent=2), encoding="utf-8"
            )
            print(mode, "exit", result.returncode, flush=True)
            print((dest / "pytest.log").read_text(encoding="utf-8")[-2500:], flush=True)
        finally:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
