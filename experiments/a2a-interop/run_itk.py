"""Bounded Windows-compatible invocation of the official ITK traversal engine.

This does not invoke the kit's Linux cluster launcher or its full SDK matrix.
Supply --workspace with pinned a2a-python, a2a-js, a2a-itk checkouts, itk-env,
and node_modules containing tsx and the official TS peer's dependencies.
"""

import argparse
import asyncio
import importlib.util
import json
import logging
import subprocess
import sys
import time
import types
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--workspace", type=Path, required=True)
parser.add_argument("--node", required=True)
args = parser.parse_args()
root = args.workspace.resolve()
out = Path(__file__).resolve().parent / "results/itk"
out.mkdir(parents=True, exist_ok=True)
sys.path.insert(0, str(root / "a2a-itk"))
# Load the real config module without executing launcher/__init__.py, which
# eagerly imports the Linux-only fcntl cache. This run owns its peer processes;
# it never uses that launcher or changes the test/traversal implementation.
launcher = types.ModuleType("test_suite.launcher")
launcher.__path__ = [str(root / "a2a-itk/test_suite/launcher")]
sys.modules["test_suite.launcher"] = launcher
config_spec = importlib.util.spec_from_file_location(
    "test_suite.launcher.config", root / "a2a-itk/test_suite/launcher/config.py"
)
config = importlib.util.module_from_spec(config_spec)
sys.modules[config_spec.name] = config
config_spec.loader.exec_module(config)
launcher.config = config
from test_suite.agent_table import AgentEndpoint, AgentTable
from testlib import execute_itk_test

flags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
agents = AgentTable(
    {"python_v10": AgentEndpoint(19001, 19002), "ts_v10": AgentEndpoint(19003, 19004)}
)
logging.basicConfig(level=logging.INFO)


async def checks(mode):
    results = {}
    for protocol in ["jsonrpc", "grpc", "http_json"]:
        for streaming in [False, True]:
            name = f"{mode}-{protocol}-streaming-{streaming}"
            try:
                result = await asyncio.wait_for(
                    execute_itk_test(
                        sdks=list(agents),
                        behavior="send_message",
                        agents=agents,
                        edges=["0->1", "1->0"],
                        scenario_name=name,
                        protocols=[protocol],
                        streaming=streaming,
                    ),
                    timeout=180,
                )
            except Exception as exc:
                result = {name: {"passed": False, "error": repr(exc)}}
            results.update(result)
            (out / f"{mode}-results.json").write_text(
                json.dumps(results, indent=2), encoding="utf-8"
            )
            print(json.dumps(result), flush=True)


for mode in ["baseline", "ca2a"]:
    processes, logs = [], []
    try:
        commands = [
            [
                sys.executable,
                str(Path(__file__).with_name("itk_sut.py")),
                "--sdk",
                str(root / "a2a-python"),
                "--itk",
                str(root / "a2a-itk"),
            ]
            + (["--ca2a"] if mode == "ca2a" else []),
            [
                args.node,
                "--import",
                (root / "node_modules/tsx/dist/loader.mjs").as_uri(),
                str(root / "a2a-js/itk/itk_agent.ts"),
                "--httpPort",
                "19003",
                "--grpcPort",
                "19004",
            ],
        ]
        for sdk, command in zip(agents, commands, strict=True):
            log = (out / f"{mode}-{sdk}.log").open("w", encoding="utf-8")
            logs.append(log)
            processes.append(
                subprocess.Popen(
                    command, cwd=root, stdout=log, stderr=subprocess.STDOUT, creationflags=flags
                )
            )
        for sdk, proc in zip(agents, processes, strict=True):
            for _ in range(100):
                if proc.poll() is not None:
                    raise RuntimeError(f"{sdk} exited {proc.returncode}; see peer log")
                try:
                    with urllib.request.urlopen(
                        agents.card_uri(sdk) + "/.well-known/agent-card.json", timeout=1
                    ) as response:
                        card = json.load(response)
                    (out / f"{mode}-{sdk}-card.json").write_text(
                        json.dumps(card, indent=2), encoding="utf-8"
                    )
                    break
                except OSError:
                    time.sleep(0.2)
            else:
                raise RuntimeError(f"{sdk} readiness timeout")
        asyncio.run(checks(mode))
    except Exception as exc:
        (out / f"{mode}-setup-error.json").write_text(
            json.dumps({"error": repr(exc)}, indent=2), encoding="utf-8"
        )
        print(repr(exc), flush=True)
        raise
    finally:
        for proc in processes:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
        for log in logs:
            log.close()
