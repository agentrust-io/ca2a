"""Pinned, Linux-only differential TCK characterization of the existing SDK demo."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import importlib.metadata
import importlib.util
import json
import os
import signal
import subprocess
import sys
from pathlib import Path

TCK_SHA = "5daf0144b4a4adbdefb62180739b13c5bd7d8196"
ROOT = Path(__file__).resolve().parents[2]


def git(path: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(path), *args], text=True).strip()


async def run(args: argparse.Namespace) -> int:
    if sys.platform != "linux":
        raise SystemExit("This characterization runner requires Linux process groups")
    tck = args.tck.resolve()
    if git(tck, "rev-parse", "HEAD") != TCK_SHA:
        raise SystemExit(f"TCK must be checked out at {TCK_SHA}")
    if git(tck, "status", "--porcelain", "--untracked-files=no"):
        raise SystemExit("TCK tracked files must be unchanged")
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    spec = importlib.util.spec_from_file_location("sdk_demo", ROOT / "examples/a2a-sdk/loopback.py")
    assert spec and spec.loader
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    original_card = demo.operator_card
    scenario_spec = importlib.util.spec_from_file_location(
        "tck_scenario", tck / "sut/a2a-python/sut_agent.py"
    )
    assert scenario_spec and scenario_spec.loader
    scenario = importlib.util.module_from_spec(scenario_spec)
    scenario_spec.loader.exec_module(scenario)

    class ScenarioExecutor(demo.InventoryExecutor):
        async def execute(self, context, event_queue):
            message = context.message
            metadata = demo.metadata_from_sdk_message(message) if message else {}
            opted = message is not None and demo.EXTENSION_URI in message.extensions
            if (demo.has_ca2a_metadata(metadata) or opted
                    or demo.EXTENSION_URI in context.requested_extensions):
                await super().execute(context, event_queue)
            else:
                await scenario.TckAgentExecutor().execute(context, event_queue)

        async def cancel(self, context, event_queue):
            await scenario.TckAgentExecutor().cancel(context, event_queue)

    def card(url, node):
        value = original_card(url, node)
        value.capabilities.streaming = True
        if args.mode == "baseline":
            del value.capabilities.extensions[:]
        return value

    demo.operator_card = card
    demo.InventoryExecutor = ScenarioExecutor
    chain, _ = demo.demo_credentials()
    node = demo.PeerNode(demo.LocalPolicy.of({demo.READ}), trusted_root_issuers={chain[0].issuer})
    env = {key: value for key, value in os.environ.items()
           if key.lower() not in {"http_proxy", "https_proxy", "all_proxy"}}
    env["NO_PROXY"] = env["no_proxy"] = "127.0.0.1,localhost"
    command = ["uv", "run", "--frozen", "python", "run_tck.py"]
    async with demo.serve(node) as (url, executor):
        command += ["--sut-host", url, "--transport", "jsonrpc", "--level", "must", "--",
                    f"--compatibility-report={out / 'compatibility'}",
                    f"--html={out / 'pytest.html'}", f"--junitxml={out / 'junit.xml'}"]
        timed_out = False
        with (out / "run.log").open("wb") as log:
            process = await asyncio.create_subprocess_exec(
                *command, cwd=tck, env=env, stdout=log, stderr=asyncio.subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                code = await asyncio.wait_for(process.wait(), timeout=args.timeout)
            except TimeoutError:
                timed_out = True
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(process.wait(), timeout=5)
                except TimeoutError:
                    os.killpg(process.pid, signal.SIGKILL)
                    await process.wait()
                code = 124
        manifest = {
            "mode": args.mode, "ca2a_commit": git(ROOT, "rev-parse", "HEAD"),
            "ca2a_tracked_changes": git(ROOT, "status", "--porcelain", "--untracked-files=no"),
            "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "tck_commit": TCK_SHA,
            "tck_lock_sha256": hashlib.sha256((tck / "uv.lock").read_bytes()).hexdigest(),
            "python": sys.version, "sdk": importlib.metadata.version("a2a-sdk"),
            "command": command, "exit_code": code, "timed_out": timed_out,
            "protected_handler_invocations": executor.invocations,
            "scope": "JSON-RPC MUST with pinned upstream scenario executor; cA2A ordinary-path differential",
        }
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return code


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tck", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--mode", choices=["baseline", "extension"], required=True)
    parser.add_argument("--timeout", type=float, default=180)
    raise SystemExit(asyncio.run(run(parser.parse_args())))
