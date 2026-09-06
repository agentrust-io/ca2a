"""Run the public tutorial entry points, including their positive controls."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    ("directory", "expected"),
    [
        ("claim1-attenuation-soundness", "200/200 narrowing chains accepted; 200/200"),
        ("claim2-cross-chain-replay", "2/2 control chains valid"),
        ("claim3-scope-policy-intersection", "1/1 allowed, 3/3 denied"),
        ("claim4-sealed-payload-confidentiality", "4/4 encryption checks passed"),
        ("claim5-provenance-dag-integrity", "reparent detected"),
        ("claim6-cross-operator-attestation", "4/4 two operators"),
    ],
)
def test_documented_experiment(directory: str, expected: str) -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "experiments" / directory / "run.py")],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert expected in result.stdout, result.stdout
    assert "SKIP" not in result.stdout


def test_sealed_channel_documented_example() -> None:
    page = (ROOT / "docs/spec/sealed-channel.md").read_text(encoding="utf-8-sig")
    blocks = re.findall(r"```python\n(.*?)```", page, flags=re.DOTALL)
    assert len(blocks) == 1
    exec(compile(blocks[0], "docs/spec/sealed-channel.md", "exec"), {})


def test_delegation_tutorial_sequence(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    namespace: dict[str, object] = {}
    for name in (
        "authoring-a-delegation-credential",
        "verify-a-delegation-chain",
        "emit-and-verify-provenance",
    ):
        path = ROOT / "docs/tutorials" / f"{name}.md"
        blocks = re.findall(r"```python\n(.*?)```", path.read_text(encoding="utf-8-sig"), re.DOTALL)
        assert blocks, path
        for block in blocks:
            exec(compile(block, str(path), "exec"), namespace)
