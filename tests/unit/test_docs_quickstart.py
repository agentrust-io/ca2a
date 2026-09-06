"""Run the documented grant and rejection examples, then verify its saved chain."""

import json
import re
import subprocess
import sys
from pathlib import Path

from ca2a_runtime.cli import main


def test_first_chain(tmp_path, capsys):
    page = Path(__file__).resolve().parents[2] / "docs/quickstart.md"
    blocks = re.findall(r"^```python\n(.*?)^```", page.read_text(encoding="utf-8"), re.M | re.S)
    assert len(blocks) == 1
    run = subprocess.run(
        [sys.executable, "-c", blocks[0]], cwd=tmp_path, capture_output=True, text=True
    )
    assert run.returncode == 0, run.stdout + run.stderr
    assert run.stdout.count("PASS:") == 3
    root = (tmp_path / "trusted-root.txt").read_text()
    assert (
        main(
            [
                "verify-chain",
                "--chain",
                str(tmp_path / "demo-chain.json"),
                "--trusted-root-issuer",
                root,
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {
        "verified": True,
        "hops": 2,
        "leaf_scope": ["cap:read"],
    }
