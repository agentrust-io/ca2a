"""The rejection-with-proof example must keep working, and keep refusing.

The example is the repo's front door: an agent exceeds its delegated authority,
is refused, and the refusal verifies offline. A silent break here would leave a
README promising something the code no longer does, so the demo runs in CI.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO = REPO_ROOT / "examples" / "rejection-with-proof" / "demo.py"


@pytest.fixture(scope="module")
def demo_run(tmp_path_factory) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    return subprocess.run(  # noqa: S603
        [sys.executable, str(DEMO)],
        capture_output=True,
        text=True,
        cwd=REPO_ROOT,
        env=env,
        check=False,
    )


def test_demo_exits_clean(demo_run) -> None:
    assert demo_run.returncode == 0, demo_run.stderr


def test_demo_refuses_the_over_scoped_call(demo_run) -> None:
    out = demo_run.stdout
    assert "DENY   tool:purchase" in out
    assert "ALLOW  tool:search" in out
    # the failure mode that would make the demo a lie
    assert "the over-scoped call was NOT refused" not in out


def test_demo_denial_verifies_through_the_cli(demo_run) -> None:
    """The CLI line the README quotes must actually say denied and verified."""
    line = next(ln for ln in demo_run.stdout.splitlines() if '"outcome": "denied"' in ln)
    payload = json.loads(line.strip())
    assert payload["verified"] is True
    assert payload["cross_checked"] is True
    assert payload["requested_capability"] == "tool:purchase"
    assert payload["effective_scope"] == ["tool:search"]


def test_demo_rejects_a_reparented_denial(demo_run) -> None:
    assert "rejected:" in demo_run.stdout
    assert "a reparented denial record was accepted" not in demo_run.stdout


def test_committed_artifacts_are_shaped_as_the_readme_says() -> None:
    here = DEMO.parent
    chain = json.loads((here / "chain.json").read_text(encoding="utf-8"))["chain"]
    records = json.loads((here / "dag.json").read_text(encoding="utf-8"))["records"]
    assert len(chain) == 3
    assert [len(c["scope"]) for c in chain] == [4, 3, 1]  # narrowing at every hop
    assert records[-1]["decision"] == "deny"
    assert records[-1]["requested_capability"] == "tool:purchase"
    assert all("decision" not in r for r in records[:-1])  # allow records stay bare
