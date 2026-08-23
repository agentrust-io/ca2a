"""The example artifacts a reader clones must verify as committed.

The demos regenerate ``chain.json`` / ``dag.json`` when they run, which means the
existing example tests verify whatever the demo just wrote, not what is in the
repository. That gap is not hypothetical: changing the hashed record body left
``examples/cross-operator-delegation/dag.json`` broken on disk, with every test
still green and the README still quoting ``ca2a verify-dag`` as working.

So these tests read the *committed* blobs out of git rather than the working
tree. A demo run cannot make them pass, and a change to the record body that
forgets to regenerate the examples fails here.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from ca2a_runtime.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parents[2]

EXAMPLES = [
    "examples/cross-operator-delegation",
    "examples/rejection-with-proof",
]


def _committed(path: str) -> str | None:
    """The blob at HEAD for ``path``, or None if git cannot tell us."""
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "show", f"HEAD:{path}"],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            check=False,
        )
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


@pytest.mark.parametrize("example", EXAMPLES)
def test_committed_dag_verifies(example: str, tmp_path: Path) -> None:
    dag = _committed(f"{example}/dag.json")
    chain = _committed(f"{example}/chain.json")
    if dag is None or chain is None:
        pytest.skip("git is unavailable or the example is not committed yet")

    dag_path = tmp_path / "dag.json"
    chain_path = tmp_path / "chain.json"
    dag_path.write_text(dag, encoding="utf-8")
    chain_path.write_text(chain, encoding="utf-8")
    root_issuer = json.loads(chain)["chain"][0]["issuer"]

    assert (
        cli_main(
            [
                "verify-dag",
                "--dag",
                str(dag_path),
                "--chain",
                str(chain_path),
                "--trusted-root-issuer",
                root_issuer,
            ]
        )
        == 0
    )


@pytest.mark.parametrize("example", EXAMPLES)
def test_committed_dag_states_an_attestation_outcome_on_every_record(example: str) -> None:
    """Every record says what the emitter established about its caller.

    Absence is the reading this field exists to prevent, so a committed record
    without it is a record an auditor would have to guess about.
    """
    blob = _committed(f"{example}/dag.json")
    if blob is None:
        pytest.skip("git is unavailable or the example is not committed yet")
    records = json.loads(blob)["records"]
    assert records
    for record in records:
        assert "caller_attestation" in record, record.get("record_id")
