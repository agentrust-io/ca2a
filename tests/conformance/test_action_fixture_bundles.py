"""The committed ACTION fixture bundles must verify offline as documented.

Each bundle under ``tests/fixtures/action/<case>/`` is a self-contained
``chain.json`` + ``dag.json`` an auditor re-checks with the shipped
``ca2a verify-dag --chain`` command, plus an ``expected.json`` that states the
verdict (see ``tests/fixtures/action/README.md``). These tests run that command
against the *committed* blobs, so a change to the record body or the chain model
that forgets to regenerate the bundles fails here rather than silently passing
against a bundle the generator just rewrote. Regenerate with
``python scripts/gen_action_fixtures.py``.

This exercises the offline provenance / authorization-denial / validity-window
axes. It does not exercise holder-proof authorization replay, which needs live
audience/secret/challenge material and is not offline-replayable evidence; see
``tests/conformance/README.md`` on the ACTION helper and holder-proof binding.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ca2a_runtime.cli import main as cli_main
from tests.committed_blobs import REPO_ROOT, committed

_BUNDLE_ROOT = REPO_ROOT / "tests" / "fixtures" / "action"
BUNDLES = (
    sorted(p.name for p in _BUNDLE_ROOT.iterdir() if p.is_dir()) if _BUNDLE_ROOT.is_dir() else []
)


def _run_verify_dag(
    chain: str,
    dag: str,
    expected: dict[str, Any],
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> tuple[int, dict[str, Any]]:
    """Run the shipped CLI on the committed blobs, returning (exit_code, output)."""
    chain_path = tmp_path / "chain.json"
    dag_path = tmp_path / "dag.json"
    chain_path.write_text(chain, encoding="utf-8")
    dag_path.write_text(dag, encoding="utf-8")

    argv = [
        "verify-dag",
        "--dag",
        str(dag_path),
        "--chain",
        str(chain_path),
        "--trusted-root-issuer",
        expected["trusted_root_issuer"],
    ]
    if expected.get("at_time") is not None:
        argv += ["--at-time", str(expected["at_time"])]
    rc = cli_main(argv)
    out = json.loads(capsys.readouterr().out.strip().splitlines()[-1])
    return rc, out


@pytest.mark.parametrize("bundle", BUNDLES)
def test_action_bundle_verifies_as_documented(
    bundle: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    base = f"tests/fixtures/action/{bundle}"
    chain = committed(f"{base}/chain.json")
    dag = committed(f"{base}/dag.json")
    expected_blob = committed(f"{base}/expected.json")
    if chain is None or dag is None or expected_blob is None:
        pytest.skip(f"{bundle} is not committed yet or git is unavailable")
    expected = json.loads(expected_blob)

    rc, out = _run_verify_dag(chain, dag, expected, tmp_path, capsys)

    verdict = expected["verdict"]
    if verdict["provenance_status"] == "invalid":
        # A defect in the chain or its records: the CLI fails closed and names
        # the reason. A bundle that agrees on failing but disagrees on why is
        # the case worth catching.
        assert rc == 1, out
        assert out["verified"] is False
        assert out["code"] == expected["code"]
    elif verdict["authorization_decision"] == "denied":
        # Valid provenance plus a recorded authorization denial: the DAG still
        # verifies, and the refusal is evidence rather than an absence of it.
        assert rc == 0, out
        assert out["verified"] is True
        assert out.get("outcome") == "denied"
        assert out.get("denial_reason") == expected["code"]
    else:
        assert rc == 0, out
        assert out["verified"] is True
        assert out.get("outcome") != "denied"


def test_bundles_are_present() -> None:
    """Guard against an empty parametrization silently passing zero cases."""
    assert BUNDLES, "no ACTION fixture bundles found under tests/fixtures/action/"
