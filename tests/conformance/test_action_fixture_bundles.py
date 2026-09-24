"""The committed ACTION fixture bundles must verify offline as documented.

Each bundle under ``tests/fixtures/action/<case>/`` is a self-contained
``chain.json`` + ``dag.json`` an auditor re-checks with the shipped
``ca2a verify-dag --chain`` command, plus an ``expected.json`` that states the
verdict (see ``tests/fixtures/action/README.md``). These tests run that command
against the *committed* blobs, so a change to the record body or the chain model
that forgets to regenerate the bundles fails here rather than silently passing
against a bundle the generator just rewrote. Regenerate with
``python scripts/gen_action_fixtures.py``.

**What is asserted vs. what is a scenario label.** ``expected.json``'s
``verdict`` is the scenario's ACTION three-axis *classification* from
``tests/conformance/README.md``, not the offline verifier's output. The offline
path checks structural consistency (never authenticated lineage) and,
for a recorded denial, ``authorization_decision == "denied"`` (the CLI's denial
outcome). ``authorization_decision == "allowed"`` and every ``controller_outcome``
are NOT offline-observable — the CLI never reports an allowed action or an
accepted/rejected controller outcome — so this test does not assert them. That
holder-proof and controller boundary is the one documented in
``tests/conformance/README.md``; these fixtures do not widen it.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from ca2a_runtime.cli import main as cli_main
from tests.committed_blobs import REPO_ROOT, committed, git_source_available

_BUNDLE_ROOT = REPO_ROOT / "tests" / "fixtures" / "action"

# The bundle set is pinned here, not discovered from disk, so deleting a whole
# bundle directory fails a test (its committed blobs go missing below) instead
# of silently shrinking a filesystem-discovered parametrization.
REQUIRED_BUNDLES = (
    "action-001-verified",
    "action-002-parent-hash-mismatch",
    "action-006-policy-denial",
    "action-010-scope-escalation",
    "action-012-credential-expired",
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
        "--structural-only",
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


@pytest.mark.parametrize("bundle", REQUIRED_BUNDLES)
def test_action_bundle_verifies_as_documented(
    bundle: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    if not git_source_available():
        pytest.skip("git or the committed source archive is unavailable; cannot read HEAD blobs")

    base = f"tests/fixtures/action/{bundle}"
    chain = committed(f"{base}/chain.json")
    dag = committed(f"{base}/dag.json")
    expected_blob = committed(f"{base}/expected.json")
    # git is available, so None here is an absent HEAD blob (missing evidence),
    # not an unavailable source tree: fail rather than skip.
    assert chain is not None, f"{base}/chain.json is missing from HEAD"
    assert dag is not None, f"{base}/dag.json is missing from HEAD"
    assert expected_blob is not None, f"{base}/expected.json is missing from HEAD"
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
        # A structurally consistent unsigned claim of denial, not an authenticated refusal.
        assert rc == 0, out
        assert out["verified"] is False
        assert out["structural_verified"] is True
        assert out.get("outcome") == "denied"
        assert out.get("denial_reason") == expected["code"]
    else:
        assert rc == 0, out
        assert out["verified"] is False
        assert out["structural_verified"] is True
        assert out.get("outcome") != "denied"


def test_committed_bundle_set_matches_required() -> None:
    """Adding or removing a whole bundle directory must be a deliberate change.

    Pins the on-disk set against ``REQUIRED_BUNDLES`` so neither a dropped
    directory (which would also fail its verify test) nor an unwired new one
    slips through unnoticed.
    """
    present = (
        {p.name for p in _BUNDLE_ROOT.iterdir() if p.is_dir()} if _BUNDLE_ROOT.is_dir() else set()
    )
    assert present == set(REQUIRED_BUNDLES)
