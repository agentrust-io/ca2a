"""Verify that the minimal example documentation commands verify and validate cleanly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca2a_runtime.cli import main

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLE_DIR = REPO_ROOT / "examples" / "minimal"
CHAIN_PATH = EXAMPLE_DIR / "chain.json"
CONFIG_PATH = EXAMPLE_DIR / "ca2a-config.yaml"
TRUSTED_ROOT_KEY = "eda38c446da3db3eba68852ca9869260c36badd48b2cab16ec8d8faf607eb162"


def test_minimal_chain_verifies(capsys: pytest.CaptureFixture[str]) -> None:
    """The verify-chain command documented in examples/minimal/README.md must pass."""
    exit_code = main(
        [
            "verify-chain",
            "--chain",
            str(CHAIN_PATH),
            "--trusted-root-issuer",
            TRUSTED_ROOT_KEY,
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload.get("verified") is True
    assert payload.get("hops") == 3
    assert payload.get("leaf_scope") == ["cap:read"]


def test_minimal_config_validates(capsys: pytest.CaptureFixture[str]) -> None:
    """The validate-config command documented in examples/minimal/README.md must confirm enforcing mode."""
    exit_code = main(
        [
            "validate-config",
            "--config",
            str(CONFIG_PATH),
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "ok: provider=software-only enforcement=enforcing" in out
