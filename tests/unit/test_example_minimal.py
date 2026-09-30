"""Tests for examples/minimal ensuring the README commands verify cleanly."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca2a_runtime.cli import main as cli_main

REPO_ROOT = Path(__file__).resolve().parents[2]
MINIMAL_DIR = REPO_ROOT / "examples" / "minimal"
CHAIN_PATH = MINIMAL_DIR / "chain.json"
CONFIG_PATH = MINIMAL_DIR / "ca2a-config.yaml"
TRUSTED_ROOT_KEY = "eda38c446da3db3eba68852ca9869260c36badd48b2cab16ec8d8faf607eb162"


def test_minimal_example_verify_chain(capsys: pytest.CaptureFixture[str]):
    exit_code = cli_main(
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
    data = json.loads(out)
    assert data.get("verified") is True


def test_minimal_example_validate_config(capsys: pytest.CaptureFixture[str]):
    exit_code = cli_main(
        [
            "validate-config",
            "--config",
            str(CONFIG_PATH),
        ]
    )
    assert exit_code == 0
    out = capsys.readouterr().out
    assert "ok: provider=software-only enforcement=enforcing" in out
