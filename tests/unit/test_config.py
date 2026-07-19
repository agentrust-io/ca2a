"""Tests for Ca2aConfig loading and validation."""

from __future__ import annotations

from pathlib import Path

import pytest

from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import ConfigError


def test_defaults_from_empty_dict() -> None:
    cfg = Ca2aConfig.from_dict({})
    assert cfg.provider == "auto"
    assert cfg.enforcement_mode == "enforcing"
    assert cfg.max_delegation_depth == 8


def test_unknown_provider_rejected() -> None:
    with pytest.raises(ConfigError):
        Ca2aConfig.from_dict({"attestation": {"provider": "magic"}})


def test_unknown_enforcement_rejected() -> None:
    with pytest.raises(ConfigError):
        Ca2aConfig.from_dict({"attestation": {"enforcement_mode": "loud"}})


def test_bad_depth_rejected() -> None:
    with pytest.raises(ConfigError):
        Ca2aConfig.from_dict({"max_delegation_depth": 0})


def test_load_from_file(tmp_path: Path) -> None:
    p = tmp_path / "ca2a-config.yaml"
    p.write_text("attestation:\n  provider: tdx\n  enforcement_mode: advisory\n")
    cfg = Ca2aConfig.load(p)
    assert cfg.provider == "tdx"
    assert cfg.enforcement_mode == "advisory"


def test_load_missing_file() -> None:
    with pytest.raises(ConfigError):
        Ca2aConfig.load("/nonexistent/ca2a-config.yaml")


def test_load_non_mapping_root(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("- just\n- a\n- list\n")
    with pytest.raises(ConfigError):
        Ca2aConfig.load(p)


def test_load_invalid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("attestation: [unclosed\n")
    with pytest.raises(ConfigError):
        Ca2aConfig.load(p)


def test_local_policy_from_dict() -> None:
    cfg = Ca2aConfig.from_dict({"local_policy": ["read", "write"]})
    assert cfg.local_policy == frozenset({"read", "write"})


def test_bad_local_policy_rejected() -> None:
    with pytest.raises(ConfigError):
        Ca2aConfig.from_dict({"local_policy": "read"})
    with pytest.raises(ConfigError):
        Ca2aConfig.from_dict({"local_policy": [""]})


def test_enclave_key_hex_from_dict() -> None:
    cfg = Ca2aConfig.from_dict({"enclave_private_key_hex": "ab" * 32})
    assert cfg.enclave_private_key_hex == "ab" * 32
