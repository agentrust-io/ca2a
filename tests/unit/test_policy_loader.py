"""Tests for policy loading used by ca2a start."""

from __future__ import annotations

from pathlib import Path

import pytest

from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import ConfigError
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.policy_loader import load_policy


def test_load_local_policy() -> None:
    cfg = Ca2aConfig(local_policy=frozenset({"read"}))
    policy = load_policy(cfg)
    assert isinstance(policy, LocalPolicy)
    assert policy.allow == frozenset({"read"})


def test_load_cedar_bundle(tmp_path: Path) -> None:
    cedar = tmp_path / "policy.cedar"
    cedar.write_text('permit(principal, action == Action::"read", resource);')
    cfg = Ca2aConfig(policy_bundle_path=str(cedar.name))
    policy = load_policy(cfg, config_dir=tmp_path)
    assert isinstance(policy, CedarPolicy)
    assert policy.permits("read")
    assert not policy.permits("write")


def test_missing_policy_rejected() -> None:
    with pytest.raises(ConfigError):
        load_policy(Ca2aConfig())
