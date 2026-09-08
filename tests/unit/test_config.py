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
    assert cfg.listen_host_port() == ("127.0.0.1", 8443)
    assert cfg.trusted_root_issuers == frozenset()
    assert cfg.agent_manifest_path is None
    assert cfg.require_caller_attestation == "none"
    assert cfg.caller_verifier_platform is None
    assert cfg.caller_verifier_trusted_roots_path is None
    assert cfg.challenge_ttl_seconds == 60


def test_caller_attestation_block_is_loaded() -> None:
    cfg = Ca2aConfig.from_dict(
        {
            "attestation": {
                "provider": "software-only",
                "require_caller_attestation": "hardware",
                "caller_verifier": {"platform": "tpm", "trusted_roots_path": "roots.pem"},
                "challenge_ttl_seconds": 30,
            }
        }
    )
    assert cfg.require_caller_attestation == "hardware"
    assert cfg.caller_verifier_platform == "tpm"
    assert cfg.caller_verifier_trusted_roots_path == "roots.pem"
    assert cfg.challenge_ttl_seconds == 30


def test_unknown_caller_attestation_rung_rejected() -> None:
    with pytest.raises(ConfigError, match="require_caller_attestation"):
        Ca2aConfig.from_dict({"attestation": {"require_caller_attestation": "always"}})


def test_hardware_rung_without_a_verifier_is_a_config_error() -> None:
    # PeerNode would refuse this too; the config layer names the field to add.
    with pytest.raises(ConfigError, match="needs attestation.caller_verifier"):
        Ca2aConfig.from_dict({"attestation": {"require_caller_attestation": "hardware"}})


def test_any_rung_does_not_need_a_verifier() -> None:
    cfg = Ca2aConfig.from_dict({"attestation": {"require_caller_attestation": "any"}})
    assert cfg.require_caller_attestation == "any"
    assert cfg.caller_verifier_platform is None


@pytest.mark.parametrize(
    "verifier",
    [
        "tpm",
        {"platform": "sgx", "trusted_roots_path": "roots.pem"},
        {"platform": "tpm"},
        {"platform": "tpm", "trusted_roots_path": ""},
        {"trusted_roots_path": "roots.pem"},
    ],
)
def test_malformed_caller_verifier_rejected(verifier: object) -> None:
    with pytest.raises(ConfigError, match="caller_verifier"):
        Ca2aConfig.from_dict({"attestation": {"caller_verifier": verifier}})


@pytest.mark.parametrize("ttl", [0, -5, "60", 1.5, True])
def test_bad_challenge_ttl_rejected(ttl: object) -> None:
    with pytest.raises(ConfigError, match="challenge_ttl_seconds"):
        Ca2aConfig.from_dict({"attestation": {"challenge_ttl_seconds": ttl}})


def test_trusted_root_issuers_are_loaded() -> None:
    cfg = Ca2aConfig.from_dict({"trusted_root_issuers": ["root-a", "root-b"]})
    assert cfg.trusted_root_issuers == frozenset({"root-a", "root-b"})


@pytest.mark.parametrize("value", ["root-a", [""], [1], {}])
def test_malformed_trusted_root_issuers_are_rejected(value: object) -> None:
    with pytest.raises(ConfigError, match="trusted_root_issuers"):
        Ca2aConfig.from_dict({"trusted_root_issuers": value})


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


def test_listen_addr_split() -> None:
    cfg = Ca2aConfig.from_dict({"listen_addr": "10.0.0.4:9000"})
    assert cfg.listen_host_port() == ("10.0.0.4", 9000)


def test_listen_addr_ipv6_brackets_stripped() -> None:
    cfg = Ca2aConfig.from_dict({"listen_addr": "[::1]:8443"})
    assert cfg.listen_host_port() == ("::1", 8443)


@pytest.mark.parametrize("addr", [":8443", "8443", "host:port", "host:0", "host:70000"])
def test_bad_listen_addr_rejected(addr: str) -> None:
    with pytest.raises(ConfigError):
        Ca2aConfig.from_dict({"listen_addr": addr})


def test_agent_manifest_config_is_loaded_as_a_complete_set() -> None:
    cfg = Ca2aConfig.from_dict(
        {
            "agent_manifest": {
                "path": "manifest.cose",
                "trust_anchor_path": "manifest-key.json",
                "authenticated_subject": "spiffe://example.test/agent/ca2a",
            }
        }
    )
    assert cfg.agent_manifest_path == "manifest.cose"
    assert cfg.agent_manifest_trust_anchor_path == "manifest-key.json"
    assert cfg.agent_manifest_authenticated_subject == "spiffe://example.test/agent/ca2a"


@pytest.mark.parametrize(
    "manifest",
    [
        {"path": "manifest.cose"},
        {"path": "manifest.cose", "trust_anchor_path": "key.json"},
        {
            "path": "manifest.cose",
            "trust_anchor_path": "key.json",
            "authenticated_subject": "not-spiffe",
        },
    ],
)
def test_incomplete_or_unbound_agent_manifest_config_is_rejected(manifest: dict) -> None:
    with pytest.raises(ConfigError, match="agent_manifest"):
        Ca2aConfig.from_dict({"agent_manifest": manifest})
