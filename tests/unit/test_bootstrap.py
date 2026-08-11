"""Tests for building a PeerNode from a config file, the path ``ca2a start`` takes.

The pipeline the node runs is covered by test_live_call.py; what is checked here
is that a config file resolves to the right policy and provider, that provider
selection fails closed rather than downgrading to software, and that a node built
this way serves a real call.
"""

from __future__ import annotations

import threading
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ca2a_runtime.bootstrap import build_peer_node, load_policy, select_provider
from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.errors import CA2AError, ConfigError
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.tee.sev_snp import SevSnpProvider
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.transport import client, server


def test_load_local_policy() -> None:
    policy = load_policy(Ca2aConfig(local_policy=frozenset({"read"})))
    assert isinstance(policy, LocalPolicy)
    assert policy.allow == frozenset({"read"})


def test_load_cedar_bundle_relative_to_config_dir(tmp_path: Path) -> None:
    cedar = tmp_path / "policy.cedar"
    cedar.write_text('permit(principal, action == Action::"read", resource);')
    policy = load_policy(Ca2aConfig(policy_bundle_path=cedar.name), config_dir=tmp_path)
    assert isinstance(policy, CedarPolicy)
    assert policy.permits("read")
    assert not policy.permits("write")


def test_cedar_bundle_wins_over_local_policy(tmp_path: Path) -> None:
    cedar = tmp_path / "policy.cedar"
    cedar.write_text('permit(principal, action == Action::"read", resource);')
    cfg = Ca2aConfig(policy_bundle_path=str(cedar), local_policy=frozenset({"write"}))
    assert isinstance(load_policy(cfg), CedarPolicy)


def test_missing_policy_rejected() -> None:
    with pytest.raises(ConfigError, match="local_policy or policy_bundle_path"):
        load_policy(Ca2aConfig())


def test_empty_cedar_bundle_rejected(tmp_path: Path) -> None:
    cedar = tmp_path / "policy.cedar"
    cedar.write_text("   \n")
    with pytest.raises(ConfigError, match="empty"):
        load_policy(Ca2aConfig(policy_bundle_path=str(cedar)))


def test_software_provider_is_explicit_only() -> None:
    assert isinstance(select_provider(Ca2aConfig(provider="software-only")), SoftwareProvider)


def test_auto_never_falls_back_to_software() -> None:
    # No confidential-computing device nodes in CI, so auto must refuse rather
    # than silently serving with no hardware guarantee.
    with pytest.raises(ConfigError, match="no hardware attestation provider"):
        select_provider(Ca2aConfig(provider="auto"))


def test_absent_hardware_provider_rejected_at_startup() -> None:
    with pytest.raises(ConfigError, match="not available on this host"):
        select_provider(Ca2aConfig(provider="sev-snp"))


def test_auto_selects_a_detected_hardware_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SevSnpProvider, "detect", classmethod(lambda cls: True))
    assert isinstance(select_provider(Ca2aConfig(provider="auto")), SevSnpProvider)


def test_unimplemented_provider_rejected() -> None:
    with pytest.raises(ConfigError, match="not implemented"):
        select_provider(Ca2aConfig(provider="opaque"))


def _delegation_chain() -> tuple[list[DelegationCredential], Ed25519PrivateKey]:
    """A one-hop chain plus the leaf subject's key, which the caller must hold."""
    root_priv, root_pub = new_keypair()
    subject_priv, subject_pub = new_keypair()
    cred = DelegationCredential(
        credential_id="c0",
        issuer=root_pub,
        subject=subject_pub,
        scope=frozenset({"read", "write"}),
        depth=0,
    ).sign(root_priv)
    return [cred], subject_priv


def _write_config(tmp_path: Path) -> Path:
    path = tmp_path / "ca2a-config.yaml"
    path.write_text(
        "attestation:\n"
        "  provider: software-only\n"
        "  enforcement_mode: enforcing\n"
        "max_delegation_depth: 3\n"
        "local_policy:\n"
        "  - read\n"
        "listen_addr: 127.0.0.1:8443\n",
        encoding="utf-8",
    )
    return path


def test_build_peer_node_carries_config(tmp_path: Path) -> None:
    cfg = Ca2aConfig.load(_write_config(tmp_path))
    node = build_peer_node(cfg, config_dir=tmp_path)
    assert isinstance(node.policy, LocalPolicy)
    assert node.policy.allow == frozenset({"read"})
    assert isinstance(node.provider, SoftwareProvider)
    assert node.max_depth == 3


def test_config_built_node_serves_a_live_call(tmp_path: Path) -> None:
    cfg = Ca2aConfig.load(_write_config(tmp_path))
    host, _ = cfg.listen_host_port()
    # Port 0 rather than the configured one: the test needs a free port, and the
    # host is what the config contributes here.
    srv = server.serve(build_peer_node(cfg, config_dir=tmp_path), host=host, port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{srv.server_address[1]}"
        chain, leaf_key = _delegation_chain()

        body = client.send_task(
            base, chain, "read", "r0", holder_key=leaf_key, payload=b"from a config file"
        )
        assert body["accepted"] is True
        assert body["granted_capability"] == "read"

        with pytest.raises(CA2AError) as exc_info:
            client.send_task(base, chain, "write", "r1", holder_key=leaf_key)
        assert exc_info.value.code == "SCOPE_NOT_PERMITTED"
    finally:
        srv.shutdown()
        srv.server_close()
