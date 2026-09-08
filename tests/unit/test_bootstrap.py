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

from ca2a_runtime.bootstrap import (
    build_caller_verifier,
    build_peer_node,
    load_policy,
    select_provider,
)
from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.delegation.credential import DelegationCredential, new_keypair
from ca2a_runtime.errors import AttestationFailed, CA2AError, ConfigError
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.tee.base import AttestationReport
from ca2a_runtime.tee.sev_snp import SevSnpProvider
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.transport import client, server

TPM_ROOT_PEM = Path(__file__).parent.parent / "fixtures/tpm/bare-rsa-prefix-0016/trusted-root.pem"


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


def test_no_caller_verifier_unless_configured() -> None:
    assert build_caller_verifier(Ca2aConfig()) is None


def test_tpm_caller_verifier_is_built_from_roots_relative_to_config_dir(tmp_path: Path) -> None:
    (tmp_path / "roots.pem").write_bytes(TPM_ROOT_PEM.read_bytes())
    cfg = Ca2aConfig.from_dict(
        {"attestation": {"caller_verifier": {"platform": "tpm", "trusted_roots_path": "roots.pem"}}}
    )
    verifier = build_caller_verifier(cfg, config_dir=tmp_path)
    assert verifier is not None
    # It is a real TPM verifier, not a stub: a report carrying no evidence fails closed.
    bare = AttestationReport(platform="tpm", measurement="m", public_key="k", nonce="n")
    with pytest.raises(AttestationFailed):
        verifier(bare, "n")


def test_missing_roots_file_rejected(tmp_path: Path) -> None:
    cfg = Ca2aConfig.from_dict(
        {"attestation": {"caller_verifier": {"platform": "tpm", "trusted_roots_path": "nope.pem"}}}
    )
    with pytest.raises(ConfigError, match="trusted_roots_path not found"):
        build_caller_verifier(cfg, config_dir=tmp_path)


def test_empty_roots_file_rejected(tmp_path: Path) -> None:
    (tmp_path / "roots.pem").write_text("\n", encoding="utf-8")
    cfg = Ca2aConfig.from_dict(
        {"attestation": {"caller_verifier": {"platform": "tpm", "trusted_roots_path": "roots.pem"}}}
    )
    with pytest.raises(ConfigError, match="trusted_roots_path is empty"):
        build_caller_verifier(cfg, config_dir=tmp_path)


@pytest.mark.parametrize("platform", ["sev-snp", "tdx"])
def test_platforms_without_a_report_verifier_are_refused_with_a_reason(
    tmp_path: Path, platform: str
) -> None:
    # The config vocabulary knows these platforms; appraising them from a roots
    # file does not exist yet. Naming one must fail at startup, not appraise nothing.
    (tmp_path / "roots.pem").write_bytes(TPM_ROOT_PEM.read_bytes())
    cfg = Ca2aConfig.from_dict(
        {
            "attestation": {
                "caller_verifier": {"platform": platform, "trusted_roots_path": "roots.pem"}
            }
        }
    )
    with pytest.raises(ConfigError, match="cannot be appraised from a config file yet") as info:
        build_caller_verifier(cfg, config_dir=tmp_path)
    assert info.value.detail


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


def _write_config(tmp_path: Path, root_issuer: str = "test-root", attestation: str = "") -> Path:
    path = tmp_path / "ca2a-config.yaml"
    path.write_text(
        "attestation:\n"
        "  provider: software-only\n"
        "  enforcement_mode: enforcing\n"
        f"{attestation}"
        "max_delegation_depth: 3\n"
        "local_policy:\n"
        "  - read\n"
        "listen_addr: 127.0.0.1:8443\n"
        f"trusted_root_issuers:\n  - {root_issuer}\n",
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
    assert node.trusted_root_issuers == frozenset({"test-root"})
    assert node.require_caller_attestation == "none"
    assert node.caller_verifier is None
    assert node.challenge_ttl_seconds == 60


def test_build_peer_node_carries_caller_attestation_knobs(tmp_path: Path) -> None:
    (tmp_path / "roots.pem").write_bytes(TPM_ROOT_PEM.read_bytes())
    cfg = Ca2aConfig.load(
        _write_config(
            tmp_path,
            attestation=(
                "  require_caller_attestation: hardware\n"
                "  caller_verifier:\n"
                "    platform: tpm\n"
                "    trusted_roots_path: roots.pem\n"
                "  challenge_ttl_seconds: 15\n"
            ),
        )
    )
    node = build_peer_node(cfg, config_dir=tmp_path)
    assert node.require_caller_attestation == "hardware"
    assert node.caller_verifier is not None
    assert node.challenge_ttl_seconds == 15


def test_build_peer_node_refuses_missing_trust_anchors() -> None:
    cfg = Ca2aConfig(provider="software-only", local_policy=frozenset({"read"}))
    with pytest.raises(ConfigError, match="trusted_root_issuer"):
        build_peer_node(cfg)


def test_config_built_node_serves_a_live_call(tmp_path: Path) -> None:
    chain, leaf_key = _delegation_chain()
    cfg = Ca2aConfig.load(_write_config(tmp_path, chain[0].issuer))
    host, _ = cfg.listen_host_port()
    # Port 0 rather than the configured one: the test needs a free port, and the
    # host is what the config contributes here.
    srv = server.serve(build_peer_node(cfg, config_dir=tmp_path), host=host, port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{srv.server_address[1]}"
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


def test_config_demanding_caller_attestation_enforces_it_on_a_live_call(tmp_path: Path) -> None:
    """The rung written in the config is the rung the served node applies."""
    chain, leaf_key = _delegation_chain()
    cfg = Ca2aConfig.load(
        _write_config(tmp_path, chain[0].issuer, attestation="  require_caller_attestation: any\n")
    )
    host, _ = cfg.listen_host_port()
    srv = server.serve(build_peer_node(cfg, config_dir=tmp_path), host=host, port=0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://{host}:{srv.server_address[1]}"

        with pytest.raises(CA2AError) as exc_info:
            client.send_task(base, chain, "read", "r0", holder_key=leaf_key)
        assert exc_info.value.code == "ATTESTATION_FAILED"

        body = client.send_task(
            base, chain, "read", "r1", holder_key=leaf_key, caller_provider=SoftwareProvider()
        )
        assert body["accepted"] is True
        assert body["caller_attestation"] == "software-only"
    finally:
        srv.shutdown()
        srv.server_close()
