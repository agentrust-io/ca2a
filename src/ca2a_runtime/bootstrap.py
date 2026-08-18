"""Build a :class:`~ca2a_runtime.node.PeerNode` from a validated config file.

``ca2a start`` is a thin wrapper over the reference transport: it reads a config
file, resolves the two things a node needs that a library caller would pass by
hand (a local policy and an attestation provider), and hands the node to
:func:`ca2a_runtime.transport.server.serve`. Nothing here is required to run a
peer; a program that already has a ``Policy`` and a provider should construct a
``PeerNode`` directly.

Provider selection fails closed. ``software-only`` carries no hardware guarantee,
so it is only ever used when the config names it: a hardware provider whose
device node is absent is a startup error, not a silent downgrade.
"""

from __future__ import annotations

from pathlib import Path

from ca2a_runtime.agent_manifest import (
    load_agent_manifest_document,
    load_agent_manifest_trust_anchor,
    verify_agent_manifest_binding,
)
from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import ConfigError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy, Policy
from ca2a_runtime.tee.base import BaseProvider
from ca2a_runtime.tee.sev_snp import SevSnpProvider
from ca2a_runtime.tee.software import SoftwareProvider
from ca2a_runtime.tee.tdx import TdxProvider
from ca2a_runtime.tee.tpm import TpmProvider

_HARDWARE_PROVIDERS: dict[str, type[BaseProvider]] = {
    "sev-snp": SevSnpProvider,
    "tdx": TdxProvider,
    "tpm": TpmProvider,
}


def load_policy(config: Ca2aConfig, *, config_dir: Path | None = None) -> Policy:
    """Resolve the callee policy from ``policy_bundle_path`` or ``local_policy``.

    Cedar wins when ``policy_bundle_path`` is set; a relative path resolves
    against the config file's directory. Otherwise ``local_policy`` becomes a
    ``LocalPolicy`` allow set. One of the two must be present: a node with no
    policy would intersect every delegated scope to nothing, which looks like a
    misconfiguration rather than a decision.
    """
    if config.policy_bundle_path:
        path = Path(config.policy_bundle_path)
        if not path.is_absolute() and config_dir is not None:
            path = config_dir / path
        if not path.is_file():
            raise ConfigError(f"policy_bundle_path not found: {path}")
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigError(f"cannot read policy_bundle_path: {path}", detail=str(exc)) from exc
        if not text.strip():
            raise ConfigError(f"policy_bundle_path is empty: {path}")
        return CedarPolicy(text)

    if config.local_policy is not None:
        return LocalPolicy(allow=config.local_policy)

    raise ConfigError("ca2a start requires local_policy or policy_bundle_path in the config")


def select_provider(config: Ca2aConfig) -> BaseProvider:
    """Resolve the attestation provider named by ``attestation.provider``."""
    name = config.provider
    if name == "software-only":
        return SoftwareProvider()

    if name in _HARDWARE_PROVIDERS:
        provider = _HARDWARE_PROVIDERS[name]
        if not provider.detect():
            raise ConfigError(
                f"attestation provider {name!r} is not available on this host",
                detail="run on the matching confidential VM, or set provider "
                "'software-only' to accept a no-hardware-guarantee posture",
            )
        return provider()

    if name == "auto":
        for candidate in _HARDWARE_PROVIDERS.values():
            if candidate.detect():
                return candidate()
        raise ConfigError(
            "no hardware attestation provider detected",
            detail="set provider 'software-only' to run without a hardware "
            "guarantee; auto never falls back to it",
        )

    raise ConfigError(f"attestation provider {name!r} is not implemented")


def build_peer_node(config: Ca2aConfig, *, config_dir: Path | None = None) -> PeerNode:
    """Build the node ``ca2a start`` serves: policy, provider, and depth limit."""
    policy = load_policy(config, config_dir=config_dir)
    if not config.trusted_root_issuers:
        raise ConfigError(
            "ca2a start requires at least one trusted_root_issuer",
            detail="pin the Ed25519 public key of each authority allowed to originate delegation chains",
        )
    manifest_binding = None
    if config.agent_manifest_path is not None:
        if (
            config.agent_manifest_trust_anchor_path is None
            or config.agent_manifest_authenticated_subject is None
        ):
            raise ConfigError(
                "Agent Manifest startup requires path, trust anchor, and authenticated subject"
            )
        manifest_path = Path(config.agent_manifest_path)
        trust_path = Path(config.agent_manifest_trust_anchor_path)
        if config_dir is not None:
            if not manifest_path.is_absolute():
                manifest_path = config_dir / manifest_path
            if not trust_path.is_absolute():
                trust_path = config_dir / trust_path
        loaded = load_agent_manifest_document(manifest_path)
        trusted_keys = load_agent_manifest_trust_anchor(trust_path)
        manifest_binding = verify_agent_manifest_binding(
            loaded,
            trusted_keys,
            authenticated_subject=config.agent_manifest_authenticated_subject,
        )

    return PeerNode(
        policy,
        provider=select_provider(config),
        max_depth=config.max_delegation_depth,
        trusted_root_issuers=config.trusted_root_issuers,
        agent_manifest=manifest_binding,
    )
