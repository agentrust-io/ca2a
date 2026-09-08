"""Runtime configuration for the cA2A peer runtime.

Defines and validates the configuration surface consumed by ``ca2a start``
and the offline CLI. See ROADMAP.md / LIMITATIONS.md for claim boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ca2a_runtime.challenge import DEFAULT_TTL_SECONDS
from ca2a_runtime.errors import ConfigError
from ca2a_runtime.peer import REQUIRE_HARDWARE, REQUIRE_NONE, REQUIREMENT_VALUES

VALID_PROVIDERS = frozenset({"auto", "tpm", "sev-snp", "tdx", "opaque", "software-only"})
VALID_ENFORCEMENT = frozenset({"enforcing", "advisory", "silent"})

# Platforms a config can name under ``attestation.caller_verifier.platform``. This
# is the set of platforms the config *vocabulary* knows, not the set that can be
# appraised today; bootstrap refuses the ones with no report-level verifier and
# says why, so a config that names ``sev-snp`` fails at startup rather than
# silently appraising nothing.
VALID_VERIFIER_PLATFORMS = frozenset({"tpm", "sev-snp", "tdx"})

DEFAULT_LISTEN_ADDR = "127.0.0.1:8443"


def split_listen_addr(addr: str) -> tuple[str, int]:
    """Split a ``host:port`` listen address, requiring the host to be explicit.

    An IPv6 host may be bracketed (``[::1]:8443``). The host is never defaulted:
    binding every interface has to be written out in the config, not inherited
    from an omitted field.
    """
    if not isinstance(addr, str) or ":" not in addr:
        raise ConfigError(
            f"listen_addr must be host:port, got {addr!r}",
            detail=f"for example {DEFAULT_LISTEN_ADDR}",
        )
    host, _, port_text = addr.rpartition(":")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        raise ConfigError(
            f"listen_addr must name a host explicitly, got {addr!r}",
            detail=f"for example {DEFAULT_LISTEN_ADDR}",
        )
    try:
        port = int(port_text)
    except ValueError:
        raise ConfigError(f"listen_addr port must be an integer, got {port_text!r}") from None
    if not 1 <= port <= 65535:
        raise ConfigError(f"listen_addr port out of range: {port}")
    return host, port


@dataclass(frozen=True)
class Ca2aConfig:
    """Validated cA2A runtime configuration."""

    provider: str = "auto"
    enforcement_mode: str = "enforcing"
    require_caller_attestation: str = REQUIRE_NONE
    caller_verifier_platform: str | None = None
    caller_verifier_trusted_roots_path: str | None = None
    challenge_ttl_seconds: int = DEFAULT_TTL_SECONDS
    max_delegation_depth: int = 8
    policy_bundle_path: str | None = None
    local_policy: frozenset[str] | None = None
    listen_addr: str = DEFAULT_LISTEN_ADDR
    trusted_root_issuers: frozenset[str] = frozenset()
    agent_manifest_path: str | None = None
    agent_manifest_trust_anchor_path: str | None = None
    agent_manifest_authenticated_subject: str | None = None

    def listen_host_port(self) -> tuple[str, int]:
        """Return ``listen_addr`` split into the host and port to bind."""
        return split_listen_addr(self.listen_addr)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Ca2aConfig:
        attestation = data.get("attestation", {}) or {}
        provider = attestation.get("provider", "auto")
        enforcement = attestation.get("enforcement_mode", "enforcing")

        if provider not in VALID_PROVIDERS:
            raise ConfigError(
                f"unknown attestation provider: {provider!r}",
                detail=f"expected one of {sorted(VALID_PROVIDERS)}",
            )
        if enforcement not in VALID_ENFORCEMENT:
            raise ConfigError(
                f"unknown enforcement_mode: {enforcement!r}",
                detail=f"expected one of {sorted(VALID_ENFORCEMENT)}",
            )

        requirement = attestation.get("require_caller_attestation", REQUIRE_NONE)
        if requirement not in REQUIREMENT_VALUES:
            raise ConfigError(
                f"unknown attestation.require_caller_attestation: {requirement!r}",
                detail=f"expected one of {sorted(REQUIREMENT_VALUES)}",
            )

        verifier = attestation.get("caller_verifier")
        verifier_platform: str | None = None
        verifier_roots: str | None = None
        if verifier is not None:
            if not isinstance(verifier, dict):
                raise ConfigError("attestation.caller_verifier must be a mapping")
            verifier_platform = verifier.get("platform")
            verifier_roots = verifier.get("trusted_roots_path")
            if verifier_platform not in VALID_VERIFIER_PLATFORMS:
                raise ConfigError(
                    f"unknown attestation.caller_verifier.platform: {verifier_platform!r}",
                    detail=f"expected one of {sorted(VALID_VERIFIER_PLATFORMS)}",
                )
            if not isinstance(verifier_roots, str) or not verifier_roots:
                raise ConfigError(
                    "attestation.caller_verifier.trusted_roots_path must be a non-empty path",
                    detail="a PEM bundle of roots the caller's attestation key chain must reach",
                )
        if requirement == REQUIRE_HARDWARE and verifier is None:
            # PeerNode refuses this at construction too. Naming the config field
            # here means the operator sees which line to add, not which argument.
            raise ConfigError(
                "attestation.require_caller_attestation 'hardware' needs attestation.caller_verifier",
                detail="a hardware report cannot be appraised without one, so every call "
                "would be refused",
            )

        ttl = attestation.get("challenge_ttl_seconds", DEFAULT_TTL_SECONDS)
        if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1:
            raise ConfigError("attestation.challenge_ttl_seconds must be a positive integer")

        depth = data.get("max_delegation_depth", 8)
        if not isinstance(depth, int) or depth < 1:
            raise ConfigError("max_delegation_depth must be a positive integer")

        raw_local = data.get("local_policy")
        local_policy: frozenset[str] | None = None
        if raw_local is not None:
            if not isinstance(raw_local, list) or not all(
                isinstance(item, str) and item for item in raw_local
            ):
                raise ConfigError("local_policy must be a list of non-empty capability strings")
            local_policy = frozenset(raw_local)

        bundle = data.get("policy_bundle_path")
        if bundle is not None and not isinstance(bundle, str):
            raise ConfigError("policy_bundle_path must be a string path")

        listen_addr = data.get("listen_addr", DEFAULT_LISTEN_ADDR)
        split_listen_addr(listen_addr)

        raw_roots = data.get("trusted_root_issuers", [])
        if not isinstance(raw_roots, list) or not all(
            isinstance(item, str) and item for item in raw_roots
        ):
            raise ConfigError("trusted_root_issuers must be a list of non-empty public-key strings")

        manifest = data.get("agent_manifest", {}) or {}
        if not isinstance(manifest, dict):
            raise ConfigError("agent_manifest must be a mapping")
        manifest_path = manifest.get("path")
        trust_anchor_path = manifest.get("trust_anchor_path")
        authenticated_subject = manifest.get("authenticated_subject")
        for name, value in (
            ("path", manifest_path),
            ("trust_anchor_path", trust_anchor_path),
            ("authenticated_subject", authenticated_subject),
        ):
            if value is not None and not isinstance(value, str):
                raise ConfigError(f"agent_manifest.{name} must be a string")
        configured = [
            manifest_path is not None,
            trust_anchor_path is not None,
            authenticated_subject is not None,
        ]
        if any(configured) and not all(configured):
            raise ConfigError(
                "agent_manifest.path, trust_anchor_path, and authenticated_subject "
                "must be configured together"
            )
        if authenticated_subject is not None and not authenticated_subject.startswith("spiffe://"):
            raise ConfigError("agent_manifest.authenticated_subject must be a SPIFFE URI")

        return cls(
            provider=provider,
            enforcement_mode=enforcement,
            require_caller_attestation=requirement,
            caller_verifier_platform=verifier_platform,
            caller_verifier_trusted_roots_path=verifier_roots,
            challenge_ttl_seconds=ttl,
            max_delegation_depth=depth,
            policy_bundle_path=bundle,
            local_policy=local_policy,
            listen_addr=listen_addr,
            trusted_root_issuers=frozenset(raw_roots),
            agent_manifest_path=manifest_path,
            agent_manifest_trust_anchor_path=trust_anchor_path,
            agent_manifest_authenticated_subject=authenticated_subject,
        )

    @classmethod
    def load(cls, path: str | Path) -> Ca2aConfig:
        p = Path(path)
        if not p.is_file():
            raise ConfigError(f"config file not found: {p}")
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise ConfigError(f"invalid YAML in {p}", detail=str(exc)) from exc
        if not isinstance(data, dict):
            raise ConfigError(f"config root must be a mapping, got {type(data).__name__}")
        return cls.from_dict(data)
