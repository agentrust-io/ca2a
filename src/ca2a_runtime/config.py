"""Runtime configuration for the cA2A peer runtime.

Defines and validates the configuration surface consumed by ``ca2a start``
and the offline CLI. See ROADMAP.md / LIMITATIONS.md for claim boundaries.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ca2a_runtime.errors import ConfigError

VALID_PROVIDERS = frozenset({"auto", "tpm", "sev-snp", "tdx", "opaque", "software-only"})
VALID_ENFORCEMENT = frozenset({"enforcing", "advisory", "silent"})

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
    max_delegation_depth: int = 8
    policy_bundle_path: str | None = None
    local_policy: frozenset[str] | None = None
    listen_addr: str = DEFAULT_LISTEN_ADDR

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

        return cls(
            provider=provider,
            enforcement_mode=enforcement,
            max_delegation_depth=depth,
            policy_bundle_path=bundle,
            local_policy=local_policy,
            listen_addr=listen_addr,
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
