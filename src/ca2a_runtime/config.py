"""Runtime configuration for the cA2A peer runtime.

The runtime peer path is under construction (see ROADMAP.md); this module
defines and validates the configuration surface it will consume.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ca2a_runtime.errors import ConfigError

VALID_PROVIDERS = frozenset(
    {"auto", "tpm", "sev-snp", "tdx", "opaque", "software-only"}
)
VALID_ENFORCEMENT = frozenset({"enforcing", "advisory", "silent"})


@dataclass(frozen=True)
class Ca2aConfig:
    """Validated cA2A runtime configuration."""

    provider: str = "auto"
    enforcement_mode: str = "enforcing"
    max_delegation_depth: int = 8
    policy_bundle_path: str | None = None
    listen_addr: str = "0.0.0.0:8443"

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

        return cls(
            provider=provider,
            enforcement_mode=enforcement,
            max_delegation_depth=depth,
            policy_bundle_path=data.get("policy_bundle_path"),
            listen_addr=data.get("listen_addr", "0.0.0.0:8443"),
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
