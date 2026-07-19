"""Load a local Policy for the live peer listener from config."""

from __future__ import annotations

from pathlib import Path

from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import ConfigError
from ca2a_runtime.policy import LocalPolicy, Policy


def load_policy(config: Ca2aConfig, *, config_dir: Path | None = None) -> Policy:
    """Resolve the callee policy from ``local_policy`` or ``policy_bundle_path``.

    Cedar wins when ``policy_bundle_path`` is set. Otherwise ``local_policy``
    becomes a ``LocalPolicy`` allow set. At least one must be present for
    ``ca2a start``.
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

    raise ConfigError(
        "ca2a start requires local_policy or policy_bundle_path in the config",
    )
