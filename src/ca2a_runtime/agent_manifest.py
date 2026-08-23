"""Agent Manifest loading, verification, and runtime identity binding."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import agent_manifest as agent_manifest_sdk

from ca2a_runtime.errors import ConfigError

_B64URL_RE = re.compile(r"^[A-Za-z0-9\-_]*$")


@dataclass(frozen=True)
class LoadedAgentManifest:
    """A decoded manifest and the COSE envelope it arrived in, if any."""

    manifest: dict[str, Any]
    envelope: bytes | None = None


@dataclass(frozen=True)
class AgentManifestBinding:
    """Identity fields read only after Agent Manifest verification succeeds."""

    manifest_id: str
    agent_id: str
    issuer: str
    authenticated_subject: str
    version: str
    # CA2A authenticates the signed identity document here. It does not observe
    # or claim equality with the deployed artifact hashes bound by the manifest.
    verification_scope: str = "signature-and-identity"


def _b64url_decode(value: str) -> bytes:
    if not _B64URL_RE.fullmatch(value):
        raise ConfigError("Agent Manifest signature/key must use base64url encoding")
    padding = (-len(value)) % 4
    try:
        return base64.urlsafe_b64decode(value + "=" * padding)
    except ValueError as exc:
        raise ConfigError("Agent Manifest signature/key is not valid base64url") from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _key_id(public_key: bytes) -> str:
    return hashlib.sha256(public_key).hexdigest()


def load_agent_manifest_document(path: str | Path) -> LoadedAgentManifest:
    """Load JSON v0.1 or a v0.2 COSE envelope, sniffing content not suffix."""
    try:
        raw = Path(path).read_bytes()
    except OSError as exc:
        raise ConfigError(f"cannot read Agent Manifest: {exc}") from exc

    try:
        manifest = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError):
        try:
            decoded = agent_manifest_sdk.decode_cose_manifest(raw)
        except Exception as exc:  # noqa: BLE001 - SDK errors become config failures
            raise ConfigError(
                f"cannot read Agent Manifest: not JSON and not a COSE envelope ({exc})"
            ) from exc
        if not isinstance(decoded.manifest, dict):
            raise ConfigError("Agent Manifest COSE payload must be a JSON object") from None
        return LoadedAgentManifest(manifest=decoded.manifest, envelope=raw)

    if not isinstance(manifest, dict):
        raise ConfigError("Agent Manifest must be a JSON object")
    if manifest.get("version") == agent_manifest_sdk.COSE_MANIFEST_VERSION and (
        "signature" not in manifest
    ):
        raise ConfigError(
            "Agent Manifest declares version "
            f"{agent_manifest_sdk.COSE_MANIFEST_VERSION} but was supplied as bare JSON; "
            "v0.2 requires the COSE envelope"
        )
    return LoadedAgentManifest(manifest=manifest)


def load_agent_manifest_trust_anchor(path: str | Path) -> dict[str, bytes]:
    """Load one Ed25519 key or a ``keys`` array from a JSON trust-anchor file."""
    try:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read Agent Manifest trust anchor: {exc}") from exc

    items: list[Any]
    if isinstance(raw, dict) and "public_key_base64url" in raw:
        items = [raw]
    elif isinstance(raw, dict) and isinstance(raw.get("keys"), list):
        items = raw["keys"]
    else:
        raise ConfigError("Agent Manifest trust anchor must contain public_key_base64url or keys[]")

    anchors: dict[str, bytes] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ConfigError("Agent Manifest trust anchor keys must be objects")
        public_key = _b64url_decode(str(item.get("public_key_base64url", "")))
        if len(public_key) != 32:
            raise ConfigError("Agent Manifest trust anchor contains an invalid Ed25519 key")
        key_id = str(item.get("key_id") or _key_id(public_key))
        if key_id != _key_id(public_key):
            raise ConfigError("Agent Manifest trust anchor key_id does not match public key")
        anchors[key_id] = public_key
    return anchors


def verify_agent_manifest_binding(
    loaded: LoadedAgentManifest,
    trusted_keys: dict[str, bytes],
    *,
    authenticated_subject: str,
) -> AgentManifestBinding:
    """Verify the supplied artifact, then bind its identity to the configured subject."""
    sdk_keys = {key_id: _b64url_encode(key) for key_id, key in trusted_keys.items()}
    result = agent_manifest_sdk.verify_manifest(
        loaded.envelope if loaded.envelope is not None else loaded.manifest,
        agent_manifest_sdk.VerificationContext(
            trusted_keys=sdk_keys,
            strict_artifact_verification=False,
        ),
        agent_manifest_sdk.RevocationStore(),
    )
    if result.result != agent_manifest_sdk.OverallResult.VALID:
        warnings = "; ".join(getattr(result, "warnings", None) or [])
        detail = f": {warnings}" if warnings else ""
        raise ConfigError(f"Agent Manifest verification failed ({result.result.value}){detail}")
    if result.signature_verified is not True:
        raise ConfigError("Agent Manifest signature verification failed")

    manifest = loaded.manifest
    manifest_id = manifest.get("manifest_id")
    agent_id = manifest.get("agent_id")
    issuer = manifest.get("issuer")
    version = manifest.get("version")
    if not isinstance(manifest_id, str) or not manifest_id:
        raise ConfigError("Agent Manifest manifest_id is missing")
    if not isinstance(agent_id, str) or not agent_id.startswith("spiffe://"):
        raise ConfigError("Agent Manifest agent_id must be a SPIFFE URI")
    if not isinstance(issuer, str) or not issuer.startswith("spiffe://"):
        raise ConfigError("Agent Manifest issuer must be a SPIFFE URI")
    if not isinstance(version, str) or not version:
        raise ConfigError("Agent Manifest version is missing")
    if not authenticated_subject.startswith("spiffe://"):
        raise ConfigError("Agent Manifest authenticated_subject must be a SPIFFE URI")
    if authenticated_subject != agent_id:
        raise ConfigError("Agent Manifest agent_id does not match authenticated_subject")

    return AgentManifestBinding(
        manifest_id=manifest_id,
        agent_id=agent_id,
        issuer=issuer,
        authenticated_subject=authenticated_subject,
        version=version,
    )
