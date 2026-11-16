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
# Private JWK members (RFC 7517/7518) and the raw-key spellings, as cMCP refuses.
_PRIVATE_KEY_MEMBERS = frozenset(
    {"d", "p", "q", "dp", "dq", "qi", "oth", "k", "private_key", "private_key_base64url"}
)

# SPIFFE ID grammar (SPIFFE ID specification, section 2), as cMCP checks it: a
# trust domain of lowercase letters, digits, ".", "-" and "_", then optional
# path segments of letters, digits, ".", "-" and "_", none empty, "." or "..".
_SPIFFE_SCHEME = "spiffe://"
_SPIFFE_TRUST_DOMAIN = re.compile(r"[a-z0-9._-]{1,255}")
_SPIFFE_PATH_SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
_MAX_SPIFFE_ID_BYTES = 2048


def _is_spiffe_id(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith(_SPIFFE_SCHEME):
        return False
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:  # a lone surrogate survives json.loads
        return False
    if len(encoded) > _MAX_SPIFFE_ID_BYTES:
        return False
    trust_domain, has_path, path = value[len(_SPIFFE_SCHEME) :].partition("/")
    if not _SPIFFE_TRUST_DOMAIN.fullmatch(trust_domain):
        return False
    if not has_path:
        return True
    return all(
        _SPIFFE_PATH_SEGMENT.fullmatch(segment) and segment not in {".", ".."}
        for segment in path.split("/")
    )


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
    """Decode canonical unpadded base64url, as cMCP does: a length of 1 mod 4 is
    never valid, and a value whose unused bits are set re-encodes differently."""
    if len(value) % 4 == 1 or not _B64URL_RE.fullmatch(value):
        raise ConfigError("Agent Manifest signature/key must use base64url encoding")
    raw = base64.urlsafe_b64decode(value + "=" * ((-len(value)) % 4))
    if _b64url_encode(raw) != value:
        raise ConfigError("Agent Manifest signature/key must use base64url encoding")
    return raw


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
    """Load only the keys of a JSON trust-anchor file, without the issuer policy.

    Not for verification: a binding needs the policy too, so use
    load_agent_manifest_trust_policy there.
    """
    return load_agent_manifest_trust_policy(path)[0]


def _no_constant(text: str) -> Any:
    raise ValueError(f"non-standard JSON constant not allowed: {text}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key {key!r}")
        out[key] = value
    return out


def load_agent_manifest_trust_policy(
    path: str | Path,
) -> tuple[dict[str, bytes], dict[str, list[str]] | None]:
    """Load a trust anchor's keys and the issuers each key may sign for (spec 5.3.3).

    Same format as cMCP: one key, or a ``keys`` array, each with
    ``public_key_base64url``, an optional ``key_id`` and an ``issuers`` list of
    SPIFFE IDs. A key with no ``issuers`` may sign for no issuer. The policy is
    None when no key declares ``issuers``; binding refuses that.
    """
    try:
        raw = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=_no_duplicate_keys,
            parse_constant=_no_constant,
        )
    except (OSError, ValueError) as exc:
        raise ConfigError(f"cannot read Agent Manifest trust anchor: {exc}") from exc

    items: list[Any]
    if isinstance(raw, dict) and "public_key_base64url" in raw:
        items = [raw]
    elif isinstance(raw, dict) and isinstance(raw.get("keys"), list):
        items = raw["keys"]
    else:
        raise ConfigError("Agent Manifest trust anchor must contain public_key_base64url or keys[]")

    anchors: dict[str, bytes] = {}
    policy: dict[str, list[str]] = {}
    declared = False
    for item in items:
        if not isinstance(item, dict):
            raise ConfigError("Agent Manifest trust anchor keys must be objects")
        if _PRIVATE_KEY_MEMBERS.intersection(item):
            raise ConfigError("Agent Manifest trust anchor must not contain private keys")
        public_key = _b64url_decode(str(item.get("public_key_base64url", "")))
        if len(public_key) != 32:
            raise ConfigError("Agent Manifest trust anchor contains an invalid Ed25519 key")
        key_id = str(item.get("key_id") or _key_id(public_key))
        if key_id != _key_id(public_key):
            raise ConfigError("Agent Manifest trust anchor key_id does not match public key")
        if key_id in anchors:
            raise ConfigError(f"Agent Manifest trust anchor repeats key_id {key_id!r}")
        anchors[key_id] = public_key
        if "issuers" not in item:
            continue
        declared = True
        issuers = item["issuers"]
        if not isinstance(issuers, list) or not all(_is_spiffe_id(i) for i in issuers):
            raise ConfigError("Agent Manifest trust anchor issuers must be a list of SPIFFE IDs")
        policy[key_id] = list(issuers)
    return anchors, (policy if declared else None)


def verify_agent_manifest_binding(
    loaded: LoadedAgentManifest,
    trusted_keys: dict[str, bytes],
    *,
    authenticated_subject: str,
    trusted_key_issuers: dict[str, list[str]] | None,
) -> AgentManifestBinding:
    """Verify the supplied artifact, then bind its identity to the configured subject.

    *trusted_key_issuers* maps each key_id to the issuers it may sign for, as
    load_agent_manifest_trust_policy returns it. It has no default, so no caller
    can leave it out by accident. None, an anchor that declares no issuers, is
    refused: without it nothing says which issuer a key speaks for (spec 5.3.3).
    """
    if trusted_key_issuers is None:
        raise ConfigError(
            "Agent Manifest trust anchor must list the issuers each key may sign for "
            "(an 'issuers' array per key, spec 5.3.3)"
        )
    sdk_keys = {key_id: _b64url_encode(key) for key_id, key in trusted_keys.items()}
    result = agent_manifest_sdk.verify_manifest(
        loaded.envelope if loaded.envelope is not None else loaded.manifest,
        agent_manifest_sdk.VerificationContext(
            trusted_keys=sdk_keys,
            trusted_key_issuers=trusted_key_issuers,
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
