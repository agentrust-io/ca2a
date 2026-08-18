"""Agent Manifest v0.1/v0.2 consumption through ca2a's startup binding path."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import agent_manifest as sdk
import pytest

from ca2a_runtime.agent_manifest import (
    load_agent_manifest_document,
    load_agent_manifest_trust_anchor,
    verify_agent_manifest_binding,
)
from ca2a_runtime.bootstrap import build_peer_node
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import ConfigError

AGENT_ID = "spiffe://factory.example/agent/ca2a/dev"
ISSUER = "spiffe://factory.example/signing-authority/development"


def _manifest(version: str) -> dict:
    return {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000315",
        "agent_id": AGENT_ID,
        "version": version,
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": "2099-09-10T00:00:00Z",
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {},
    }


def _cose() -> tuple[bytes, dict, str, bytes]:
    keypair = sdk.generate_ed25519()
    manifest = _manifest("0.2")
    return (
        sdk.sign_manifest_cose(manifest, keypair),
        manifest,
        keypair.key_id,
        keypair.public_bytes,
    )


def _v01() -> tuple[dict, str, bytes]:
    keypair = sdk.generate_ed25519()
    manifest = _manifest("0.1")
    manifest["@context"] = "https://agentmanifest.agentrust-io.com/v0.1/context.json"
    manifest["signature"] = sdk.Ed25519Signer(keypair).sign(manifest)
    return manifest, keypair.key_id, keypair.public_bytes


def _trust_file(path: Path, key_id: str, public_key: bytes) -> Path:
    path.write_text(
        json.dumps(
            {
                "key_id": key_id,
                "public_key_base64url": base64.urlsafe_b64encode(public_key).rstrip(b"=").decode(),
            }
        ),
        encoding="utf-8",
    )
    return path


def test_v02_cose_binds_end_to_end(tmp_path: Path) -> None:
    envelope, manifest, key_id, public_key = _cose()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)

    loaded = load_agent_manifest_document(path)
    binding = verify_agent_manifest_binding(
        loaded, {key_id: public_key}, authenticated_subject=AGENT_ID
    )

    assert loaded.envelope == envelope
    assert binding.manifest_id == manifest["manifest_id"]
    assert binding.agent_id == AGENT_ID
    assert binding.version == "0.2"


def test_v01_json_still_binds(tmp_path: Path) -> None:
    manifest, key_id, public_key = _v01()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    binding = verify_agent_manifest_binding(
        load_agent_manifest_document(path),
        {key_id: public_key},
        authenticated_subject=AGENT_ID,
    )
    assert binding.version == "0.1"


def test_v02_bare_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(_manifest("0.2")), encoding="utf-8")
    with pytest.raises(ConfigError, match="COSE envelope"):
        load_agent_manifest_document(path)


def test_tampered_cose_is_rejected(tmp_path: Path) -> None:
    envelope, _manifest_doc, key_id, public_key = _cose()
    tampered = bytearray(envelope)
    tampered[len(tampered) // 2] ^= 1
    path = tmp_path / "manifest.cose"
    path.write_bytes(tampered)

    try:
        loaded = load_agent_manifest_document(path)
    except ConfigError:
        return
    with pytest.raises(ConfigError, match="verification failed"):
        verify_agent_manifest_binding(loaded, {key_id: public_key}, authenticated_subject=AGENT_ID)


def test_untrusted_cose_is_rejected(tmp_path: Path) -> None:
    envelope, _manifest_doc, _key_id, _public_key = _cose()
    other = sdk.generate_ed25519()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)
    with pytest.raises(ConfigError, match="verification failed"):
        verify_agent_manifest_binding(
            load_agent_manifest_document(path),
            {other.key_id: other.public_bytes},
            authenticated_subject=AGENT_ID,
        )


def test_subject_mismatch_is_rejected(tmp_path: Path) -> None:
    envelope, _manifest_doc, key_id, public_key = _cose()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)
    with pytest.raises(ConfigError, match="does not match"):
        verify_agent_manifest_binding(
            load_agent_manifest_document(path),
            {key_id: public_key},
            authenticated_subject="spiffe://factory.example/agent/other/dev",
        )


def test_startup_carries_verified_manifest_binding(tmp_path: Path) -> None:
    envelope, manifest, key_id, public_key = _cose()
    manifest_path = tmp_path / "manifest.cose"
    manifest_path.write_bytes(envelope)
    trust_path = _trust_file(tmp_path / "manifest-key.json", key_id, public_key)
    config = Ca2aConfig(
        provider="software-only",
        local_policy=frozenset({"read"}),
        trusted_root_issuers=frozenset({"delegation-root"}),
        agent_manifest_path=manifest_path.name,
        agent_manifest_trust_anchor_path=trust_path.name,
        agent_manifest_authenticated_subject=AGENT_ID,
    )

    node = build_peer_node(config, config_dir=tmp_path)

    assert node.agent_manifest is not None
    assert node.agent_manifest.manifest_id == manifest["manifest_id"]
    assert node.agent_manifest.agent_id == AGENT_ID


def test_trust_anchor_key_id_must_match_key(tmp_path: Path) -> None:
    keypair = sdk.generate_ed25519()
    path = _trust_file(tmp_path / "manifest-key.json", "0" * 64, keypair.public_bytes)
    with pytest.raises(ConfigError, match="key_id does not match"):
        load_agent_manifest_trust_anchor(path)
