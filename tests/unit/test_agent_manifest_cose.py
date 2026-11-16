"""Agent Manifest v0.1/v0.2 consumption through ca2a's startup binding path."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import agent_manifest as sdk
import pytest
from agent_manifest import _cose as sdk_cose

from ca2a_runtime.agent_manifest import (
    load_agent_manifest_document,
    load_agent_manifest_trust_anchor,
    load_agent_manifest_trust_policy,
    verify_agent_manifest_binding,
)
from ca2a_runtime.bootstrap import build_peer_node
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import ConfigError

AGENT_ID = "spiffe://factory.example/agent/ca2a/dev"
ISSUER = "spiffe://factory.example/signing-authority/development"
EXPIRES_AT = (datetime.now(UTC) + timedelta(days=30)).isoformat().replace("+00:00", "Z")


def _manifest(version: str) -> dict:
    return {
        "@context": "https://manifest.agentrust-io.com/v0.2/context.json",
        "@type": "AgentManifest",
        "manifest_id": "0197739a-8c00-7000-8000-000000000315",
        "agent_id": AGENT_ID,
        "version": version,
        "issued_at": "2026-06-12T00:00:00Z",
        "expires_at": EXPIRES_AT,
        "issuer": ISSUER,
        "crypto_profile": "standard",
        "artifacts": {
            "system_prompt": {"hash": "sha256:" + "a" * 64},
            "policy_bundle": {"hash": "sha256:" + "b" * 64},
            "model_identity": {
                "version": "ca2a-test-model",
                "deployment_type": "api",
            },
        },
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


def _trust_file(
    path: Path, key_id: str, public_key: bytes, issuers: list[str] | None = None
) -> Path:
    entry = {
        "key_id": key_id,
        "public_key_base64url": base64.urlsafe_b64encode(public_key).rstrip(b"=").decode(),
    }
    if issuers is not None:
        entry["issuers"] = issuers
    path.write_text(json.dumps(entry), encoding="utf-8")
    return path


def test_v02_cose_binds_end_to_end(tmp_path: Path) -> None:
    envelope, manifest, key_id, public_key = _cose()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)

    loaded = load_agent_manifest_document(path)
    binding = verify_agent_manifest_binding(
        loaded,
        {key_id: public_key},
        authenticated_subject=AGENT_ID,
        trusted_key_issuers={key_id: [ISSUER]},
    )

    assert loaded.envelope == envelope
    assert binding.manifest_id == manifest["manifest_id"]
    assert binding.agent_id == AGENT_ID
    assert binding.version == "0.2"
    assert binding.verification_scope == "signature-and-identity"


def test_v01_json_still_binds(tmp_path: Path) -> None:
    manifest, key_id, public_key = _v01()
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest), encoding="utf-8")

    binding = verify_agent_manifest_binding(
        load_agent_manifest_document(path),
        {key_id: public_key},
        authenticated_subject=AGENT_ID,
        trusted_key_issuers={key_id: [ISSUER]},
    )
    assert binding.version == "0.1"


def test_v02_bare_json_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(_manifest("0.2")), encoding="utf-8")
    with pytest.raises(ConfigError, match="COSE envelope"):
        load_agent_manifest_document(path)


def test_v01_payload_inside_v02_envelope_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AM-VEC-COSE-012 through cA2A's own startup loader."""
    keypair = sdk.generate_ed25519()
    manifest = _manifest("0.1")
    manifest["@context"] = "https://agentmanifest.agentrust-io.com/v0.1/context.json"

    # Bypass only the producer guard to construct the adversarial signed wire
    # artifact. The consumer decoder and verifier remain unmodified.
    monkeypatch.setattr(sdk_cose, "_require_v02", lambda _manifest: None)
    path = tmp_path / "v01-in-v02.cose"
    path.write_bytes(sdk.sign_manifest_cose(manifest, keypair))

    with pytest.raises(ConfigError, match="payload declares manifest version 0.1"):
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
        verify_agent_manifest_binding(
            loaded,
            {key_id: public_key},
            authenticated_subject=AGENT_ID,
            trusted_key_issuers={key_id: [ISSUER]},
        )


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
            trusted_key_issuers={other.key_id: [ISSUER]},
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
            trusted_key_issuers={key_id: [ISSUER]},
        )


def test_startup_carries_verified_manifest_binding(tmp_path: Path) -> None:
    envelope, manifest, key_id, public_key = _cose()
    manifest_path = tmp_path / "manifest.cose"
    manifest_path.write_bytes(envelope)
    trust_path = _trust_file(tmp_path / "manifest-key.json", key_id, public_key, [ISSUER])
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


def _cose_file(tmp_path: Path) -> tuple[Path, str, bytes]:
    envelope, _manifest_doc, key_id, public_key = _cose()
    path = tmp_path / "manifest.cose"
    path.write_bytes(envelope)
    return path, key_id, public_key


def test_binding_without_issuer_policy_is_refused(tmp_path: Path) -> None:
    path, key_id, public_key = _cose_file(tmp_path)
    with pytest.raises(ConfigError, match="issuers each key may sign for"):
        verify_agent_manifest_binding(
            load_agent_manifest_document(path),
            {key_id: public_key},
            authenticated_subject=AGENT_ID,
            trusted_key_issuers=None,
        )


def test_issuer_policy_cannot_be_left_out(tmp_path: Path) -> None:
    path, key_id, public_key = _cose_file(tmp_path)
    with pytest.raises(TypeError, match="trusted_key_issuers"):
        verify_agent_manifest_binding(  # type: ignore[call-arg]
            load_agent_manifest_document(path), {key_id: public_key}, authenticated_subject=AGENT_ID
        )


# ── Two keys, two issuers: each key binds only for its own ───────────────────

ISSUER_B = "spiffe://factory.example/signing-authority/b"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _signed_by(tmp_path: Path, keypair, issuer: str, name: str, version: str = "0.2") -> Path:
    manifest = _manifest(version)
    manifest["issuer"] = issuer
    path = tmp_path / name
    if version == "0.2":
        path.write_bytes(sdk.sign_manifest_cose(manifest, keypair))
    else:
        manifest["@context"] = "https://agentmanifest.agentrust-io.com/v0.1/context.json"
        manifest["signature"] = sdk.Ed25519Signer(keypair).sign(manifest)
        path.write_text(json.dumps(manifest), encoding="utf-8")
    return path


def _anchor(tmp_path: Path, entries: list[dict]) -> Path:
    path = tmp_path / "anchor.json"
    path.write_text(json.dumps({"keys": entries}), encoding="utf-8")
    return path


def _bind(manifest_path: Path, anchor_path: Path):
    keys, policy = load_agent_manifest_trust_policy(anchor_path)
    return verify_agent_manifest_binding(
        load_agent_manifest_document(manifest_path),
        keys,
        authenticated_subject=AGENT_ID,
        trusted_key_issuers=policy,
    )


_B_POLICIES = {
    "own-issuer": {"issuers": [ISSUER_B]},
    "no-issuers-member": {},
    "empty-list": {"issuers": []},
    "a-issuer-only": {"issuers": [ISSUER]},
}


@pytest.mark.parametrize("version", ["0.1", "0.2"])
@pytest.mark.parametrize("b_policy", list(_B_POLICIES))
@pytest.mark.parametrize(
    "signer, claimed",
    [("a", ISSUER), ("a", ISSUER_B), ("b", ISSUER), ("b", ISSUER_B)],
)
def test_each_key_binds_only_for_issuers_listed_against_it(
    tmp_path: Path, b_policy: str, signer: str, claimed: str, version: str
) -> None:
    a, b = sdk.generate_ed25519(), sdk.generate_ed25519()
    anchor = _anchor(
        tmp_path,
        [
            {"key_id": a.key_id, "public_key_base64url": _b64(a.public_bytes), "issuers": [ISSUER]},
            {
                "key_id": b.key_id,
                "public_key_base64url": _b64(b.public_bytes),
                **_B_POLICIES[b_policy],
            },
        ],
    )
    manifest = _signed_by(tmp_path, a if signer == "a" else b, claimed, "m", version)
    allowed = {"a": [ISSUER], "b": _B_POLICIES[b_policy].get("issuers", [])}[signer]
    if claimed in allowed:
        assert _bind(manifest, anchor).agent_id == AGENT_ID
    else:
        with pytest.raises(ConfigError):
            _bind(manifest, anchor)


def test_an_anchor_whose_keys_all_list_no_issuer_binds_nothing(tmp_path: Path) -> None:
    """Every key declares `issuers: []`: the policy exists and authorizes no one."""
    path, key_id, public_key = _cose_file(tmp_path)
    anchor = _anchor(
        tmp_path, [{"key_id": key_id, "public_key_base64url": _b64(public_key), "issuers": []}]
    )
    assert load_agent_manifest_trust_policy(anchor)[1] == {key_id: []}
    with pytest.raises(ConfigError):
        _bind(path, anchor)
    config = Ca2aConfig(
        provider="software-only",
        local_policy=frozenset({"read"}),
        trusted_root_issuers=frozenset({"delegation-root"}),
        agent_manifest_path=path.name,
        agent_manifest_trust_anchor_path=anchor.name,
        agent_manifest_authenticated_subject=AGENT_ID,
    )
    with pytest.raises(ConfigError):
        build_peer_node(config, config_dir=tmp_path)


def test_a_hybrid_manifest_needs_its_second_signer_trusted(tmp_path: Path) -> None:
    """Trust anchors hold Ed25519 keys, so the ML-DSA signer of a hybrid
    COSE_Sign is never trusted and the manifest does not bind."""
    from agent_manifest import _signing

    if not _signing.ml_dsa65_available():
        pytest.skip("ML-DSA-65 backend not installed")
    keypair = _signing.generate_hybrid()
    path = tmp_path / "hybrid.cose"
    path.write_bytes(sdk.sign_cose_sign_hybrid(_manifest("0.2"), keypair))
    ed = keypair.ed25519
    anchor = _anchor(
        tmp_path,
        [{"key_id": ed.key_id, "public_key_base64url": _b64(ed.public_bytes), "issuers": [ISSUER]}],
    )
    with pytest.raises(ConfigError):
        _bind(path, anchor)


def test_key_authorized_for_another_issuer_is_refused(tmp_path: Path) -> None:
    path, key_id, public_key = _cose_file(tmp_path)
    with pytest.raises(ConfigError, match="verification failed"):
        verify_agent_manifest_binding(
            load_agent_manifest_document(path),
            {key_id: public_key},
            authenticated_subject=AGENT_ID,
            trusted_key_issuers={key_id: ["spiffe://factory.example/signing-authority/other"]},
        )


def test_startup_refuses_an_anchor_without_issuers(tmp_path: Path) -> None:
    path, key_id, public_key = _cose_file(tmp_path)
    trust_path = _trust_file(tmp_path / "manifest-key.json", key_id, public_key)
    config = Ca2aConfig(
        provider="software-only",
        local_policy=frozenset({"read"}),
        trusted_root_issuers=frozenset({"delegation-root"}),
        agent_manifest_path=path.name,
        agent_manifest_trust_anchor_path=trust_path.name,
        agent_manifest_authenticated_subject=AGENT_ID,
    )
    with pytest.raises(ConfigError, match="issuers each key may sign for"):
        build_peer_node(config, config_dir=tmp_path)


def test_trust_policy_reads_issuers_per_key(tmp_path: Path) -> None:
    keypair = sdk.generate_ed25519()
    path = _trust_file(tmp_path / "k.json", keypair.key_id, keypair.public_bytes, [ISSUER])
    keys, policy = load_agent_manifest_trust_policy(path)
    assert keys == {keypair.key_id: keypair.public_bytes}
    assert policy == {keypair.key_id: [ISSUER]}
    assert load_agent_manifest_trust_anchor(path) == keys


@pytest.mark.parametrize(
    "mutate, message",
    [
        (lambda e: {**e, "issuers": ["not-a-spiffe-id"]}, "list of SPIFFE IDs"),
        (lambda e: {**e, "issuers": ISSUER}, "list of SPIFFE IDs"),
        (lambda e: {**e, "d": "AAAA"}, "private keys"),
        (lambda e: {"keys": [e, e]}, "repeats key_id"),
    ]
    + [
        (lambda e, m=member: {**e, m: "AAAA"}, "private keys")
        for member in ("p", "q", "dp", "dq", "qi", "oth", "k", "private_key")
    ]
    + [
        (lambda e, i=bad: {**e, "issuers": [i]}, "list of SPIFFE IDs")
        for bad in (
            "spiffe://Example.org/issuer",  # trust domain must be lowercase
            "spiffe://example.org/../issuer",
            "spiffe://example.org/a//b",
            "spiffe://example.org/issuer/",
            "spiffe://example.org:443/issuer",
            "spiffe://user@example.org/issuer",
            "spiffe://example.org/is suer",
            "spiffe://example.org/" + "a" * 2048,
            "spiffe://",
        )
    ],
)
def test_trust_policy_refuses_bad_entries(tmp_path: Path, mutate, message: str) -> None:
    keypair = sdk.generate_ed25519()
    entry = {
        "key_id": keypair.key_id,
        "public_key_base64url": base64.urlsafe_b64encode(keypair.public_bytes)
        .rstrip(b"=")
        .decode(),
        "issuers": [ISSUER],
    }
    path = tmp_path / "k.json"
    path.write_text(json.dumps(mutate(entry)), encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_agent_manifest_trust_policy(path)


def test_trust_policy_accepts_a_trust_domain_issuer(tmp_path: Path) -> None:
    keypair = sdk.generate_ed25519()
    path = _trust_file(
        tmp_path / "k.json", keypair.key_id, keypair.public_bytes, ["spiffe://example.org"]
    )
    assert load_agent_manifest_trust_policy(path)[1] == {keypair.key_id: ["spiffe://example.org"]}


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_trust_policy_refuses_non_standard_constants(tmp_path: Path, constant: str) -> None:
    path = tmp_path / "k.json"
    path.write_text(f'{{"public_key_base64url": "AA", "x": {constant}}}', encoding="utf-8")
    with pytest.raises(ConfigError, match="non-standard JSON constant"):
        load_agent_manifest_trust_policy(path)


@pytest.mark.parametrize(
    "encoded",
    [
        "A",  # length 1 mod 4 never decodes
        "AB",  # unused bits set: canonical is "AA"
        "AAF",  # unused bits set: canonical is "AAE"
        "AA==",  # padded
        "AA+A",  # standard alphabet
        "A A",
    ],
)
def test_trust_anchor_key_must_be_canonical_base64url(tmp_path: Path, encoded: str) -> None:
    path = tmp_path / "k.json"
    path.write_text(
        json.dumps({"public_key_base64url": encoded, "issuers": [ISSUER]}), encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="base64url"):
        load_agent_manifest_trust_policy(path)


@pytest.mark.parametrize(
    "content, message",
    [
        (b"\xff\xfe{}", "(?i)cannot read"),
        (b"[]", "public_key_base64url or keys"),
        (b"7", "public_key_base64url or keys"),
        (b'{"keys": "x"}', "public_key_base64url or keys"),
        (b'{"keys": [7]}', "must be objects"),
    ],
    ids=["invalid-utf8", "array", "number", "keys-not-list", "entry-not-object"],
)
def test_malformed_trust_anchor_files_are_refused(
    tmp_path: Path, content: bytes, message: str
) -> None:
    path = tmp_path / "k.json"
    path.write_bytes(content)
    with pytest.raises(ConfigError, match=message):
        load_agent_manifest_trust_policy(path)


def test_an_anchor_with_no_keys_binds_nothing(tmp_path: Path) -> None:
    """As in cMCP: it loads as no keys and no policy, and binding refuses it."""
    path, _key_id, _public_key = _cose_file(tmp_path)
    anchor = tmp_path / "k.json"
    anchor.write_text('{"keys": []}', encoding="utf-8")
    assert load_agent_manifest_trust_policy(anchor) == ({}, None)
    with pytest.raises(ConfigError, match="issuers each key may sign for"):
        _bind(path, anchor)


def test_one_bad_entry_refuses_the_whole_anchor(tmp_path: Path) -> None:
    good = sdk.generate_ed25519()
    path = _anchor(
        tmp_path,
        [
            {
                "key_id": good.key_id,
                "public_key_base64url": _b64(good.public_bytes),
                "issuers": [ISSUER],
            },
            {"public_key_base64url": "AB", "issuers": [ISSUER]},
        ],
    )
    with pytest.raises(ConfigError):
        load_agent_manifest_trust_policy(path)


def test_startup_refuses_a_malformed_issuer_policy(tmp_path: Path) -> None:
    path, key_id, public_key = _cose_file(tmp_path)
    anchor = _anchor(
        tmp_path, [{"key_id": key_id, "public_key_base64url": _b64(public_key), "issuers": ["x"]}]
    )
    config = Ca2aConfig(
        provider="software-only",
        local_policy=frozenset({"read"}),
        trusted_root_issuers=frozenset({"delegation-root"}),
        agent_manifest_path=path.name,
        agent_manifest_trust_anchor_path=anchor.name,
        agent_manifest_authenticated_subject=AGENT_ID,
    )
    with pytest.raises(ConfigError, match="SPIFFE"):
        build_peer_node(config, config_dir=tmp_path)


def test_trust_policy_refuses_duplicate_json_keys(tmp_path: Path) -> None:
    path = tmp_path / "k.json"
    path.write_text(
        '{"public_key_base64url": "AA", "public_key_base64url": "BB"}', encoding="utf-8"
    )
    with pytest.raises(ConfigError, match="duplicate JSON key"):
        load_agent_manifest_trust_policy(path)


# ── Review round 2 ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "text, message",
    [
        ('{"version": "0.1", "issuer": "a", "issuer": "b"}', "duplicate JSON key"),
        ('{"version": "0.1", "n": NaN}', "non-standard JSON constant"),
    ],
    ids=["duplicate-member", "nan"],
)
def test_a_manifest_that_is_not_one_json_document_is_refused(
    tmp_path: Path, text: str, message: str
) -> None:
    """Two readers must not see two documents behind one signature."""
    path = tmp_path / "manifest.json"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match=message):
        load_agent_manifest_document(path)


@pytest.mark.parametrize(
    "edit, message",
    [
        ({"public_key_base64url": None}, "must be a string"),
        ({"public_key_base64url": 123}, "must be a string"),
        ({"key_id": None}, "non-empty string"),
        ({"key_id": ""}, "non-empty string"),
        ({"key_id": False}, "non-empty string"),
        ({"key_id": 7}, "non-empty string"),
    ],
    ids=["key-null", "key-number", "id-null", "id-empty", "id-false", "id-number"],
)
def test_trust_anchor_members_keep_their_types(tmp_path: Path, edit: dict, message: str) -> None:
    keypair = sdk.generate_ed25519()
    entry = {
        "key_id": keypair.key_id,
        "public_key_base64url": _b64(keypair.public_bytes),
        "issuers": [ISSUER],
        **edit,
    }
    path = _anchor(tmp_path, [entry])
    with pytest.raises(ConfigError, match=message):
        load_agent_manifest_trust_policy(path)


def test_a_duplicate_member_inside_a_key_entry_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "k.json"
    path.write_text(
        '{"keys": [{"public_key_base64url": "AA", "issuers": [], "issuers": []}]}',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="duplicate JSON key"):
        load_agent_manifest_trust_policy(path)


@pytest.mark.parametrize(
    "policy",
    [["spiffe://x.example/i"], {"k": "spiffe://x.example/i"}, {"k": ["not-spiffe"]}, {1: []}],
    ids=["list", "issuers-not-list", "issuer-not-spiffe", "key-not-string"],
)
def test_a_policy_passed_directly_is_held_to_the_loaders_shape(tmp_path: Path, policy) -> None:
    path, key_id, public_key = _cose_file(tmp_path)
    with pytest.raises(ConfigError, match="trusted_key_issuers must map"):
        verify_agent_manifest_binding(
            load_agent_manifest_document(path),
            {key_id: public_key},
            authenticated_subject=AGENT_ID,
            trusted_key_issuers=policy,
        )


def test_startup_binds_with_a_single_key_anchor(tmp_path: Path) -> None:
    path, key_id, public_key = _cose_file(tmp_path)
    anchor = _trust_file(tmp_path / "manifest-key.json", key_id, public_key, [ISSUER])
    config = Ca2aConfig(
        provider="software-only",
        local_policy=frozenset({"read"}),
        trusted_root_issuers=frozenset({"delegation-root"}),
        agent_manifest_path=path.name,
        agent_manifest_trust_anchor_path=anchor.name,
        agent_manifest_authenticated_subject=AGENT_ID,
    )
    assert build_peer_node(config, config_dir=tmp_path) is not None
