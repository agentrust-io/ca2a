"""Unit tests for the A2A SendMessage <-> PeerRequest transport adapter."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from ca2a_runtime.errors import TransportError
from ca2a_runtime.peer import PeerRequest
from ca2a_runtime.transport import (
    EXTENSION_URI,
    KEY_DELEGATION_CHAIN,
    KEY_PARENT_RECORD_HASH,
    KEY_RECORD_ID,
    KEY_REQUESTED_CAPABILITY,
    KEY_SEALED_PAYLOAD,
    attach_ca2a_metadata,
    has_ca2a_metadata,
    parse_peer_request,
)
from tests.unit.conftest import build_chain

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "a2a"


def _cred_dicts(scopes: list[frozenset[str]]) -> list[dict]:
    chain = build_chain(scopes)
    return [
        {
            **c.body(),
            "signature": c.signature,
        }
        for c in chain
    ]


def _ca2a_meta(
    *,
    chain: list[dict] | None = None,
    capability: str = "read",
    record_id: str = "rec-0",
    parent_record_hash: str | None = None,
    sealed_payload: str | None = None,
    include_sealed: bool = False,
) -> dict:
    meta = {
        KEY_DELEGATION_CHAIN: chain
        if chain is not None
        else _cred_dicts(
            [frozenset({"read", "write"}), frozenset({"read"})]
        ),
        KEY_REQUESTED_CAPABILITY: capability,
        KEY_RECORD_ID: record_id,
        KEY_PARENT_RECORD_HASH: parent_record_hash,
    }
    if include_sealed or sealed_payload is not None:
        meta[KEY_SEALED_PAYLOAD] = sealed_payload
    return meta


def test_parse_valid_root_to_leaf_from_send_message() -> None:
    envelope = json.loads((FIXTURES / "send_message_ca2a.json").read_text(encoding="utf-8"))
    # Fixture uses placeholder credentials; build a live signed chain into a copy.
    chain = _cred_dicts([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])
    envelope["params"]["message"]["metadata"][KEY_DELEGATION_CHAIN] = chain
    envelope["params"]["message"]["metadata"][KEY_REQUESTED_CAPABILITY] = "read"
    envelope["params"]["message"]["metadata"][KEY_RECORD_ID] = "rec-live"
    envelope["params"]["message"]["metadata"][KEY_PARENT_RECORD_HASH] = None

    req = parse_peer_request(envelope)
    assert req is not None
    assert req.requested_capability == "read"
    assert req.record_id == "rec-live"
    assert req.parent_record_hash is None
    assert req.sealed_payload is None
    assert len(req.chain) == 2
    assert req.chain[-1].scope == frozenset({"read", "write"})


def test_no_ca2a_extension_returns_none() -> None:
    message = {
        "messageId": "1",
        "role": "user",
        "parts": [{"text": "hello"}],
        "metadata": {"https://example.com/ext/other/v1/flag": True},
    }
    assert parse_peer_request(message) is None
    assert not has_ca2a_metadata(message["metadata"])


def test_missing_delegation_chain_fails_closed() -> None:
    meta = _ca2a_meta()
    del meta[KEY_DELEGATION_CHAIN]
    with pytest.raises(TransportError) as exc:
        parse_peer_request({"metadata": meta})
    assert exc.value.code == "TRANSPORT_ERROR"


def test_empty_delegation_chain_fails_closed() -> None:
    with pytest.raises(TransportError):
        parse_peer_request({"metadata": _ca2a_meta(chain=[])})


def test_invalid_delegation_hop_fails_closed() -> None:
    with pytest.raises(TransportError):
        parse_peer_request({"metadata": _ca2a_meta(chain=[{"not": "a credential"}])})


def test_malformed_base64_sealed_payload_fails_closed() -> None:
    with pytest.raises(TransportError) as exc:
        parse_peer_request(
            {"metadata": _ca2a_meta(sealed_payload="!!!not-base64!!!", include_sealed=True)}
        )
    assert "base64url" in str(exc.value).lower() or "sealed_payload" in str(exc.value)


@pytest.mark.parametrize("bad", ["abcd?", "ab cd", "ab==cd", "a+b/c", "%%%%"])
def test_sealed_payload_outside_base64url_alphabet_fails_closed(bad: str) -> None:
    # base64.urlsafe_b64decode silently ignores stray characters, so these must
    # be rejected explicitly rather than accepted as opaque bytes.
    with pytest.raises(TransportError) as exc:
        parse_peer_request({"metadata": _ca2a_meta(sealed_payload=bad, include_sealed=True)})
    assert exc.value.code == "TRANSPORT_ERROR"


def test_parent_record_hash_null_is_root() -> None:
    req = parse_peer_request({"metadata": _ca2a_meta(parent_record_hash=None)})
    assert req is not None
    assert req.parent_record_hash is None


def test_unknown_non_ca2a_metadata_preserved_and_ignored() -> None:
    foreign = "https://example.com/ext/other/v1/trace"
    meta = _ca2a_meta()
    meta[foreign] = {"keep": True}
    req = parse_peer_request({"metadata": meta})
    assert req is not None

    attached = attach_ca2a_metadata({"metadata": {foreign: {"keep": True}}}, req)
    assert attached["metadata"][foreign] == {"keep": True}
    assert KEY_DELEGATION_CHAIN in attached["metadata"]


def test_round_trip_attach_then_parse() -> None:
    chain = build_chain([frozenset({"read", "write"}), frozenset({"read"})])
    sealed = b"\x00opaque-ciphertext\xff"
    original = PeerRequest(
        chain=chain,
        requested_capability="read",
        record_id="rec-rt",
        sealed_payload=sealed,
        parent_record_hash="sha256:abc",
    )
    message = {
        "messageId": "m-1",
        "role": "user",
        "parts": [{"text": "task"}],
        "metadata": {"https://example.com/ext/other/v1/x": 1},
    }
    attached = attach_ca2a_metadata(message, original)
    assert attached["parts"] == message["parts"]
    assert attached["metadata"]["https://example.com/ext/other/v1/x"] == 1

    parsed = parse_peer_request(attached)
    assert parsed is not None
    assert parsed.requested_capability == original.requested_capability
    assert parsed.record_id == original.record_id
    assert parsed.parent_record_hash == original.parent_record_hash
    assert parsed.sealed_payload == sealed
    assert len(parsed.chain) == len(original.chain)
    assert parsed.chain[0].credential_id == original.chain[0].credential_id
    assert parsed.chain[-1].signature == original.chain[-1].signature


def test_sealed_payload_is_opaque_bytes_only() -> None:
    raw = b"not-a-verified-measurement-binding"
    encoded = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
    req = parse_peer_request({"metadata": _ca2a_meta(sealed_payload=encoded)})
    assert req is not None
    assert req.sealed_payload == raw


def test_extension_uri_is_stable() -> None:
    assert EXTENSION_URI == "https://agentrust.io/extensions/ca2a/v0.1"
    assert KEY_DELEGATION_CHAIN.startswith(EXTENSION_URI)
