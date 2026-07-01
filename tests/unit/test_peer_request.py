"""Tests for the transport-agnostic inbound peer request handler."""

from __future__ import annotations

import pytest

from ca2a_runtime.channel import SealedChannel, generate_channel_keypair
from ca2a_runtime.errors import ScopeEscalation, ScopeNotPermitted, SealedChannelError
from ca2a_runtime.peer import PeerRequest, PeerResult, handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import verify_dag
from tests.unit.conftest import build_chain


def _chain():
    return build_chain([frozenset({"read", "write", "admin"}), frozenset({"read", "write"})])


def test_handles_request_without_payload() -> None:
    req = PeerRequest(chain=_chain(), requested_capability="read", record_id="rec-0")
    result = handle_peer_request(req, policy=LocalPolicy.of(["read", "audit"]))
    assert isinstance(result, PeerResult)
    assert result.granted_capability == "read"
    assert result.effective_scope == frozenset({"read"})
    assert result.payload is None
    assert verify_dag([result.record]) == [result.record]


def test_handles_request_with_sealed_payload() -> None:
    priv, pub = generate_channel_keypair()
    payload = b"do the thing"
    req = PeerRequest(
        chain=_chain(), requested_capability="read", record_id="rec-0",
        sealed_payload=SealedChannel(pub).seal(payload),
    )
    result = handle_peer_request(
        req, policy=LocalPolicy.of(["read"]), enclave_private_key=priv
    )
    assert result.payload == payload


def test_denied_capability_raises_before_payload() -> None:
    priv, pub = generate_channel_keypair()
    req = PeerRequest(
        chain=_chain(), requested_capability="admin", record_id="rec-0",
        sealed_payload=SealedChannel(pub).seal(b"secret"),
    )
    with pytest.raises(ScopeNotPermitted):
        handle_peer_request(req, policy=LocalPolicy.of(["read"]), enclave_private_key=priv)


def test_sealed_payload_without_key_fails_closed() -> None:
    _, pub = generate_channel_keypair()
    req = PeerRequest(
        chain=_chain(), requested_capability="read", record_id="rec-0",
        sealed_payload=SealedChannel(pub).seal(b"secret"),
    )
    with pytest.raises(SealedChannelError):
        handle_peer_request(req, policy=LocalPolicy.of(["read"]))  # no enclave key


def test_invalid_chain_rejected() -> None:
    bad = build_chain([frozenset({"read"}), frozenset({"read", "write"})])  # escalation
    req = PeerRequest(chain=bad, requested_capability="read", record_id="rec-0")
    with pytest.raises(ScopeEscalation):
        handle_peer_request(req, policy=LocalPolicy.of(["read", "write"]))
