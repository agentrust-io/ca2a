"""Tests for the transport-agnostic inbound peer request handler.

These run with holder binding on, as the handler ships, so each also asserts the
pipeline still works when the caller has proved it holds the leaf key. The
binding property itself is covered in ``test_holder_binding.py``.
"""

from __future__ import annotations

import pytest

from ca2a_runtime import peer as peer_module
from ca2a_runtime.channel import SealedChannel, generate_channel_keypair
from ca2a_runtime.errors import (
    ScopeEscalation,
    ScopeNotPermitted,
    SealedChannelError,
    UntrustedDelegationRoot,
)
from ca2a_runtime.peer import PeerResult
from ca2a_runtime.peer import handle_peer_request as _handle_peer_request
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.provenance import verify_dag
from tests.unit.conftest import (
    TEST_AUDIENCE,
    TEST_SECRET,
    build_chain_with_keys,
    proved_request,
)


def _chain():
    return build_chain_with_keys(
        [frozenset({"read", "write", "admin"}), frozenset({"read", "write"})]
    )


def _handle(req, policy, **kwargs):
    """Run the handler with the challenge context the holder proof commits to."""
    return handle_peer_request(
        req, policy=policy, audience=TEST_AUDIENCE, challenge_secret=TEST_SECRET, **kwargs
    )


def handle_peer_request(request, **kwargs):
    return _handle_peer_request(request, trusted_root_issuers={request.chain[0].issuer}, **kwargs)


def test_handles_request_without_payload() -> None:
    chain, keys = _chain()
    result = _handle(
        proved_request(chain, keys[-1], "read", "rec-0"), LocalPolicy.of(["read", "audit"])
    )
    assert isinstance(result, PeerResult)
    assert result.granted_capability == "read"
    assert result.effective_scope == frozenset({"read"})
    assert result.payload is None
    assert verify_dag([result.record]) == [result.record]


def test_handles_request_with_sealed_payload() -> None:
    chain, keys = _chain()
    priv, pub = generate_channel_keypair()
    payload = b"do the thing"
    req = proved_request(
        chain, keys[-1], "read", "rec-0", sealed_payload=SealedChannel(pub).seal(payload)
    )
    result = _handle(req, LocalPolicy.of(["read"]), enclave_private_key=priv)
    assert result.payload == payload


def test_denied_capability_raises_before_payload() -> None:
    chain, keys = _chain()
    priv, pub = generate_channel_keypair()
    req = proved_request(
        chain, keys[-1], "admin", "rec-0", sealed_payload=SealedChannel(pub).seal(b"secret")
    )
    with pytest.raises(ScopeNotPermitted):
        _handle(req, LocalPolicy.of(["read"]), enclave_private_key=priv)


def test_sealed_payload_without_key_fails_closed() -> None:
    chain, keys = _chain()
    _, pub = generate_channel_keypair()
    req = proved_request(
        chain, keys[-1], "read", "rec-0", sealed_payload=SealedChannel(pub).seal(b"secret")
    )
    with pytest.raises(SealedChannelError):
        _handle(req, LocalPolicy.of(["read"]))  # no enclave key


def test_invalid_chain_rejected() -> None:
    # Escalation at hop 1. The chain is rejected before holder binding is checked,
    # because a proof over an unverified leaf proves nothing worth having.
    chain, keys = build_chain_with_keys([frozenset({"read"}), frozenset({"read", "write"})])
    req = proved_request(chain, keys[-1], "read", "rec-0")
    with pytest.raises(ScopeEscalation):
        _handle(req, LocalPolicy.of(["read", "write"]))


def test_untrusted_root_is_rejected() -> None:
    # The handler enforces the trust set itself: a chain that verifies perfectly
    # but roots outside it is refused, and refused before the caller is
    # challenged for a holder proof.
    chain, keys = _chain()
    req = proved_request(chain, keys[-1], "read", "rec-0")
    with pytest.raises(UntrustedDelegationRoot):
        _handle_peer_request(
            req,
            policy=LocalPolicy.of(["read"]),
            audience=TEST_AUDIENCE,
            challenge_secret=TEST_SECRET,
            trusted_root_issuers={"some-other-root"},
        )


def test_chain_is_verified_exactly_once(monkeypatch: pytest.MonkeyPatch) -> None:
    """One accepted request costs one chain verification, not two.

    The real verifier still runs -- the wrapper only counts calls -- so the
    request is genuinely verified while the count pins down how often.
    """
    real_verify_chain = peer_module.verify_chain
    calls = 0

    def counting_verify_chain(*args, **kwargs):
        nonlocal calls
        calls += 1
        return real_verify_chain(*args, **kwargs)

    monkeypatch.setattr(peer_module, "verify_chain", counting_verify_chain)

    chain, keys = _chain()
    result = _handle(proved_request(chain, keys[-1], "read", "rec-0"), LocalPolicy.of(["read"]))

    assert calls == 1
    # The saved verification did not cost the authorization decision.
    assert result.granted_capability == "read"
    assert result.effective_scope == frozenset({"read"})
