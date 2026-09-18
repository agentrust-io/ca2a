"""Response trust is scoped to one live caller and one complete request."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import pickle
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime import response as response_module
from ca2a_runtime.attestation import VerifiedPeer
from ca2a_runtime.node import PeerNode
from ca2a_runtime.policy import LocalPolicy
from ca2a_runtime.response import (
    PROFILE,
    AuthenticatedPeerError,
    PendingResponse,
    ResponseAuthenticationFailed,
    ResponseProducer,
    decode,
    encode,
)
from ca2a_runtime.transport import client, server
from tests.unit.test_live_call import _chain


def exchange(*, clock=lambda: 10.0):
    private = X25519PrivateKey.generate()
    peer = VerifiedPeer(private.public_key().public_bytes_raw().hex(), "none", "test")
    pending = PendingResponse(peer, {"record_id": "same-id", "payload": "test"}, clock=clock)
    producer = ResponseProducer(private, decode(pending.request_bytes))
    return private, pending, producer


def success(producer):
    return producer.finish(200, {"accepted": True, "record": {"id": "r"}})


def test_valid_response_and_one_use():
    _, pending, producer = exchange()
    raw = encode(success(producer))
    result = pending.verify(200, raw)
    assert result.body["accepted"]
    assert result.authentication()["peer_assurance"] == "none"
    assert result.authentication()["audience"] == "live-caller-only"
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, raw)


@pytest.mark.parametrize(
    "field,value",
    [
        ("body", {"accepted": True, "record": {"id": "substituted"}}),
        ("status", 403),
        ("kind", "denial"),
        ("profile", "legacy"),
        ("request_sha256", "00" * 32),
        ("mac", "00" * 32),
    ],
)
def test_changed_response_is_not_exposed(field, value):
    _, pending, producer = exchange()
    response = success(producer)
    response[field] = value
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, encode(response))


@pytest.mark.parametrize("field", ["recipient", "session", "request"])
def test_valid_mac_for_changed_request_context_is_refused(field):
    private, pending, _ = exchange()
    envelope = decode(pending.request_bytes)
    if field == "recipient":
        envelope[field] = X25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    elif field == "session":
        envelope[field] = "33" * 32
    else:
        envelope[field]["payload"] = "another task"
    producer = ResponseProducer(private, envelope)
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, encode(success(producer)))


def test_wrong_peer_key_and_rotation_require_new_handshake():
    _, pending, _ = exchange()
    other = X25519PrivateKey.generate()
    envelope = decode(pending.request_bytes)
    with pytest.raises(ResponseAuthenticationFailed):
        ResponseProducer(other, envelope)
    envelope["peer"] = other.public_key().public_bytes_raw().hex()
    substituted = ResponseProducer(other, envelope)
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, encode(success(substituted)))
    fresh = PendingResponse(VerifiedPeer(envelope["peer"], "none", "new"), {"task": "new"})
    producer = ResponseProducer(other, decode(fresh.request_bytes))
    assert fresh.verify(200, encode(success(producer))).body["accepted"]


def test_old_response_cannot_be_consumed_after_state_loss():
    private, pending, producer = exchange()
    fresh = PendingResponse(
        VerifiedPeer(private.public_key().public_bytes_raw().hex(), "none", "test"),
        decode(pending.request_bytes)["request"],
    )
    with pytest.raises(ResponseAuthenticationFailed):
        fresh.verify(200, encode(success(producer)))


@pytest.mark.parametrize("now", [40.0, 41.0, 9.0, float("nan"), float("inf")])
def test_deadline_clock_rollback_and_invalid_clock_fail_closed(now):
    ticks = iter([10.0, now])
    _, pending, producer = exchange(clock=lambda: next(ticks))
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, encode(success(producer)))


@pytest.mark.parametrize("timeout", [0, -1, 301, float("nan"), float("inf")])
def test_invalid_timeout(timeout):
    private = X25519PrivateKey.generate()
    with pytest.raises(ValueError):
        PendingResponse(
            VerifiedPeer(private.public_key().public_bytes_raw().hex(), "none", ""),
            {},
            timeout=timeout,
        )


def test_concurrent_consumption_has_exactly_one_success():
    _, pending, producer = exchange()
    raw = encode(success(producer))

    def consume(_):
        try:
            pending.verify(200, raw)
            return True
        except ResponseAuthenticationFailed:
            return False

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(consume, range(16))) == 1


@pytest.mark.parametrize(
    "raw",
    [
        b'{"a":1,"a":2}',
        b'{"outer":{"a":1,"a":2}}',
        b"[]",
        b'{"n":NaN}',
        b'{"n":1.0}',
        b'{"n":9007199254740992}',
        b'{"s":"\\ud800"}',
        b'{"a":' + b"[" * 70 + b"0" + b"]" * 70 + b"}",
        b"x" * ((1 << 20) + 1),
    ],
    ids=lambda raw: f"json-{len(raw)}-{hashlib.sha256(raw).hexdigest()[:8]}",
)
def test_ambiguous_or_unbounded_json_is_rejected(raw):
    with pytest.raises(ResponseAuthenticationFailed):
        decode(raw)


def test_invalid_response_consumes_occurrence():
    _, pending, producer = exchange()
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, b"{}")
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, encode(success(producer)))


@pytest.mark.parametrize("mutation", ["extra", "missing", "zero-key", "uppercase", "profile"])
def test_invalid_request_context_is_rejected_before_execution(mutation):
    private, pending, _ = exchange()
    envelope = decode(pending.request_bytes)
    if mutation == "extra":
        envelope["extra"] = True
    elif mutation == "missing":
        del envelope["request"]
    elif mutation == "zero-key":
        envelope["recipient"] = "00" * 32
    elif mutation == "uppercase":
        envelope["recipient"] = "AB" * 32
    else:
        envelope["profile"] = "unknown"
    with pytest.raises(ResponseAuthenticationFailed):
        ResponseProducer(private, envelope)


def test_authenticated_denial_and_unsigned_denial_are_different():
    _, pending, producer = exchange()
    body = {"error": {"code": "DENIED", "message": "denied"}}
    response = pending.verify(403, encode(producer.finish(403, body)))
    error = AuthenticatedPeerError(response)
    assert error.code == "DENIED"
    assert error.http_status == 403
    assert error.response_authentication["profile"] == PROFILE
    _, other, _ = exchange()
    with pytest.raises(ResponseAuthenticationFailed):
        other.verify(403, encode(body))


def test_valid_mac_with_unsupported_confidential_output_kind_is_rejected():
    _, pending, producer = exchange()
    body = {
        "profile": PROFILE,
        "request_sha256": producer.request_sha256,
        "status": 200,
        "kind": "confidential-output",
        "body": {"accepted": True},
    }
    # Deliberately authenticate the unsupported kind: this isolates its gate.
    mac = hmac.new(
        producer._key, b"ca2a/response-mac/v1/statement\x00" + encode(body), "sha256"
    ).hexdigest()
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, encode({**body, "mac": mac}))


def test_independent_hkdf_and_mac_verifies_reference_response():
    private, pending, producer = exchange()
    envelope = decode(pending.request_bytes)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    shared = private.exchange(
        X25519PublicKey.from_public_bytes(bytes.fromhex(envelope["recipient"]))
    )
    # RFC 5869 extract and one-block expand, independent of production HKDF.
    digest = hashlib.sha256(pending.request_bytes).digest()
    prk = hmac.new(digest, shared, "sha256").digest()
    key = hmac.new(prk, b"ca2a/response-mac/v1/key\x01", "sha256").digest()
    response = success(producer)
    mac = response.pop("mac")
    # ASCII-only fixture: stdlib sorting supplies independent canonical bytes.
    raw = json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
    expected = hmac.new(key, b"ca2a/response-mac/v1/statement\x00" + raw, "sha256").hexdigest()
    assert mac == expected


@pytest.fixture
def live_peer():
    chain, holder = _chain()
    node = PeerNode(LocalPolicy.of({"read"}), trusted_root_issuers={chain[0].issuer})
    http = server.serve(node, port=0)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield node, f"http://127.0.0.1:{http.server_port}", chain, holder
    finally:
        http.shutdown()
        http.server_close()
        thread.join(timeout=5)


def call(peer, capability="read", strict=True):
    _, url, chain, holder = peer
    return client.send_task(
        url,
        chain,
        capability,
        "same-id",
        holder_key=holder,
        payload=b"private-canary",
        require_authenticated_response=strict,
    )


def test_real_http_authenticated_success_denial_and_legacy(live_peer):
    result = call(live_peer)
    assert result["accepted"]
    assert result["response_authentication"]["peer_assurance"] == "none"
    assert "private-canary" not in json.dumps(result)
    with pytest.raises(AuthenticatedPeerError) as failure:
        call(live_peer, "write")
    assert failure.value.code == "SCOPE_NOT_PERMITTED"
    assert failure.value.response_authentication["profile"] == PROFILE
    assert "response_authentication" not in call(live_peer, strict=False)


@pytest.mark.parametrize("change", ["body", "status", "unsigned", "other-request"])
def test_real_http_substituted_response_never_reaches_caller(live_peer, monkeypatch, change):
    original = client._post_authenticated
    previous = None

    def intercept(url, raw):
        nonlocal previous
        status, response = original(url, raw)
        envelope = decode(response)
        if change == "body":
            envelope["body"]["record"]["record_id"] = "forged"
        elif change == "status":
            status = 403
        elif change == "unsigned":
            envelope = envelope["body"]
        elif previous is None:
            previous = response
            return status, response
        else:
            return status, previous
        return status, encode(envelope)

    monkeypatch.setattr(client, "_post_authenticated", intercept)
    if change == "other-request":
        assert call(live_peer)["accepted"]
    with pytest.raises(ResponseAuthenticationFailed, match="unknown"):
        call(live_peer)


def test_timeout_after_execution_is_not_retried(live_peer, monkeypatch):
    original = client._post_authenticated
    calls = []

    def lose_reply(url, raw):
        calls.append(raw)
        status, _ = original(url, raw)
        assert status == 200
        raise TimeoutError("reply lost")

    monkeypatch.setattr(client, "_post_authenticated", lose_reply)
    with pytest.raises(ResponseAuthenticationFailed, match="unknown"):
        call(live_peer)
    assert len(calls) == 1


def test_snapshotting_request_avoids_mutable_aliases():
    private, pending, _ = exchange()
    envelope = decode(pending.request_bytes)
    producer = ResponseProducer(private, envelope)
    before = copy.deepcopy(producer.envelope)
    envelope["request"]["payload"] = "changed"
    assert producer.envelope == before


@pytest.mark.parametrize("clone", [copy.copy, copy.deepcopy, pickle.dumps])
def test_pending_state_cannot_be_copied_or_restored(clone):
    _, pending, _ = exchange()
    with pytest.raises(TypeError, match="cannot be copied"):
        clone(pending)


def test_deadline_is_checked_after_verification(monkeypatch):
    now = [10.0]
    _, pending, producer = exchange(clock=lambda: now[0])
    raw = encode(success(producer))
    original = response_module.decode

    def slow_decode(raw):
        value = original(raw)
        now[0] = 40.0
        return value

    monkeypatch.setattr(response_module, "decode", slow_decode)
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(200, raw)


def test_clock_failure_is_unknown_outcome():
    def clock():
        raise RuntimeError("clock unavailable")

    _, pending, producer = exchange()
    pending._clock = clock
    with pytest.raises(ResponseAuthenticationFailed, match="unknown"):
        pending.verify(200, encode(success(producer)))


def test_legacy_response_cannot_inject_local_assurance(live_peer, monkeypatch):
    original = client._post_json

    def spoof(url, body):
        status, result = original(url, body)
        result["response_authentication"] = {"profile": PROFILE, "peer_assurance": "hardware"}
        return status, result

    monkeypatch.setattr(client, "_post_json", spoof)
    assert "response_authentication" not in call(live_peer, strict=False)


def test_real_http_redirect_is_not_followed(live_peer, monkeypatch):
    calls = []

    def redirect(handler):
        handler.rfile.read(int(handler.headers.get("Content-Length", 0)))
        calls.append(handler.path)
        handler.send_response(307)
        handler.send_header("Location", server.AUTHENTICATED_TASK_PATH)
        handler.send_header("Content-Length", "2")
        handler.end_headers()
        handler.wfile.write(b"{}")

    monkeypatch.setattr(server._PeerHandler, "do_POST", redirect)
    with pytest.raises(ResponseAuthenticationFailed):
        call(live_peer)
    assert calls == [server.AUTHENTICATED_TASK_PATH]


def test_invalid_context_precedes_handler(live_peer, monkeypatch):
    node, url, _, _ = live_peer
    calls = []
    monkeypatch.setattr(node, "handle", lambda message: calls.append(message))
    pending = PendingResponse(VerifiedPeer(node.channel_public_key, "none", ""), {})
    envelope = decode(pending.request_bytes)
    envelope["recipient"] = "00" * 32
    status, raw = client._post_authenticated(url + server.AUTHENTICATED_TASK_PATH, encode(envelope))
    assert calls == []
    with pytest.raises(ResponseAuthenticationFailed):
        pending.verify(status, raw)


def vector_pending(monkeypatch, vector):
    key = X25519PrivateKey.from_private_bytes(bytes.fromhex(vector["caller_private_key"]))

    class FixedKey:
        @staticmethod
        def generate():
            return key

    monkeypatch.setattr(response_module, "X25519PrivateKey", FixedKey)
    monkeypatch.setattr(
        response_module.secrets, "token_hex", lambda _: vector["request"]["session"]
    )
    return PendingResponse(
        VerifiedPeer(vector["request"]["peer"], "none", "synthetic"), vector["request"]["request"]
    )


def test_committed_language_neutral_vector_and_negative_twins(monkeypatch):
    vector = json.loads((Path(__file__).parents[1] / "fixtures/response-mac-v1.json").read_bytes())
    pending = vector_pending(monkeypatch, vector)
    assert pending.request_bytes.hex() == vector["request_canonical_hex"]
    assert pending._key.hex() == vector["hkdf_key_hex"]
    private = X25519PrivateKey.from_private_bytes(bytes.fromhex(vector["callee_private_key"]))
    producer = ResponseProducer(private, vector["request"])
    assert producer.finish(200, vector["response"]["body"]) == vector["response"]
    assert pending.verify(200, encode(vector["response"])).body["accepted"]
    for case in vector["negative_cases"]:
        valid = vector_pending(monkeypatch, vector)
        assert valid.verify(200, encode(vector["response"])).body["accepted"]
        pending = vector_pending(monkeypatch, vector)
        changed = copy.deepcopy(vector["response"])
        current = changed
        for field in case["path"][:-1]:
            current = current[field]
        current[case["path"][-1]] = case["value"]
        with pytest.raises(ResponseAuthenticationFailed):
            pending.verify(200, encode(changed))
