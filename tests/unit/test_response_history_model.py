"""Bounded histories for one-use caller state, independent of transport retries."""

from itertools import product

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from ca2a_runtime.attestation import VerifiedPeer
from ca2a_runtime.response import (
    PendingResponse,
    ResponseAuthenticationFailed,
    ResponseProducer,
    decode,
    encode,
)


def test_response_occurrence_matches_bounded_history_model():
    operations = ("success", "denial", "malformed", "expire", "rollback", "restore")
    histories = 0
    for history in product(operations, repeat=4):
        private = X25519PrivateKey.generate()
        peer = VerifiedPeer(private.public_key().public_bytes_raw().hex(), "none", "model")
        clock = [10.0]
        pending = PendingResponse(peer, {"operation": "read"}, clock=lambda clock=clock: clock[0])
        producer = ResponseProducer(private, decode(pending.request_bytes))
        success = encode(producer.finish(200, {"accepted": True, "value": "synthetic"}))
        denial = encode(
            producer.finish(403, {"error": {"code": "DENIED", "message": "synthetic refusal"}})
        )
        consumed = False
        for step, operation in enumerate((*history, "success")):
            if operation in ("expire", "rollback", "restore"):
                clock[0] = {"expire": 40.0, "rollback": 9.0, "restore": 10.0}[operation]
                continue
            expected = not consumed and 10.0 <= clock[0] < 40.0 and operation != "malformed"
            consumed = True
            status, raw = {
                "success": (200, success),
                "denial": (403, denial),
                "malformed": (200, b"not JSON"),
            }[operation]
            try:
                result = pending.verify(status, raw)
            except ResponseAuthenticationFailed:
                observed = False
            else:
                observed = True
                assert result.status == status, (history, step)
                assert result.request_sha256 == pending.request_sha256, (history, step)
                assert result.authentication()["audience"] == "live-caller-only"
                if operation == "denial":
                    assert result.body["error"]["code"] == "DENIED"
                else:
                    assert result.body["accepted"] is True
            assert observed is expected, (history, step, operation, clock[0])
        histories += 1
    assert histories == 1296


@pytest.mark.parametrize("first_kind", ("success", "malformed"))
def test_first_verifier_consumes_before_a_contending_valid_response(monkeypatch, first_kind):
    import threading
    from concurrent.futures import ThreadPoolExecutor

    from ca2a_runtime import response as module

    private = X25519PrivateKey.generate()
    peer = VerifiedPeer(private.public_key().public_bytes_raw().hex(), "none", "model")
    pending = PendingResponse(peer, {"operation": "read"}, clock=lambda: 10.0)
    producer = ResponseProducer(private, decode(pending.request_bytes))
    valid = encode(producer.finish(200, {"accepted": True}))
    first_entered = threading.Event()
    second_attempting = threading.Event()
    original_decode = module.decode

    def held_decode(raw):
        first_entered.set()
        assert second_attempting.wait(5), "second verifier did not reach the barrier"
        return original_decode(raw)

    monkeypatch.setattr(module, "decode", held_decode)

    def verify(raw, second=False):
        if second:
            assert first_entered.wait(5), "first verifier did not reach decode"
            second_attempting.set()
        try:
            pending.verify(200, raw)
        except ResponseAuthenticationFailed:
            return False
        return True

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(verify, valid if first_kind == "success" else b"malformed")
        second = pool.submit(verify, valid, True)
        assert first.result(timeout=10) is (first_kind == "success")
        assert second.result(timeout=10) is False
