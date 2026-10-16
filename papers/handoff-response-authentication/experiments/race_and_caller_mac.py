"""Concurrent verification and the caller-constructed MAC.

Twenty rounds of 16 concurrent verifications of one valid response on eight worker threads
must each expose exactly one accepted response. Then the caller builds a response statement
with its own derived key and its verifier accepts it: the expected counterexample to reading
the MAC as transferable proof of peer authorship. The second part reads a private attribute
(_key) on purpose; that access is a test seam, not an attacker capability.

Usage: race_and_caller_mac.py SCRATCH   (run with the pinned cA2A source on PYTHONPATH)
"""
from concurrent.futures import ThreadPoolExecutor
import hmac
import json
from pathlib import Path
import sys


def response() -> dict:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from ca2a_runtime.attestation import VerifiedPeer
    from ca2a_runtime.response import (PendingResponse, ResponseAuthenticationFailed, ResponseProducer,
                                       decode, encode)
    private = X25519PrivateKey.generate()
    peer = VerifiedPeer(private.public_key().public_bytes_raw().hex(), "none", "synthetic")
    counts = []
    for _ in range(20):
        pending = PendingResponse(peer, {"task": "synthetic"})
        raw = encode(ResponseProducer(private, decode(pending.request_bytes)).finish(200, {"accepted": True}))

        def consume(_):
            try:
                pending.verify(200, raw)
                return True
            except ResponseAuthenticationFailed:
                return False
        with ThreadPoolExecutor(max_workers=8) as pool:
            count = sum(pool.map(consume, range(16)))
        assert count == 1
        counts.append(count)
    pending = PendingResponse(peer, {"task": "synthetic forgery demonstration"})
    statement = {"profile": decode(pending.request_bytes)["profile"],
                 "request_sha256": pending.request_sha256, "status": 200, "kind": "provenance",
                 "body": {"accepted": True, "note": "constructed locally by caller"}}
    mac = hmac.new(pending._key, b"ca2a/response-mac/v1/statement\0" + encode(statement), "sha256").hexdigest()
    assert pending.verify(200, encode({**statement, "mac": mac})).body["accepted"]
    return {"rounds": 20, "attempts": 320, "successes_per_round": counts,
            "caller_constructed_mac_accepted": True,
            "limit": "Local caller authentication is not transferable evidence of peer authorship."}


if __name__ == "__main__":
    Path(sys.argv[1]).mkdir(parents=True)
    print(json.dumps(response(), indent=2))
