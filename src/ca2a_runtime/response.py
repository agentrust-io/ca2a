"""One-use live response authentication; not a portable signature or encryption."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ca2a_runtime.attestation import VerifiedPeer
from ca2a_runtime.canonical import canonicalize
from ca2a_runtime.errors import CA2AError
from ca2a_runtime.errors import ResponseAuthenticationFailed as ResponseAuthenticationFailed

PROFILE = "ca2a-response-mac-v1"
MAX_BYTES = 1 << 20
_REQUEST_FIELDS = {"profile", "peer", "recipient", "session", "request"}
_RESPONSE_FIELDS = {"profile", "request_sha256", "status", "kind", "body", "mac"}


class AuthenticatedPeerError(CA2AError):
    """An authenticated peer denial, not proof that no side effect occurred."""

    def __init__(self, response: VerifiedResponse) -> None:
        error = response.body["error"]
        super().__init__(str(error.get("message", "peer denial")))
        self.code = str(error.get("code", "PEER_DENIAL"))
        self.http_status = response.status
        self.response_authentication = response.authentication()


def _fail() -> ResponseAuthenticationFailed:
    return ResponseAuthenticationFailed(
        "response authentication failed; execution outcome is unknown"
    )


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _fail()
        result[key] = value
    return result


def encode(value: dict[str, Any]) -> bytes:
    """Bound the existing integer-only JCS profile, with string object keys."""

    def check(item: Any, depth: int = 0) -> None:
        if depth > 64:
            raise _fail()
        if isinstance(item, dict):
            if any(not isinstance(key, str) for key in item):
                raise _fail()
            for child in item.values():
                check(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                check(child, depth + 1)

    try:
        check(value)
        raw = canonicalize(value)
        if len(raw) > MAX_BYTES:
            raise _fail()
        return raw
    except (TypeError, ValueError, RecursionError) as exc:
        raise _fail() from exc


def decode(raw: bytes) -> dict[str, Any]:
    """Reject ambiguous/oversized JSON before it can be authenticated."""
    if len(raw) > MAX_BYTES:
        raise _fail()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_object)
        if not isinstance(value, dict):
            raise _fail()
        encode(value)
        return value
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise _fail() from exc


def _hex(value: Any, length: int = 32) -> bytes:
    if not isinstance(value, str) or len(value) != length * 2:
        raise _fail()
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise _fail() from exc
    if len(raw) != length or raw.hex() != value:
        raise _fail()
    return raw


def _key(private: X25519PrivateKey, public: str, request_hash: str) -> bytes:
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(_hex(public)))
    except ValueError as exc:
        raise _fail() from exc
    return HKDF(
        algorithm=SHA256(),
        length=32,
        salt=bytes.fromhex(request_hash),
        info=b"ca2a/response-mac/v1/key",
    ).derive(shared)


def _mac(key: bytes, statement: dict[str, Any]) -> str:
    return hmac.new(
        key, b"ca2a/response-mac/v1/statement\x00" + encode(statement), "sha256"
    ).hexdigest()


@dataclass(frozen=True)
class VerifiedResponse:
    """A live caller's verified statement; both session parties can create its MAC."""

    status: int
    body: dict[str, Any]
    request_sha256: str
    peer_assurance: str

    def authentication(self) -> dict[str, str]:
        return {
            "profile": PROFILE,
            "peer_assurance": self.peer_assurance,
            "request_sha256": self.request_sha256,
            "audience": "live-caller-only",
        }


class ResponseProducer:
    """Validate the request and establish the response key before executing it."""

    def __init__(self, private: X25519PrivateKey, envelope: dict[str, Any]) -> None:
        # Freeze caller-owned input before both hashing and execution.
        self.envelope = decode(encode(envelope))
        if set(self.envelope) != _REQUEST_FIELDS or self.envelope["profile"] != PROFILE:
            raise _fail()
        peer = private.public_key().public_bytes_raw().hex()
        if self.envelope["peer"] != peer or not isinstance(self.envelope["request"], dict):
            raise _fail()
        _hex(self.envelope["session"])
        self.request_sha256 = hashlib.sha256(encode(self.envelope)).hexdigest()
        self._key = _key(private, self.envelope["recipient"], self.request_sha256)

    def finish(self, status: int, body: dict[str, Any]) -> dict[str, Any]:
        statement = {
            "profile": PROFILE,
            "request_sha256": self.request_sha256,
            "status": status,
            "kind": "provenance" if status == 200 else "denial",
            "body": body,
        }
        result = {**statement, "mac": _mac(self._key, statement)}
        encode(result)
        return result


class PendingResponse:
    """Process-local, expiring, single-use verification state for one request.

    No persistence, restart recovery or resubmission. Every new call gets a fresh
    key and occurrence ID. State loss means an unknown outcome, not an empty
    replay cache with permission to accept an old response.
    """

    def __init__(
        self,
        peer: VerifiedPeer,
        message: dict[str, Any],
        *,
        timeout: float = 30.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not math.isfinite(timeout) or not 0 < timeout <= 300:
            raise ValueError("response timeout must be finite and in (0, 300]")
        private = X25519PrivateKey.generate()
        self._request = encode(
            {
                "profile": PROFILE,
                "peer": peer.public_key,
                "recipient": private.public_key().public_bytes_raw().hex(),
                "session": secrets.token_hex(32),
                "request": message,
            }
        )
        self.request_sha256 = hashlib.sha256(self._request).hexdigest()
        self._key = _key(private, peer.public_key, self.request_sha256)
        self._assurance = peer.assurance
        self._clock = clock
        self._started = clock()
        if not math.isfinite(self._started):
            raise ValueError("response clock must be finite")
        self._deadline = self._started + timeout
        self._used = False
        self._lock = threading.Lock()

    @property
    def request_bytes(self) -> bytes:
        return self._request

    def __copy__(self) -> PendingResponse:
        raise TypeError("pending response state cannot be copied or restored")

    def __deepcopy__(self, memo: dict[int, Any]) -> PendingResponse:
        raise TypeError("pending response state cannot be copied or restored")

    def __reduce__(self) -> Any:
        raise TypeError("pending response state cannot be copied or restored")

    def _check_deadline(self) -> None:
        try:
            now = self._clock()
            if not math.isfinite(now) or not self._started <= now < self._deadline:
                raise _fail()
        except Exception as exc:
            raise _fail() from exc

    def verify(self, status: int, raw: bytes) -> VerifiedResponse:
        """Consume this occurrence even on failure; never expose unverified content."""
        with self._lock:
            if self._used:
                raise _fail()
            self._used = True
            key, self._key = self._key, b""
            try:
                self._check_deadline()
                envelope = decode(raw)
                if set(envelope) != _RESPONSE_FIELDS:
                    raise _fail()
                mac = envelope.pop("mac")
                _hex(mac)
                if (
                    envelope["profile"] != PROFILE
                    or envelope["request_sha256"] != self.request_sha256
                    or type(envelope["status"]) is not int
                    or type(status) is not int
                    or envelope["status"] != status
                    or not (status == 200 or 400 <= status <= 599)
                ):
                    raise _fail()
                if not hmac.compare_digest(mac, _mac(key, envelope)):
                    raise _fail()
                body = envelope["body"]
                kind = "provenance" if status == 200 else "denial"
                if envelope["kind"] != kind or not isinstance(body, dict):
                    raise _fail()
                if status == 200 and body.get("accepted") is not True:
                    raise _fail()
                if status != 200 and not isinstance(body.get("error"), dict):
                    raise _fail()
                self._check_deadline()
                return VerifiedResponse(status, body, self.request_sha256, self._assurance)
            except (ValueError, TypeError, OSError) as exc:
                raise _fail() from exc
