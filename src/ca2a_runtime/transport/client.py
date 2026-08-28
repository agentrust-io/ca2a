"""Reference HTTP client for the cA2A peer path (standard library only).

The caller side of the live call: fetch a peer's attested channel key, verify it
under a fresh nonce, seal a payload to it, and send a delegated task. Uses urllib
only. On a confidential VM, pass a ``verifier`` that wraps :mod:`ca2a_verify`;
without one, the peer key is accepted at ``assurance="none"`` (software mode).
"""

from __future__ import annotations

import json
import secrets
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ca2a_runtime.attestation import (
    ChannelOffer,
    VerifiedPeer,
    Verifier,
    offer_channel,
    seal_to_peer,
    verify_offer,
)
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.delegation.holder import build_holder_proof
from ca2a_runtime.errors import AttestationFailed, CA2AError, TransportError
from ca2a_runtime.peer import PeerRequest
from ca2a_runtime.tee.base import BaseProvider
from ca2a_runtime.transport import a2a_adapter, wire
from ca2a_runtime.transport.server import CHANNEL_PATH, TASK_PATH

_TIMEOUT = 10.0
_ALLOWED_SCHEMES = ("http", "https")
_MAX_RESPONSE = 1 << 20


def _require_http_url(url: str) -> None:
    """Reject any non-HTTP(S) URL before opening it, failing closed.

    ``urllib.request.urlopen`` will open ``file:`` and custom schemes too, which
    is what bandit B310 / ruff S310 warn about. The reference client only ever
    talks HTTP(S) to a peer base URL, so any other scheme is a misconfiguration.
    """
    if urllib.parse.urlparse(url).scheme not in _ALLOWED_SCHEMES:
        raise TransportError(
            "refusing to open a non-HTTP(S) URL",
            detail=f"scheme must be one of {_ALLOWED_SCHEMES}",
        )



def _read_bounded(resp: Any) -> bytes:
    """Read a response body, failing closed once it exceeds ``_MAX_RESPONSE``.

    A callee's ``Content-Length`` header is not trusted as the cap: a hostile
    or simply broken peer can omit it, lie about it, or use chunked transfer
    encoding, and ``http.client`` will still hand back whatever bytes arrive.
    Reading one byte past the limit and checking the actual length -- the same
    read-then-check shape ``server.py`` uses for the request side via
    ``_MAX_BODY`` -- bounds memory regardless of what the peer claims.
    """
    body = resp.read(_MAX_RESPONSE + 1)
    if len(body) > _MAX_RESPONSE:
        raise TransportError(
            "peer response exceeds the maximum allowed size",
            detail=f"body must be at most {_MAX_RESPONSE} bytes",
        )
    return body


def _get_json(url: str) -> dict[str, Any]:
    _require_http_url(url)
    with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:  # noqa: S310  # nosec B310
        return json.loads(_read_bounded(resp))


def _post_json(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    _require_http_url(url)
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310  # nosec B310
            return resp.status, json.loads(_read_bounded(resp))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(_read_bounded(exc))


@dataclass(frozen=True)
class Handshake:
    """What one round trip to the handshake endpoint yields.

    ``peer`` is the appraised callee. ``challenge`` is the callee's half of a
    mutual exchange, and is None when the callee issued none -- an older or
    deliberately one-directional peer, which is still perfectly usable.
    """

    peer: VerifiedPeer
    challenge: str | None


def handshake(base_url: str, *, verifier: Verifier | None = None) -> Handshake:
    """Fetch the peer's attested channel key, verify it, and keep its challenge.

    One round trip serves both directions: the nonce is the caller's own and is
    what makes the callee's report live, and the challenge that comes back is what
    would make the caller's report live in the other direction.
    """
    nonce = secrets.token_hex(16)
    body = _get_json(f"{base_url}{CHANNEL_PATH}?nonce={nonce}")
    offer = wire.parse_channel_offer(body)
    return Handshake(
        peer=verify_offer(offer, expected_nonce=nonce, verifier=verifier),
        challenge=wire.parse_challenge(body),
    )


def fetch_verified_peer(base_url: str, *, verifier: Verifier | None = None) -> VerifiedPeer:
    """Fetch the peer's attested channel key and verify it under a fresh nonce."""
    return handshake(base_url, verifier=verifier).peer


def send_task(
    base_url: str,
    chain: list[DelegationCredential],
    requested_capability: str,
    record_id: str,
    *,
    holder_key: Ed25519PrivateKey,
    payload: bytes | None = None,
    verifier: Verifier | None = None,
    parent_record_hash: str | None = None,
    caller_provider: BaseProvider | None = None,
) -> dict[str, Any]:
    """Run the caller side end to end: verify the peer, prove holdership, seal, send.

    ``holder_key`` is the private half of ``chain[-1].subject``. Without it the
    caller cannot answer the callee's challenge, which is the point: a chain
    copied from a log or an audit bundle is not enough to make a call.

    Pass ``caller_provider`` to also make the *attestation* exchange mutual: the
    caller binds its own channel key into a report under the same challenge, so
    the callee learns what the caller is running as well as that it is the
    delegate. The two are independent, and the holder proof commits to the offer's
    channel key when one is sent, which is what ties the attested runtime and the
    delegated principal into a single statement.

    Returns the parsed response body on acceptance. Raises a :class:`CA2AError`
    carrying the peer's error code and message on any peer-side failure.
    """
    sealed: bytes | None = None
    caller_offer: ChannelOffer | None = None
    # Always: the holder proof needs the callee's identity as its audience and a
    # challenge the callee issued, and both arrive in this one round trip.
    hello = handshake(base_url, verifier=verifier)
    if hello.challenge is None:
        raise AttestationFailed(
            "the peer issued no challenge, so the caller cannot prove it holds the leaf key",
            detail="the callee's handshake response carried no 'challenge' field",
        )
    if payload is not None:
        sealed = seal_to_peer(hello.peer, payload)
    if caller_provider is not None:
        # The private half goes unused today: response sealing was withdrawn
        # because nothing confidential comes back (the response is the
        # provenance record, which has to stay readable). The key's job here
        # is to be what the report binds, which is what makes the caller's
        # measurement live rather than replayed.
        _caller_private_key, caller_offer = offer_channel(caller_provider, nonce=hello.challenge)

    # After sealing and after the offer, because the proof commits to both.
    holder_proof = build_holder_proof(
        holder_key,
        chain[-1],
        audience=hello.peer.public_key,
        challenge=hello.challenge,
        requested_capability=requested_capability,
        record_id=record_id,
        sealed_payload=sealed,
        caller_channel_key=(None if caller_offer is None else caller_offer.channel_public_key),
        parent_record_hash=parent_record_hash,
    )
    request = PeerRequest(
        chain=chain,
        requested_capability=requested_capability,
        record_id=record_id,
        sealed_payload=sealed,
        parent_record_hash=parent_record_hash,
        caller_offer=caller_offer,
        holder_proof=holder_proof,
    )
    message = a2a_adapter.attach_ca2a_metadata({}, request)
    status, body = _post_json(f"{base_url}{TASK_PATH}", message)
    if status != 200:
        err = body.get("error", {})
        raise _rehydrate_error(err)
    return body


def _rehydrate_error(err: dict[str, Any]) -> CA2AError:
    exc = CA2AError(str(err.get("message", "peer error")), detail=err.get("detail"))
    code = err.get("code")
    if isinstance(code, str):
        exc.code = code
    status = err.get("http_status")
    if isinstance(status, int):
        exc.http_status = status
    return exc
