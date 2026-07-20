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
import urllib.request
from typing import Any

from ca2a_runtime.attestation import VerifiedPeer, Verifier, seal_to_peer, verify_offer
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.errors import CA2AError
from ca2a_runtime.transport import a2a
from ca2a_runtime.transport.server import CHANNEL_PATH, TASK_PATH

_TIMEOUT = 10.0


def _get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(url, timeout=_TIMEOUT) as resp:  # noqa: S310
        return json.loads(resp.read())


def _post_json(url: str, body: dict[str, Any]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(
        url, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def fetch_verified_peer(base_url: str, *, verifier: Verifier | None = None) -> VerifiedPeer:
    """Fetch the peer's attested channel key and verify it under a fresh nonce."""
    nonce = secrets.token_hex(16)
    offer = a2a.parse_channel_offer(_get_json(f"{base_url}{CHANNEL_PATH}?nonce={nonce}"))
    return verify_offer(offer, expected_nonce=nonce, verifier=verifier)


def send_task(
    base_url: str,
    chain: list[DelegationCredential],
    requested_capability: str,
    record_id: str,
    *,
    payload: bytes | None = None,
    verifier: Verifier | None = None,
    parent_record_hash: str | None = None,
) -> dict[str, Any]:
    """Run the caller side end to end: verify the peer, seal the payload, send the task.

    Returns the parsed response body on acceptance. Raises a :class:`CA2AError`
    carrying the peer's error code and message on any peer-side failure.
    """
    sealed: bytes | None = None
    if payload is not None:
        peer = fetch_verified_peer(base_url, verifier=verifier)
        sealed = seal_to_peer(peer, payload)
    message = a2a.build_task_message(
        chain,
        requested_capability,
        record_id,
        sealed_payload=sealed,
        parent_record_hash=parent_record_hash,
    )
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
