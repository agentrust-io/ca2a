"""A2A wire adapter: SendMessage metadata <-> PeerRequest.

This module is the transport-side boundary for the cA2A profile. It extracts
namespaced cA2A fields from A2A ``metadata`` into a :class:`PeerRequest`, and
attaches the same fields for outbound messages. It does not speak HTTP, does
not verify attestation, and does not bind a sealed payload to a measurement —
those are separate Tier 2/3 checkboxes. See ``docs/spec/transport.md``.
"""

from __future__ import annotations

import base64
import copy
import re
from typing import Any

from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.errors import InvalidCredential, TransportError
from ca2a_runtime.peer import PeerRequest
from ca2a_runtime.transport.constants import (
    CA2A_METADATA_KEYS,
    KEY_DELEGATION_CHAIN,
    KEY_PARENT_RECORD_HASH,
    KEY_RECORD_ID,
    KEY_REQUESTED_CAPABILITY,
    KEY_SEALED_PAYLOAD,
)

# Unpadded base64url alphabet only; padding is added during decode, so an
# embedded "=" (or any other character) is rejected as malformed.
_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]*")


def has_ca2a_metadata(metadata: dict[str, Any] | None) -> bool:
    """Return True if any namespaced cA2A metadata key is present."""
    if not metadata:
        return False
    return any(key in metadata for key in CA2A_METADATA_KEYS)


def collect_metadata(
    message_or_request: dict[str, Any],
    *,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect A2A metadata from a SendMessage envelope, message, or overlay.

    Resolution order (later wins on key collision):

    1. ``params.metadata`` on a JSON-RPC ``SendMessage`` / ``message/send`` body
    2. ``message.metadata`` / ``params.message.metadata``
    3. Explicit ``metadata`` keyword (caller override)
    """
    collected: dict[str, Any] = {}

    params = message_or_request.get("params")
    if isinstance(params, dict):
        params_meta = params.get("metadata")
        if isinstance(params_meta, dict):
            collected.update(params_meta)
        msg = params.get("message")
        if isinstance(msg, dict):
            msg_meta = msg.get("metadata")
            if isinstance(msg_meta, dict):
                collected.update(msg_meta)
    else:
        msg_meta = message_or_request.get("metadata")
        if isinstance(msg_meta, dict):
            collected.update(msg_meta)

    if metadata is not None:
        collected.update(metadata)
    return collected


def _b64url_decode(value: str) -> bytes:
    """Decode a base64url string, failing closed on any non-base64url input.

    ``base64.urlsafe_b64decode`` silently ignores characters outside the
    alphabet, so a malformed value like ``"abcd?"`` would otherwise be accepted
    as opaque bytes. We validate the URL-safe alphabet (and reject embedded
    padding) before decoding so present-but-malformed metadata fails closed.
    """
    if not _BASE64URL_RE.fullmatch(value):
        raise TransportError(
            "sealed_payload is not valid base64url",
            detail="value contains characters outside the base64url alphabet",
        )
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise TransportError(
            "sealed_payload is not valid base64url",
            detail=str(exc),
        ) from exc


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _credential_to_dict(cred: DelegationCredential) -> dict[str, Any]:
    body = cred.body()
    body["signature"] = cred.signature
    return body


def parse_peer_request(
    message_or_request: dict[str, Any],
    *,
    metadata: dict[str, Any] | None = None,
) -> PeerRequest | None:
    """Parse A2A SendMessage-shaped input into a :class:`PeerRequest`.

    Returns ``None`` when no cA2A extension keys are present: the message is
    ordinary A2A input and must not be treated as a partial trust state.

    When any cA2A key is present, parsing fails closed with
    :class:`TransportError` (or :class:`InvalidCredential` for a malformed
    hop) rather than inventing defaults.

    ``sealed_payload`` is treated as opaque bytes only. Decoding it does not
    imply the ciphertext is bound to a verified attestation measurement.
    """
    meta = collect_metadata(message_or_request, metadata=metadata)
    if not has_ca2a_metadata(meta):
        return None

    raw_chain = meta.get(KEY_DELEGATION_CHAIN)
    if raw_chain is None:
        raise TransportError("cA2A metadata present but delegation_chain is missing")
    if not isinstance(raw_chain, list) or not raw_chain:
        raise TransportError(
            "delegation_chain must be a non-empty JSON array of credential objects"
        )

    chain: list[DelegationCredential] = []
    for i, item in enumerate(raw_chain):
        if not isinstance(item, dict):
            raise TransportError(
                f"delegation_chain hop {i} must be an object",
                detail=f"got {type(item).__name__}",
            )
        try:
            chain.append(DelegationCredential.from_dict(item))
        except InvalidCredential as exc:
            raise TransportError(
                f"delegation_chain hop {i} is malformed",
                detail=str(exc),
            ) from exc

    capability = meta.get(KEY_REQUESTED_CAPABILITY)
    if not isinstance(capability, str) or not capability:
        raise TransportError("requested_capability must be a non-empty string")

    record_id = meta.get(KEY_RECORD_ID)
    if not isinstance(record_id, str) or not record_id:
        raise TransportError("record_id must be a non-empty string")

    if KEY_PARENT_RECORD_HASH not in meta:
        raise TransportError(
            "parent_record_hash key is required when cA2A metadata is present "
            "(use null for a root hop)"
        )
    parent_raw = meta[KEY_PARENT_RECORD_HASH]
    if parent_raw is None:
        parent_record_hash: str | None = None
    elif isinstance(parent_raw, str):
        parent_record_hash = parent_raw
    else:
        raise TransportError("parent_record_hash must be a string or null")

    sealed_payload: bytes | None = None
    if KEY_SEALED_PAYLOAD in meta and meta[KEY_SEALED_PAYLOAD] is not None:
        sealed_raw = meta[KEY_SEALED_PAYLOAD]
        if not isinstance(sealed_raw, str):
            raise TransportError("sealed_payload must be a base64url string or null")
        sealed_payload = _b64url_decode(sealed_raw)

    return PeerRequest(
        chain=chain,
        requested_capability=capability,
        record_id=record_id,
        sealed_payload=sealed_payload,
        parent_record_hash=parent_record_hash,
    )


def attach_ca2a_metadata(
    message: dict[str, Any],
    request: PeerRequest,
) -> dict[str, Any]:
    """Return a deep copy of ``message`` with cA2A extension fields attached.

    Existing non-cA2A metadata keys are preserved. Existing cA2A keys are
    replaced with values derived from ``request``. A2A routing fields and
    message ``parts`` / payload semantics are left untouched.
    """
    out = copy.deepcopy(message)
    meta = out.setdefault("metadata", {})
    if not isinstance(meta, dict):
        raise TransportError("message.metadata must be a mapping when attaching cA2A fields")

    meta[KEY_DELEGATION_CHAIN] = [_credential_to_dict(c) for c in request.chain]
    meta[KEY_REQUESTED_CAPABILITY] = request.requested_capability
    meta[KEY_RECORD_ID] = request.record_id
    meta[KEY_PARENT_RECORD_HASH] = request.parent_record_hash
    if request.sealed_payload is None:
        meta.pop(KEY_SEALED_PAYLOAD, None)
    else:
        meta[KEY_SEALED_PAYLOAD] = _b64url_encode(request.sealed_payload)
    return out
