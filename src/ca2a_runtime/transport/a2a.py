"""A2A wire binding: parse cA2A-profile A2A messages into runtime objects.

A2A carries the task; cA2A adds a ``ca2a`` block to the message (the delegation
chain, the requested capability, a provenance record id and parent link, and an
optional sealed payload) plus a channel-offer exchange for the attestation
handshake. This module is the boundary the ROADMAP calls out: it parses a real
A2A message's ``ca2a`` block into a :class:`~ca2a_runtime.peer.PeerRequest`,
builds that message on the caller side, and serializes a
:class:`~ca2a_runtime.peer.PeerResult`, a :class:`~ca2a_runtime.attestation.ChannelOffer`,
or an error back onto the wire. It does no I/O; a transport does the I/O and
calls this.
"""

from __future__ import annotations

import base64
from typing import Any

from ca2a_runtime.attestation import ChannelOffer
from ca2a_runtime.delegation.credential import DelegationCredential
from ca2a_runtime.errors import CA2AError, InvalidCredential
from ca2a_runtime.peer import PeerRequest, PeerResult
from ca2a_runtime.provenance import DelegationRecord
from ca2a_runtime.tee.base import AttestationReport


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(value: str, field: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise InvalidCredential(f"invalid base64 in {field}", detail=str(exc)) from exc


def _credential_to_dict(cred: DelegationCredential) -> dict[str, Any]:
    return {**cred.body(), "signature": cred.signature}


def _record_to_dict(record: DelegationRecord) -> dict[str, Any]:
    body = record.body()
    body["record_hash"] = record.record_hash()
    return body


def build_task_message(
    chain: list[DelegationCredential],
    requested_capability: str,
    record_id: str,
    *,
    sealed_payload: bytes | None = None,
    parent_record_hash: str | None = None,
) -> dict[str, Any]:
    """Build the cA2A-profile A2A message a caller sends for a delegated task.

    A real A2A message wraps this ``ca2a`` block inside its own params envelope;
    the block is the profile's contribution and the unit this module parses.
    """
    block: dict[str, Any] = {
        "delegation_chain": [_credential_to_dict(c) for c in chain],
        "requested_capability": requested_capability,
        "record_id": record_id,
    }
    if sealed_payload is not None:
        block["sealed_payload"] = _b64e(sealed_payload)
    if parent_record_hash is not None:
        block["parent_record_hash"] = parent_record_hash
    return {"ca2a": block}


def parse_peer_request(message: dict[str, Any]) -> PeerRequest:
    """Parse an A2A message's ``ca2a`` block into a PeerRequest. Fails closed."""
    block = message.get("ca2a")
    if not isinstance(block, dict):
        raise InvalidCredential("message has no ca2a block")
    try:
        raw_chain = block["delegation_chain"]
        capability = str(block["requested_capability"])
        record_id = str(block["record_id"])
    except (KeyError, TypeError) as exc:
        raise InvalidCredential("ca2a block missing a required field", detail=str(exc)) from exc
    if not isinstance(raw_chain, list):
        raise InvalidCredential("delegation_chain must be a list")
    chain = [DelegationCredential.from_dict(item) for item in raw_chain]

    sealed = block.get("sealed_payload")
    parent = block.get("parent_record_hash")
    return PeerRequest(
        chain=chain,
        requested_capability=capability,
        record_id=record_id,
        sealed_payload=_b64d(sealed, "sealed_payload") if isinstance(sealed, str) else None,
        parent_record_hash=str(parent) if parent is not None else None,
    )


def serialize_peer_result(result: PeerResult) -> dict[str, Any]:
    """Serialize an accepted result onto the wire.

    The opened payload is the callee's confidential task input and is never
    echoed back; the response confirms acceptance and returns the provenance
    record (with its hash) so the caller can chain the next hop.
    """
    return {
        "accepted": True,
        "effective_scope": sorted(result.effective_scope),
        "granted_capability": result.granted_capability,
        "record": _record_to_dict(result.record),
    }


def serialize_error(err: CA2AError) -> dict[str, Any]:
    """Serialize a CA2AError onto the wire using its stable code and status."""
    return {
        "error": {
            "code": err.code,
            "message": str(err),
            "detail": err.detail,
            "http_status": err.http_status,
        }
    }


def serialize_channel_offer(offer: ChannelOffer) -> dict[str, Any]:
    """Serialize a channel offer (the callee's attested channel key) onto the wire."""
    return {
        "channel_public_key": offer.channel_public_key,
        "attestation": {
            "platform": offer.report.platform,
            "measurement": offer.report.measurement,
            "public_key": offer.report.public_key,
            "nonce": offer.report.nonce,
        },
    }


def parse_channel_offer(data: dict[str, Any]) -> ChannelOffer:
    """Parse a channel offer received from a peer. Fails closed."""
    try:
        public_key = str(data["channel_public_key"])
        att = data["attestation"]
        report = AttestationReport(
            platform=str(att["platform"]),
            measurement=str(att["measurement"]),
            public_key=str(att["public_key"]),
            nonce=str(att["nonce"]),
        )
    except (KeyError, TypeError) as exc:
        raise InvalidCredential("malformed channel offer", detail=str(exc)) from exc
    return ChannelOffer(channel_public_key=public_key, report=report)
