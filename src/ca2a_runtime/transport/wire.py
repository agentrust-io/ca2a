"""JSON encodings for the reference HTTP transport's responses and handshake.

``a2a_adapter`` binds the inbound *request* from A2A metadata. It deliberately
leaves out the pieces the reference HTTP server needs on the way back: the peer
result and error responses, and the channel-offer exchange for the attestation
handshake. Those are here. This is reference-transport plumbing, not part of the
A2A profile itself.
"""

from __future__ import annotations

from typing import Any

from ca2a_runtime.attestation import ChannelOffer
from ca2a_runtime.errors import CA2AError, TransportError
from ca2a_runtime.peer import PeerResult
from ca2a_runtime.provenance import DelegationRecord
from ca2a_runtime.tee.base import AttestationReport


def _record_to_dict(record: DelegationRecord) -> dict[str, Any]:
    body = record.body()
    body["record_hash"] = record.record_hash()
    return body


def serialize_peer_result(result: PeerResult) -> dict[str, Any]:
    """Serialize an accepted result. The opened payload is the callee's
    confidential input and is never echoed; the response returns the provenance
    record (with its hash) so the caller can chain the next hop."""
    return {
        "accepted": True,
        "effective_scope": sorted(result.effective_scope),
        "granted_capability": result.granted_capability,
        "record": _record_to_dict(result.record),
    }


def serialize_error(err: CA2AError) -> dict[str, Any]:
    """Serialize a CA2AError using its stable code and HTTP status."""
    return {
        "error": {
            "code": err.code,
            "message": str(err),
            "detail": err.detail,
            "http_status": err.http_status,
        }
    }


def serialize_channel_offer(offer: ChannelOffer) -> dict[str, Any]:
    """Serialize a channel offer (the callee's attested channel key)."""
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
        raise TransportError("malformed channel offer", detail=str(exc)) from exc
    return ChannelOffer(channel_public_key=public_key, report=report)
