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
    record (with its hash) so the caller can chain the next hop.

    ``caller_attestation`` is also inside ``record``, where it is hashed and
    therefore portable evidence. It is repeated at the top level so a caller can
    see what the callee made of it without unpacking the record, and the two can
    never disagree because both are read from the same result."""
    return {
        "accepted": True,
        "effective_scope": sorted(result.effective_scope),
        "granted_capability": result.granted_capability,
        "caller_attestation": result.caller_attestation,
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


def serialize_channel_offer(
    offer: ChannelOffer, *, challenge: str | None = None
) -> dict[str, Any]:
    """Serialize a channel offer (a peer's attested channel key).

    Used in both directions, which is why it lives here rather than beside either
    one: the callee returns it from the handshake endpoint, and the caller nests
    the same shape in its ``caller_offer`` metadata. One codec, so the two
    encodings cannot drift apart.

    ``challenge`` is the callee's half of a mutual exchange and is omitted when
    the callee issues none, so an older caller sees exactly the response it saw
    before. A caller that does not understand the field simply does not attest.
    """
    body: dict[str, Any] = {
        "channel_public_key": offer.channel_public_key,
        "attestation": {
            "platform": offer.report.platform,
            "measurement": offer.report.measurement,
            "public_key": offer.report.public_key,
            "nonce": offer.report.nonce,
        },
    }
    if challenge is not None:
        body["challenge"] = challenge
    return body


def parse_channel_offer(data: dict[str, Any]) -> ChannelOffer:
    """Parse a channel offer received from a peer. Fails closed."""
    if not isinstance(data, dict):
        raise TransportError(
            "malformed channel offer", detail=f"expected an object, got {type(data).__name__}"
        )
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


def parse_challenge(data: dict[str, Any]) -> str | None:
    """Read the callee's challenge out of a handshake response.

    Returns None when the callee issued none, which is not an error: a callee
    that does not want mutual attestation is a callee the caller can still talk
    to. A present-but-non-string value is malformed and fails closed.
    """
    if "challenge" not in data:
        return None
    challenge = data["challenge"]
    if not isinstance(challenge, str) or not challenge:
        raise TransportError(
            "challenge must be a non-empty string when present",
            detail=f"got {type(challenge).__name__}",
        )
    return challenge
