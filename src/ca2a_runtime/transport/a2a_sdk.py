"""Bridge between the official ``a2a-sdk`` and the cA2A profile.

cA2A is a profile *on* A2A, and until this module it integrated with no A2A
implementation: :mod:`ca2a_runtime.transport.a2a_adapter` parsed A2A-shaped
``dict``s and :mod:`ca2a_runtime.transport.server` was a bespoke HTTP server. A
team already running the official SDK had no way to adopt the profile short of
replacing their transport with ours, which should not be required to evaluate a profile.

This is the whole bridge, and it is deliberately thin. The SDK carries A2A
``metadata`` as a ``google.protobuf.Struct``, so converting that to a plain
mapping hands the existing adapter exactly what it already parses. The Agent
Card helpers contribute only cA2A's extension to a card the embedding
application owns. They do not invent an agent identity, skill, interface, URL,
serving route, or signature. Nothing here appraises or enforces; it converts,
declares, and records discovery for the embedding application to act on.

**The Struct round trip loses integer-ness.** ``Struct`` has no integer type, so
a credential's ``depth`` of ``0`` comes back as ``0.0``, and its validity bounds
(``not_before`` / ``not_after``) suffer the same fate. This bridge restores only
finite integral values of those fields before handing metadata to the strict
parser. A non-integral value remains a float and is rejected rather than
truncated. ``tests/unit/test_a2a_sdk_bridge.py`` holds both sides of that
boundary.

Install with the extra::

    pip install 'ca2a-runtime[a2a-sdk]'
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from ca2a_runtime.errors import TransportError
from ca2a_runtime.node import PeerNode
from ca2a_runtime.peer import REQUIREMENT_VALUES, PeerRequest
from ca2a_runtime.transport import a2a_adapter
from ca2a_runtime.transport.constants import EXTENSION_URI, KEY_DELEGATION_CHAIN

if TYPE_CHECKING:
    from a2a.types import AgentCard, AgentExtension
else:  # Keep runtime annotations resolvable while preserving the optional extra.
    try:  # pragma: no cover - exercised by whichever branch the environment takes
        from a2a.types import AgentCard, AgentExtension
    except ImportError:  # pragma: no cover
        AgentCard = Any
        AgentExtension = Any

try:  # pragma: no cover - exercised by whichever branch the environment takes
    from google.protobuf import json_format

    _IMPORT_ERROR: ImportError | None = None
except ImportError as exc:  # pragma: no cover
    json_format = None
    _IMPORT_ERROR = exc

__all__ = [
    "AgentCardDiscovery",
    "EXTENSION_HEADER",
    "agent_extension_for_node",
    "attach_to_sdk_message",
    "inspect_agent_card",
    "merge_agent_card",
    "metadata_from_sdk_message",
    "opted_in",
    "parse_sdk_message",
]

#: The header an A2A client uses to opt in to an extension. Mirrors the SDK's own
#: ``a2a.extensions.common.HTTP_EXTENSION_HEADER``, restated rather than imported
#: so this constant is readable without the SDK installed.
EXTENSION_HEADER = "A2A-Extensions"


@dataclass(frozen=True)
class AgentCardDiscovery:
    """What a remote Agent Card says about cA2A, without an enforcement decision.

    Discovery is deliberately permissive in the Developer Preview: a missing or
    malformed declaration is returned as a warning, not raised as a transport
    error. The caller can record this result and choose its own rollout policy
    without this bridge quietly turning absence into either trust or refusal.
    """

    advertised: bool
    required: bool | None
    require_caller_attestation: str | None
    warnings: tuple[str, ...]


def _require_protobuf() -> None:
    if json_format is None:
        raise TransportError(
            "the a2a-sdk bridge needs protobuf",
            detail=f"install 'ca2a-runtime[a2a-sdk]' ({_IMPORT_ERROR})",
        )


def _load_a2a_sdk() -> tuple[Any, Any, Any]:
    """Load the optional SDK pieces used by Agent Card integration."""
    try:
        from a2a.extensions.common import find_extension_by_uri
        from a2a.types import AgentCard, AgentExtension
    except ImportError as exc:  # pragma: no cover - depends on optional install
        raise TransportError(
            "the Agent Card bridge needs the official a2a-sdk",
            detail=f"install 'ca2a-runtime[a2a-sdk]' ({exc})",
        ) from exc
    return AgentCard, AgentExtension, find_extension_by_uri


def agent_extension_for_node(node: PeerNode) -> AgentExtension:
    """Build cA2A's official-SDK ``AgentExtension`` from live node state.

    ``require_caller_attestation`` comes from the :class:`PeerNode` that will
    enforce calls, rather than from a second card-specific configuration value,
    so the declaration cannot drift from runtime behavior. ``required`` remains
    false: peers that do not opt in can still use ordinary A2A.
    """
    _require_protobuf()
    _, agent_extension_type, _ = _load_a2a_sdk()
    extension = agent_extension_type(uri=EXTENSION_URI, required=False)
    json_format.ParseDict(
        {"require_caller_attestation": node.require_caller_attestation},
        extension.params,
    )
    return extension


def merge_agent_card(card: AgentCard, node: PeerNode) -> AgentCard:
    """Return an operator-owned Agent Card with one current cA2A declaration.

    The input is not mutated. Every operator field and every unrelated extension
    is copied unchanged; an existing cA2A declaration is replaced in place and
    duplicate cA2A declarations are collapsed. cA2A does not own enough context
    to construct the rest of a card.

    Call this before the operator signs the card. Modifying a signed card would
    invalidate its signatures, and this bridge deliberately neither verifies nor
    re-signs Agent Cards.
    """
    if card.signatures:
        raise TransportError(
            "merge the cA2A extension before signing the Agent Card",
            detail="cA2A does not verify or re-sign operator Agent Cards",
        )

    agent_card_type, _, _ = _load_a2a_sdk()
    merged = agent_card_type()
    merged.CopyFrom(card)
    generated = agent_extension_for_node(node)
    extensions = merged.capabilities.extensions
    matching = [
        index for index, extension in enumerate(extensions) if extension.uri == EXTENSION_URI
    ]
    if matching:
        extensions[matching[0]].CopyFrom(generated)
        for index in reversed(matching[1:]):
            del extensions[index]
    else:
        extensions.add().CopyFrom(generated)
    return merged


def inspect_agent_card(card: AgentCard) -> AgentCardDiscovery:
    """Record a peer's cA2A Agent Card declaration without refusing the peer.

    Fetching the card remains the official SDK client's job. This helper uses
    the SDK's extension lookup and interprets only the one cA2A parameter defined
    by the profile. Missing or duplicate declarations, ``required=true``, unknown
    parameter names, and unsupported requirement values are warnings for the
    caller to record; none silently changes runtime policy.
    """
    _require_protobuf()
    _, _, find_extension_by_uri = _load_a2a_sdk()
    extension = find_extension_by_uri(card, EXTENSION_URI)
    if extension is None:
        return AgentCardDiscovery(
            advertised=False,
            required=None,
            require_caller_attestation=None,
            warnings=(f"peer Agent Card does not advertise {EXTENSION_URI}",),
        )

    warnings: list[str] = []
    matches = sum(1 for item in card.capabilities.extensions if item.uri == EXTENSION_URI)
    if matches > 1:
        warnings.append(f"peer Agent Card advertises {EXTENSION_URI} {matches} times")
    if extension.required:
        warnings.append("peer Agent Card marks the cA2A extension required=true")

    params = dict(json_format.MessageToDict(extension.params))
    known_params = {"require_caller_attestation"}
    for name in sorted(params.keys() - known_params):
        warnings.append(f"cA2A declaration has an unknown parameter {name!r}")
    raw_requirement = params.get("require_caller_attestation")
    requirement: str | None = None
    if isinstance(raw_requirement, str) and raw_requirement in REQUIREMENT_VALUES:
        requirement = raw_requirement
    elif raw_requirement is None:
        warnings.append("cA2A declaration has no require_caller_attestation parameter")
    else:
        warnings.append("cA2A declaration has an unsupported require_caller_attestation parameter")

    return AgentCardDiscovery(
        advertised=True,
        required=bool(extension.required),
        require_caller_attestation=requirement,
        warnings=tuple(warnings),
    )


def metadata_from_sdk_message(message: Any) -> dict[str, Any]:
    """Return an SDK message's ``metadata`` Struct as a plain mapping.

    Accepts anything carrying a ``metadata`` attribute (the SDK's ``Message``, or
    a ``RequestContext``'s message). A message with no metadata yields an empty
    mapping, which the adapter reads as "not a cA2A message" rather than as a
    malformed one.
    """
    _require_protobuf()
    metadata = getattr(message, "metadata", None)
    if metadata is None:
        return {}
    result = dict(json_format.MessageToDict(metadata))
    chain = result.get(KEY_DELEGATION_CHAIN)
    if isinstance(chain, list):
        for credential in chain:
            if not isinstance(credential, dict):
                continue
            for field in ("depth", "not_before", "not_after"):
                value = credential.get(field)
                if isinstance(value, float) and value.is_integer():
                    credential[field] = int(value)
    return result


def parse_sdk_message(message: Any) -> PeerRequest | None:
    """Parse an SDK message into a :class:`PeerRequest`, or None.

    Returns None when the message carries no cA2A extension keys: it is ordinary
    A2A input and must not be treated as a partial trust state. Fails closed with
    :class:`~ca2a_runtime.errors.TransportError` when cA2A keys are present but
    malformed, exactly as the dict-shaped adapter does, because it *is* the
    dict-shaped adapter.
    """
    return a2a_adapter.parse_peer_request({"metadata": metadata_from_sdk_message(message)})


def attach_to_sdk_message(message: Any, request: PeerRequest) -> Any:
    """Attach the cA2A metadata for ``request`` onto an SDK message, in place.

    Mutates and returns ``message``. Unlike the dict-shaped
    :func:`~ca2a_runtime.transport.a2a_adapter.attach_ca2a_metadata`, which
    deep-copies, an SDK message is a protobuf object the caller is building, so
    copying it would surprise more than it protects. Existing non-cA2A metadata
    keys survive; A2A routing fields and ``parts`` are untouched.

    Also appends the extension URI to ``message.extensions`` when that repeated
    field exists, which is the per-message half of the opt-in the profile
    requires. The HTTP header half is the caller's, since this module does not
    speak HTTP.
    """
    _require_protobuf()
    merged = dict(metadata_from_sdk_message(message))
    merged.update(a2a_adapter.attach_ca2a_metadata({}, request)["metadata"])
    message.metadata.Clear()
    json_format.ParseDict(merged, message.metadata)

    extensions = getattr(message, "extensions", None)
    if extensions is not None and EXTENSION_URI not in extensions:
        extensions.append(EXTENSION_URI)
    return message


def opted_in(header_values: list[str] | None) -> bool:
    """Whether an ``A2A-Extensions`` header opts in to this profile.

    The header may repeat and may carry comma-separated values, so both are
    handled. Absence is False and is not an error: the profile is an overlay, and
    a peer that says nothing is a peer using plain A2A.
    """
    if not header_values:
        return False
    return any(
        item.strip() == EXTENSION_URI for value in header_values for item in value.split(",")
    )
