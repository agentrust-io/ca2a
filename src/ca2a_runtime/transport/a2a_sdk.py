"""Bridge between the official ``a2a-sdk`` and the cA2A profile.

cA2A is a profile *on* A2A, and until this module it integrated with no A2A
implementation: :mod:`ca2a_runtime.transport.a2a_adapter` parsed A2A-shaped
``dict``s and :mod:`ca2a_runtime.transport.server` was a bespoke HTTP server. A
team already running the official SDK had no way to adopt the profile short of
replacing their transport with ours, which nobody does to try an alpha.

This is the whole bridge, and it is deliberately thin: the SDK carries A2A
``metadata`` as a ``google.protobuf.Struct``, so converting that to a plain
mapping hands the existing adapter exactly what it already parses. One parser,
one set of tests, and the profile stays transport-agnostic. Nothing here
verifies, enforces, or appraises; it converts and delegates.

**The Struct round trip loses integer-ness, and that is safe here for a reason
worth stating.** ``Struct`` has no integer type, so a credential's ``depth`` of
``0`` comes back as ``0.0``. That matters because a credential's signature covers
the RFC 8785 canonical bytes of its body and
:func:`ca2a_runtime.canonical.canonicalize` *refuses floats outright*. The chain
still verifies because ``DelegationCredential.from_dict`` coerces ``depth`` with
``int()`` before anything is canonicalized, so the bytes that get verified are
the integer form the signer signed. A float that is not integral cannot be
smuggled through either: it would coerce to a different integer and the
signature would then fail. ``tests/unit/test_a2a_sdk_bridge.py`` holds that.

Install with the extra::

    pip install 'ca2a[a2a-sdk]'
"""

from __future__ import annotations

from typing import Any

from ca2a_runtime.errors import TransportError
from ca2a_runtime.peer import PeerRequest
from ca2a_runtime.transport import a2a_adapter
from ca2a_runtime.transport.constants import EXTENSION_URI

try:  # pragma: no cover - exercised by whichever branch the environment takes
    from google.protobuf import json_format

    _IMPORT_ERROR: ImportError | None = None
except ImportError as exc:  # pragma: no cover
    json_format = None
    _IMPORT_ERROR = exc

__all__ = [
    "EXTENSION_HEADER",
    "attach_to_sdk_message",
    "metadata_from_sdk_message",
    "opted_in",
    "parse_sdk_message",
]

#: The header an A2A client uses to opt in to an extension. Mirrors the SDK's own
#: ``a2a.extensions.common.HTTP_EXTENSION_HEADER``, restated rather than imported
#: so this constant is readable without the SDK installed.
EXTENSION_HEADER = "A2A-Extensions"


def _require_protobuf() -> None:
    if json_format is None:
        raise TransportError(
            "the a2a-sdk bridge needs protobuf",
            detail=f"install 'ca2a[a2a-sdk]' ({_IMPORT_ERROR})",
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
    return dict(json_format.MessageToDict(metadata))


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
