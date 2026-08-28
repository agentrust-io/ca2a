"""Shared base64url codec for the reference transport's wire formats.

Both :mod:`ca2a_runtime.transport.wire` (channel-offer evidence) and
:mod:`ca2a_runtime.transport.a2a_adapter` (sealed payloads) need to put raw
bytes into JSON as base64url text, and both need to fail closed on malformed
input rather than silently accepting or truncating it. This is the one place
that alphabet and padding logic lives, so the two encodings cannot drift
apart -- see ``wire.py``'s own docstring for why that matters.

This has to be its own module rather than living in either of the two:
``a2a_adapter`` already imports ``parse_channel_offer``/``serialize_channel_offer``
from ``wire``, so ``wire`` importing back from ``a2a_adapter`` would be circular.
"""

from __future__ import annotations

import base64
import re

from ca2a_runtime.errors import TransportError

_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+")


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def b64url_decode(field: str, value: str) -> bytes:
    """Decode a base64url string, failing closed on any non-base64url input.

    ``field`` names the value in the error message (e.g. ``"sealed_payload"``
    or ``"raw_evidence"``), since the same helper serves several wire fields.
    """
    if not isinstance(value, str) or not _BASE64URL_RE.fullmatch(value):
        raise TransportError(
            f"{field} is not valid base64url",
            detail=f"expected a non-empty base64url string, got {type(value).__name__}",
        )
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise TransportError(f"{field} is not valid base64url", detail=str(exc)) from exc
