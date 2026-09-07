"""RFC 8785 JSON Canonicalization Scheme (JCS) for the value types cA2A signs.

Credentials and provenance records are signed over the canonical byte encoding
of a JSON object. RFC 8785 fixes that encoding so any conforming implementation
(here and in agent-manifest) produces identical bytes and therefore
cross-verifiable signatures.

This implements JCS for the JSON value types cA2A uses: objects, arrays,
strings, integers, booleans, and null. Object keys are sorted by their UTF-16
code units, strings use JCS minimal escaping (control characters only; non-ASCII
is emitted literally as UTF-8), and integers serialize as their shortest decimal
form. Floating-point numbers are not part of the cA2A data model and are
rejected rather than serialized approximately, and integers are bounded to the
range RFC 8785 can round-trip for the same reason.
"""

from __future__ import annotations

from typing import Any

# RFC 8785 section 3.2.2.3 serializes every number through the ECMAScript Number
# type, so only integers exactly representable as an IEEE 754 double survive the
# round trip. 9007199254740992 and 9007199254740993 both come back as
# "9007199254740992", which would let one signature stand for two records.
# Matches the rfc8785 reference implementation, agent-manifest and trace-spec.
_MAX_SAFE_INTEGER = 9007199254740991  # 2**53 - 1

# JCS short escapes for control characters (RFC 8785 section 3.2.2.2).
_SHORT_ESCAPES = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def _escape_string(s: str) -> str:
    out: list[str] = ['"']
    for ch in s:
        code = ord(ch)
        if code in _SHORT_ESCAPES:
            out.append(_SHORT_ESCAPES[code])
        elif code < 0x20:
            out.append(f"\\u{code:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _serialize(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _escape_string(value)
    if isinstance(value, int):  # bool already handled above
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise ValueError(
                f"integer {value} is outside the safe integer domain RFC 8785 can "
                f"serialize (+/-{_MAX_SAFE_INTEGER}); emitting it verbatim would "
                "diverge from a conforming verifier, and a verifier that applies "
                "the ECMAScript conversion would accept one signature for two "
                "distinct values"
            )
        return str(value)
    if isinstance(value, float):
        raise TypeError("RFC 8785 canonicalization of floats is not supported in cA2A")
    if isinstance(value, list):
        return "[" + ",".join(_serialize(v) for v in value) + "]"
    if isinstance(value, dict):
        items = sorted(value.items(), key=lambda kv: str(kv[0]).encode("utf-16-be"))
        return "{" + ",".join(f"{_escape_string(str(k))}:{_serialize(v)}" for k, v in items) + "}"
    raise TypeError(f"unsupported type for canonicalization: {type(value).__name__}")


def canonicalize(value: Any) -> bytes:
    """Return the RFC 8785 canonical UTF-8 encoding of ``value``."""
    return _serialize(value).encode("utf-8")
