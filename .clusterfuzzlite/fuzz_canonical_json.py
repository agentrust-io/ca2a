#!/usr/bin/python3
"""Fuzz the RFC 8785 canonicalizer for the invariant its signatures depend on.

canonicalize() produces the bytes every delegation credential, holder proof,
revocation statement and response MAC is computed over, so the bytes must be a
faithful, lossless encoding of the input. The property asserted is a round trip:
parsing the canonical output back must reproduce the input exactly.

A crash-only check would pass over the bugs that matter here. The ones found in
sibling canonicalizers were silent: two distinct keys serialized as one key
twice, a parser kept one of the pair, and a field vanished from a document whose
signature claimed to cover it.

Structure is built from the fuzz data rather than by mutating JSON text, so the
budget goes on key and value shapes (combining marks, surrogate pairs, control
characters, integers straddling 2**53) rather than on producing valid JSON.
"""

import json
import sys

import atheris

with atheris.instrument_imports():
    from ca2a_runtime.canonical import canonicalize

_MAX_DEPTH = 4
_MAX_ITEMS = 6
_SAFE = 2**53 - 1


def _build(fdp, depth=0):
    if depth >= _MAX_DEPTH or fdp.remaining_bytes() == 0:
        return fdp.ConsumeUnicodeNoSurrogates(16)
    kind = fdp.ConsumeIntInRange(0, 6)
    if kind == 0:
        return None
    if kind == 1:
        return fdp.ConsumeBool()
    if kind == 2:
        # Straddle the safe-integer boundary: outside it canonicalize() must
        # refuse rather than emit digits a conforming verifier would not.
        return fdp.ConsumeIntInRange(-(2**54), 2**54)
    if kind == 3:
        return fdp.ConsumeUnicodeNoSurrogates(64)
    if kind == 4:
        return [_build(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(0, _MAX_ITEMS))]
    return {
        fdp.ConsumeUnicodeNoSurrogates(24): _build(fdp, depth + 1)
        for _ in range(fdp.ConsumeIntInRange(0, _MAX_ITEMS))
    }


def _has_unsafe_int(value):
    if isinstance(value, bool):
        return False
    if isinstance(value, int):
        return not -_SAFE <= value <= _SAFE
    if isinstance(value, dict):
        return any(_has_unsafe_int(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_unsafe_int(v) for v in value)
    return False


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    value = _build(fdp)
    try:
        out = canonicalize(value)
    except ValueError:
        # Declared: integers outside the RFC 8785 safe domain, and only those.
        assert _has_unsafe_int(value), "canonicalize() refused an in-domain value"
        return
    assert not _has_unsafe_int(value), "an out-of-domain integer was serialized"

    # cA2A's data model has no floats, so every number re-parses as the int it
    # was and the round trip can be asserted exactly, bools included.
    assert json.loads(out) == value, f"canonical bytes did not round-trip: {out!r}"
    assert canonicalize(json.loads(out)) == out, "canonical form is not a fixed point"


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
