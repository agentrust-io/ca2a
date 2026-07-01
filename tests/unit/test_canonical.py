"""Tests for the RFC 8785 (JCS) canonicalizer."""

from __future__ import annotations

import pytest

from ca2a_runtime.canonical import canonicalize


def test_key_order_is_deterministic() -> None:
    assert canonicalize({"b": 1, "a": 2}) == canonicalize({"a": 2, "b": 1})
    assert canonicalize({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


def test_primitives() -> None:
    assert canonicalize(None) == b"null"
    assert canonicalize(True) == b"true"
    assert canonicalize(False) == b"false"
    assert canonicalize(42) == b"42"
    assert canonicalize("x") == b'"x"'


def test_nested_structures() -> None:
    assert canonicalize({"scope": ["b", "a"], "n": 0}) == b'{"n":0,"scope":["b","a"]}'


def test_control_character_escaping() -> None:
    # Newline and tab use short escapes; other controls use \\u00xx.
    assert canonicalize("a\nb\tc") == b'"a\\nb\\tc"'
    assert canonicalize("\x00\x1f") == b'"\\u0000\\u001f"'
    assert canonicalize('a"b\\c') == b'"a\\"b\\\\c"'


def test_non_ascii_is_literal_utf8() -> None:
    # JCS does not escape non-ASCII; it is emitted as UTF-8 bytes.
    assert canonicalize({"k": "é"}) == '{"k":"é"}'.encode()


def test_utf16_key_ordering() -> None:
    # Keys sort by UTF-16 code units; ASCII keys sort as expected.
    out = canonicalize({"z": 1, "a": 1, "m": 1})
    assert out == b'{"a":1,"m":1,"z":1}'


def test_float_rejected() -> None:
    with pytest.raises(TypeError):
        canonicalize({"x": 1.5})
