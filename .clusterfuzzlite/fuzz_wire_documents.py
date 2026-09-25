#!/usr/bin/python3
"""Fuzz the JSON documents cA2A accepts from outside.

Each surface takes arbitrary JSON from a party that has not been authenticated
yet, and each documents one error family for anything malformed:

- the A2A request a callee serves (``PeerNode.handle``), which parses the
  delegation chain, holder proof, caller offer and sealed payload, then runs
  the inbound pipeline up to the first refusal: CA2AError;
- the authenticated-response envelope (``response.decode``):
  ResponseAuthenticationFailed, a CA2AError;
- a revocation snapshot (``RevocationSnapshot.from_dict``): InvalidRevocation;
- a delegation chain document and a TRACE DAG handed to the offline verifier:
  CA2AError.

Anything else escaping (TypeError, AttributeError, KeyError, UnicodeError,
RecursionError) is a crash: on the live path it drops the connection with no
response, and offline it escapes the verifier's contract. The input is decoded
the way the reference server decodes a body, so what reaches the parsers is
exactly what the wire can deliver.
"""

import contextlib
import json
import sys

import atheris

with atheris.instrument_imports():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from ca2a_runtime import response
    from ca2a_runtime.delegation import RevocationSnapshot
    from ca2a_runtime.errors import CA2AError
    from ca2a_runtime.node import PeerNode
    from ca2a_runtime.policy import LocalPolicy
    from ca2a_verify.dag import verify_trace_dag
    from ca2a_verify.verify import _parse_chain, verify_delegation_chain

_ROOT = Ed25519PrivateKey.from_private_bytes(b"\x01" * 32).public_key().public_bytes_raw().hex()
_NODE = PeerNode(LocalPolicy.of(["read", "write"]), trusted_root_issuers={_ROOT})


def _handle(doc):
    if isinstance(doc, dict):
        _NODE.handle(doc)


def _revocations(doc):
    RevocationSnapshot.from_dict(doc)


def _chain(doc):
    verify_delegation_chain(_parse_chain(doc), trusted_root_issuers={_ROOT})


def _dag(doc):
    if isinstance(doc, dict):
        doc = doc.get("records", doc)
    if isinstance(doc, list) and doc:
        verify_trace_dag(doc, trusted_keys=[])


_JSON_TARGETS = [_handle, _revocations, _chain, _dag]


def TestOneInput(data: bytes) -> None:
    if not data:
        return
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, len(_JSON_TARGETS))
    raw = fdp.ConsumeBytes(fdp.remaining_bytes())
    if choice == len(_JSON_TARGETS):
        with contextlib.suppress(CA2AError):
            response.decode(raw)
        return
    try:
        doc = json.loads(raw)
    except (ValueError, RecursionError):
        # The reference server answers 400 before any parser runs.
        return
    with contextlib.suppress(CA2AError):
        _JSON_TARGETS[choice](doc)


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
