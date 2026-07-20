"""Offline verification of a cA2A TRACE delegation DAG.

Given the signed TRACE records a workflow emitted (one per delegation hop), this
verifier confirms, from the signed records alone and a set of trusted keys:

1. each record is structurally valid TRACE and signed by a trusted key;
2. the records form an unbroken root-to-leaf chain, each hop's
   ``delegation.parent_record_hash`` equal to the hash of the parent's full
   signed record (see :func:`ca2a_runtime.trace_binding.trace_record_hash`);
3. the root carries no delegation block and no record hash repeats.

The base TRACE record is validated with ``agentrust-trace``. The A2A profile's
``delegation`` block is validated here, in cA2A, because it is the profile's own
extension: a published ``agentrust-trace`` whose bundled schema predates the
block would otherwise reject any delegated record. cA2A owns the profile, so it
owns the block's validation and stays robust to that cross-repo version skew.

Scope non-escalation across hops is a property of the delegation *credentials*,
verified by :func:`ca2a_runtime.delegation.verify_chain`; this verifier covers
the record linkage and authenticity. :func:`cross_check_trace_dag` ties the two
together by matching each hop's recorded credential id to the chain.

Everything fails closed: the first violation raises, and no partial result is
returned.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from agentrust_trace import validate_json, verify_record
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ca2a_runtime.delegation import DelegationCredential
from ca2a_runtime.errors import ProvenanceLinkBroken, TraceRecordInvalid
from ca2a_runtime.trace_binding import trace_record_hash


@dataclass(frozen=True)
class TraceDagResult:
    """The outcome of a successful TRACE DAG verification."""

    hops: int
    root_subject: str
    leaf_subject: str
    subjects: list[str]


# The TRACE digest form (sha256:/sha384: + lowercase hex), same as the schema.
_DIGEST_RE = re.compile(r"^sha(256:[0-9a-f]{64}|384:[0-9a-f]{96})$")


def _validate_delegation_block(block: Any, index: int) -> None:
    """Validate the A2A profile delegation block on a record (None means root).

    Mirrors the ``delegation`` object in the TRACE v0.1 schema: exactly
    ``parent_record_hash`` (a digest) and ``credential_id`` (a non-empty string),
    no other keys. Validated in cA2A so a stale published ``agentrust-trace``
    schema cannot make a well-formed delegated record fail structural checks.
    """
    if block is None:
        return
    if not isinstance(block, dict):
        raise TraceRecordInvalid(f"record {index} delegation block is not an object")
    if set(block) != {"parent_record_hash", "credential_id"}:
        raise TraceRecordInvalid(
            f"record {index} delegation block has unexpected fields",
            detail=f"got {sorted(block)}, expected parent_record_hash + credential_id",
        )
    parent_hash = block["parent_record_hash"]
    if not isinstance(parent_hash, str) or not _DIGEST_RE.match(parent_hash):
        raise TraceRecordInvalid(f"record {index} delegation.parent_record_hash is not a digest")
    credential_id = block["credential_id"]
    if not isinstance(credential_id, str) or not credential_id:
        raise TraceRecordInvalid(f"record {index} delegation.credential_id is missing")


def _b64url_decode(value: str) -> bytes:
    padded = value + "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(padded)


def _jwk_raw(jwk: dict[str, Any]) -> bytes:
    """Raw Ed25519 public-key bytes from an OKP JWK, or raise TraceRecordInvalid."""
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise TraceRecordInvalid(
            "unsupported cnf.jwk key type", detail="expected an OKP/Ed25519 key"
        )
    x = jwk.get("x")
    if not isinstance(x, str):
        raise TraceRecordInvalid("cnf.jwk is missing its 'x' parameter")
    try:
        return _b64url_decode(x)
    except (binascii.Error, ValueError) as exc:
        raise TraceRecordInvalid("cnf.jwk 'x' is not valid base64url", detail=str(exc)) from exc


def _trusted_raw_keys(trusted_keys: Iterable[Any]) -> set[bytes]:
    """Normalize trusted keys (Ed25519PublicKey or JWK dict) to raw-byte identities."""
    raw: set[bytes] = set()
    for key in trusted_keys:
        if isinstance(key, Ed25519PublicKey):
            raw.add(
                key.public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            )
        elif isinstance(key, dict):
            raw.add(_jwk_raw(key))
        else:
            raise TypeError(f"unsupported trusted key type: {type(key).__name__}")
    return raw


def verify_trace_dag(
    records: list[dict[str, Any]],
    *,
    trusted_keys: Iterable[Any],
    max_age_seconds: int | None = None,
) -> TraceDagResult:
    """Verify a signed root-to-leaf TRACE delegation DAG offline.

    ``trusted_keys`` is the set of keys the caller trusts to have produced hops,
    each an ``Ed25519PublicKey`` or an OKP JWK dict. A record is accepted only if
    the key it embeds is trusted *and* its signature verifies against that key, so
    a record signed by an untrusted key (or a trusted key spoofed into ``cnf``) is
    rejected. ``max_age_seconds`` bounds each record's freshness; pass ``None``
    (the default, suited to offline audit of historical records) to skip the age
    check.

    Raises ``TraceRecordInvalid`` for a structurally invalid, untrusted, or
    badly-signed record, and ``ProvenanceLinkBroken`` for a broken parent link,
    a mislabeled root, or a repeated record. Returns a summary on success.
    """
    if not records:
        raise ProvenanceLinkBroken("empty TRACE DAG")

    trusted = _trusted_raw_keys(trusted_keys)
    prev_hash: str | None = None
    seen_hashes: set[str] = set()
    subjects: list[str] = []

    for i, record in enumerate(records):
        # Validate the base record with agentrust-trace, and the A2A profile's
        # delegation block here (see the module docstring): the base schema is
        # version-stable, the profile extension is cA2A's own.
        base_record = {k: v for k, v in record.items() if k != "delegation"}
        try:
            validate_json(base_record)
        except Exception as exc:  # jsonschema.ValidationError
            raise TraceRecordInvalid(
                f"record {i} is not a valid TRACE record", detail=str(exc)
            ) from exc
        _validate_delegation_block(record.get("delegation"), i)

        jwk = record.get("cnf", {}).get("jwk", {})
        if _jwk_raw(jwk) not in trusted:
            raise TraceRecordInvalid(f"record {i} is signed by an untrusted key")
        try:
            verify_record(record, jwk, max_age_seconds=max_age_seconds)
        except InvalidSignature as exc:
            raise TraceRecordInvalid(f"record {i} signature does not verify") from exc
        except ValueError as exc:
            raise TraceRecordInvalid(
                f"record {i} could not be verified", detail=str(exc)
            ) from exc

        record_hash = trace_record_hash(record)
        if record_hash in seen_hashes:
            raise ProvenanceLinkBroken(f"record {i} repeats an earlier record")
        seen_hashes.add(record_hash)

        delegation = record.get("delegation")
        if i == 0:
            if delegation is not None:
                raise ProvenanceLinkBroken("root record must not carry a delegation block")
        else:
            if delegation is None:
                raise ProvenanceLinkBroken(f"record {i} is missing its delegation block")
            if delegation.get("parent_record_hash") != prev_hash:
                raise ProvenanceLinkBroken(
                    f"record {i} parent link does not match the previous record's hash",
                    detail="a tampered or reparented record was detected",
                )

        subjects.append(record["subject"])
        prev_hash = record_hash

    return TraceDagResult(
        hops=len(records),
        root_subject=subjects[0],
        leaf_subject=subjects[-1],
        subjects=subjects,
    )


def cross_check_trace_dag(
    records: list[dict[str, Any]], chain: list[DelegationCredential]
) -> None:
    """Tie a verified TRACE DAG to the delegation chain it should reflect.

    Confirms the DAG has one record per credential and that every non-root hop
    acted under the credential the chain names at that position (the root hop
    records no credential id, per the profile). Raises ProvenanceLinkBroken on
    any mismatch. Run ``verify_trace_dag`` and ``verify_chain`` first; this only
    checks that they line up.
    """
    if len(records) != len(chain):
        raise ProvenanceLinkBroken(
            f"DAG length {len(records)} does not match chain length {len(chain)}"
        )
    for i in range(1, len(records)):
        delegation = records[i].get("delegation") or {}
        if delegation.get("credential_id") != chain[i].credential_id:
            raise ProvenanceLinkBroken(f"record {i} credential_id does not match the chain")
