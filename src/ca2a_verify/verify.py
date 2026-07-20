"""Offline verification of cA2A delegation chains.

Thin wrapper over ``ca2a_runtime.delegation.verify_chain`` that loads a chain
from JSON and returns a structured result. The delegation DAG verifier (linking
each hop's TRACE record to its parent) lives in ``ca2a_verify.dag``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ca2a_runtime.delegation import DelegationCredential, verify_chain
from ca2a_runtime.errors import CA2AError, InvalidCredential

# Re-exported so callers can catch a single verify-layer error type.
VerificationError = CA2AError


@dataclass(frozen=True)
class ChainResult:
    """The outcome of a successful chain verification."""

    hops: int
    root_issuer: str
    leaf_subject: str
    leaf_scope: list[str]


def verify_delegation_chain(
    chain: list[DelegationCredential], *, max_depth: int = 8
) -> ChainResult:
    """Verify a root-to-leaf chain and summarize it. Raises on any violation."""
    verify_chain(chain, max_depth=max_depth)
    root = chain[0]
    leaf = chain[-1]
    return ChainResult(
        hops=len(chain),
        root_issuer=root.issuer,
        leaf_subject=leaf.subject,
        leaf_scope=sorted(leaf.scope),
    )


def _parse_chain(data: Any) -> list[DelegationCredential]:
    if isinstance(data, dict) and "chain" in data:
        data = data["chain"]
    if not isinstance(data, list):
        raise InvalidCredential("chain document must be a list or {\"chain\": [...]}")
    return [DelegationCredential.from_dict(item) for item in data]


def verify_chain_file(path: str | Path, *, max_depth: int = 8) -> ChainResult:
    """Load a delegation chain from a JSON file and verify it."""
    p = Path(path)
    if not p.is_file():
        raise InvalidCredential(f"chain file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidCredential(f"invalid JSON in {p}", detail=str(exc)) from exc
    return verify_delegation_chain(_parse_chain(data), max_depth=max_depth)
