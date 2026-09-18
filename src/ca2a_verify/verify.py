"""Offline verification of cA2A delegation chains.

Thin wrapper over ``ca2a_runtime.delegation.verify_chain`` that loads a chain
from JSON and returns a structured result. The delegation DAG verifier (linking
each hop's TRACE record to its parent) lives in ``ca2a_verify.dag``.
"""

from __future__ import annotations

import json
from collections.abc import Collection
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ca2a_runtime.delegation import DelegationCredential, RevocationSnapshot, verify_chain
from ca2a_runtime.errors import CA2AError, InvalidCredential, InvalidRevocation

# Re-exported so callers can catch a single verify-layer error type.
VerificationError = CA2AError


@dataclass(frozen=True)
class ChainResult:
    """The outcome of a successful chain verification."""

    hops: int
    root_issuer: str
    leaf_subject: str
    leaf_scope: list[str]
    revocation_checked: bool = False
    """False when no revocation snapshot was supplied. The chain verified, but
    whether any hop has been revoked was not checked and is not known."""
    revocation_as_of: int | None = None
    """When checked, the ``as_of`` time of the snapshot that found no revoked hop."""

    @property
    def revocation(self) -> str:
        """``"not_revoked"`` when checked against a snapshot, else ``"not_checked"``."""
        return "not_revoked" if self.revocation_checked else "not_checked"


def verify_delegation_chain(
    chain: list[DelegationCredential],
    *,
    trusted_root_issuers: Collection[str],
    max_depth: int = 8,
    at_time: int | None = None,
    revocations: RevocationSnapshot | None = None,
    max_revocation_staleness: int | None = None,
) -> ChainResult:
    """Verify a root-to-leaf chain and summarize it. Raises on any violation.

    ``at_time`` is the Unix time validity windows are evaluated at; ``None``
    means the current time. An auditor replaying recorded evidence passes the
    time the action was decided, not its own.

    ``revocations`` and ``max_revocation_staleness`` are passed to
    :func:`~ca2a_runtime.delegation.verify_chain`. Without a snapshot the result
    has ``revocation_checked=False``.
    """
    status = verify_chain(
        chain,
        max_depth=max_depth,
        trusted_root_issuers=trusted_root_issuers,
        at_time=at_time,
        revocations=revocations,
        max_revocation_staleness=max_revocation_staleness,
    )
    root = chain[0]
    leaf = chain[-1]
    return ChainResult(
        hops=len(chain),
        root_issuer=root.issuer,
        leaf_subject=leaf.subject,
        leaf_scope=sorted(leaf.scope),
        revocation_checked=status.checked,
        revocation_as_of=status.as_of,
    )


def _parse_chain(data: Any) -> list[DelegationCredential]:
    if isinstance(data, dict) and "chain" in data:
        data = data["chain"]
    if not isinstance(data, list):
        raise InvalidCredential('chain document must be a list or {"chain": [...]}')
    return [DelegationCredential.from_dict(item) for item in data]


def verify_chain_file(
    path: str | Path,
    *,
    trusted_root_issuers: Collection[str],
    max_depth: int = 8,
    at_time: int | None = None,
    revocations: RevocationSnapshot | None = None,
    max_revocation_staleness: int | None = None,
) -> ChainResult:
    """Load a delegation chain from a JSON file and verify it."""
    p = Path(path)
    if not p.is_file():
        raise InvalidCredential(f"chain file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidCredential(f"invalid JSON in {p}", detail=str(exc)) from exc
    return verify_delegation_chain(
        _parse_chain(data),
        trusted_root_issuers=trusted_root_issuers,
        max_depth=max_depth,
        at_time=at_time,
        revocations=revocations,
        max_revocation_staleness=max_revocation_staleness,
    )


def load_revocation_snapshot(path: str | Path) -> RevocationSnapshot:
    """Load a revocation snapshot (``{"as_of": ..., "revocations": [...]}``).

    Every statement's signature is checked on load; a snapshot containing any
    statement that does not verify raises ``InvalidRevocation``.
    """
    p = Path(path)
    if not p.is_file():
        raise InvalidRevocation(f"revocation file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidRevocation(f"invalid JSON in {p}", detail=str(exc)) from exc
    return RevocationSnapshot.from_dict(data)
