#!/usr/bin/env python3
"""Generate the offline-verifiable ACTION fixture bundles under tests/fixtures/action/.

Each bundle is a chain.json + dag.json an auditor re-checks with
``ca2a verify-dag --chain``, plus an expected.json stating the verdict. Keys are
seeded, so regenerating is byte-stable and does not churn the diff. The loader
test (tests/conformance/test_action_fixture_bundles.py) verifies the committed
blobs, which is what catches a bundle nobody regenerated.

Idea credit: @Ahmedibrahim222 (agentrust-io/ca2a#36). Tracked in #164.

    python scripts/gen_action_fixtures.py
"""

# ruff: noqa: T201
from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

from ca2a_runtime.delegation import DelegationCredential  # noqa: E402
from ca2a_runtime.provenance import DelegationRecord, denial_record_for, record_for  # noqa: E402

FIXTURE_DIR = REPO_ROOT / "tests" / "fixtures" / "action"
_WRONG_PARENT_HASH = "0" * 64  # well-formed hex that matches no record's hash

_VERIFIED = {
    "provenance_status": "verified",
    "authorization_decision": "allowed",
    "controller_outcome": "accepted",
}
_INVALID = {
    "provenance_status": "invalid",
    "authorization_decision": "not_evaluated",
    "controller_outcome": "not_evaluated",
}
_DENIED = {
    "provenance_status": "verified",
    "authorization_decision": "denied",
    "controller_outcome": "not_evaluated",
}


@dataclass(frozen=True)
class Bundle:
    name: str
    chain: list[DelegationCredential]
    records: list[DelegationRecord]
    verdict: dict[str, str]
    code: str | None = None
    at_time: int | None = None


def _keypair(label: str) -> tuple[Ed25519PrivateKey, str]:
    """A deterministic Ed25519 keypair (RFC 8032 signing is deterministic)."""
    priv = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    return priv, priv.public_key().public_bytes_raw().hex()


def _chain(
    case: str,
    scopes: list[frozenset[str]],
    *,
    not_before: int | None = None,
    not_after: int | None = None,
) -> list[DelegationCredential]:
    """A signed chain, one hop per scope. sign() does not check attenuation, so a
    case may pass a widening scope to exercise the escalation check."""
    chain: list[DelegationCredential] = []
    priv, pub = _keypair(f"{case}::0")
    parent_id: str | None = None
    for depth, scope in enumerate(scopes):
        next_priv, next_pub = _keypair(f"{case}::{depth + 1}")
        cred = DelegationCredential(
            credential_id=f"cred-{depth}",
            issuer=pub,
            subject=next_pub,
            scope=scope,
            depth=depth,
            parent_id=parent_id,
            not_before=not_before,
            not_after=not_after,
        ).sign(priv)
        chain.append(cred)
        parent_id = cred.credential_id
        priv, pub = next_priv, next_pub
    return chain


def _allow_records(chain: list[DelegationCredential]) -> list[DelegationRecord]:
    records: list[DelegationRecord] = []
    parent_hash: str | None = None
    for depth, cred in enumerate(chain):
        rec = record_for(cred, record_id=f"rec-{depth}", parent_record_hash=parent_hash)
        records.append(rec)
        parent_hash = rec.record_hash()
    return records


def _bundles() -> list[Bundle]:
    # ACTION-001: narrowing chain with a matching linked DAG.
    c = _chain(
        "action-001",
        [
            frozenset({"robot.move", "robot.inspect", "robot.stop"}),
            frozenset({"robot.move", "robot.inspect"}),
        ],
    )
    verified = Bundle("action-001-verified", c, _allow_records(c), _VERIFIED)

    # ACTION-002: child record points at a parent hash that matches nothing.
    c = _chain(
        "action-002",
        [
            frozenset({"robot.move", "robot.inspect", "robot.stop"}),
            frozenset({"robot.move", "robot.inspect"}),
        ],
    )
    recs = _allow_records(c)
    recs[1] = replace(recs[1], parent_record_hash=_WRONG_PARENT_HASH)
    parent_mismatch = Bundle(
        "action-002-parent-hash-mismatch", c, recs, _INVALID, "PROVENANCE_LINK_BROKEN"
    )

    # ACTION-005/006: valid chain whose leaf hop refuses an out-of-scope call,
    # recorded as a linked denial rather than dropped.
    c = _chain(
        "action-006",
        [
            frozenset({"task:read", "task:write", "tool:search", "tool:purchase"}),
            frozenset({"task:read", "tool:search", "tool:purchase"}),
            frozenset({"tool:search"}),
        ],
    )
    recs = _allow_records(c)
    reason = "capability 'tool:purchase' is not in the effective scope"
    recs.append(
        denial_record_for(
            c[-1],
            record_id="rec-denied-purchase",
            parent_record_hash=recs[-1].record_hash(),
            requested_capability="tool:purchase",
            effective_scope=c[-1].scope,
            reason=reason,
        )
    )
    denial = Bundle("action-006-policy-denial", c, recs, _DENIED, reason)

    # ACTION-010: hop 1 widens rather than narrows.
    c = _chain("action-010", [frozenset({"robot.move"}), frozenset({"robot.move", "robot.fly"})])
    escalation = Bundle(
        "action-010-scope-escalation", c, _allow_records(c), _INVALID, "SCOPE_ESCALATION"
    )

    # ACTION-012: windowed chain replayed after its window has lapsed.
    c = _chain(
        "action-012",
        [
            frozenset({"robot.move", "robot.inspect", "robot.stop"}),
            frozenset({"robot.move", "robot.inspect"}),
        ],
        not_before=1_000,
        not_after=2_000,
    )
    expired = Bundle(
        "action-012-credential-expired",
        c,
        _allow_records(c),
        _INVALID,
        "CREDENTIAL_EXPIRED",
        at_time=3_000,
    )

    return [verified, parent_mismatch, denial, escalation, expired]


def main() -> int:
    for b in _bundles():
        d = FIXTURE_DIR / b.name
        d.mkdir(parents=True, exist_ok=True)
        chain_doc = {"chain": [{**c.body(), "signature": c.signature} for c in b.chain]}
        dag_doc = {"records": [r.body() for r in b.records]}
        expected = {
            "trusted_root_issuer": b.chain[0].issuer,
            "at_time": b.at_time,
            "verdict": b.verdict,
            "code": b.code,
        }
        (d / "chain.json").write_text(json.dumps(chain_doc, indent=2) + "\n", encoding="utf-8")
        (d / "dag.json").write_text(json.dumps(dag_doc, indent=2) + "\n", encoding="utf-8")
        (d / "expected.json").write_text(json.dumps(expected, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {len(_bundles())} bundles under {FIXTURE_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
