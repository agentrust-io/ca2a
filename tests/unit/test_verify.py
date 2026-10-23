"""Tests for the offline ca2a-verify layer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca2a_runtime.cli import main as cli_main
from ca2a_runtime.delegation import DelegationCredential
from ca2a_runtime.errors import CA2AError, InvalidCredential, InvalidRevocation, ScopeEscalation
from ca2a_verify import (
    ChainResult,
    load_revocation_snapshot,
    verify_chain_file,
    verify_delegation_chain,
)
from tests.unit.conftest import build_chain


def _dump(chain: list[DelegationCredential]) -> list[dict]:
    return [c.body() | {"signature": c.signature} for c in chain]


def test_verify_delegation_chain_summary(valid_chain: list[DelegationCredential]) -> None:
    result = verify_delegation_chain(valid_chain, trusted_root_issuers={valid_chain[0].issuer})
    assert isinstance(result, ChainResult)
    assert result.hops == 3
    assert result.leaf_scope == ["cap:a"]
    assert result.root_issuer == valid_chain[0].issuer


def test_verify_delegation_chain_rejects_escalation() -> None:
    chain = build_chain([frozenset({"cap:a"}), frozenset({"cap:a", "cap:b"})])
    with pytest.raises(ScopeEscalation):
        verify_delegation_chain(chain, trusted_root_issuers={chain[0].issuer})


def test_verify_chain_file_list(tmp_path: Path, valid_chain: list[DelegationCredential]) -> None:
    p = tmp_path / "chain.json"
    p.write_text(json.dumps(_dump(valid_chain)))
    result = verify_chain_file(p, trusted_root_issuers={valid_chain[0].issuer})
    assert result.hops == 3


def test_verify_chain_file_wrapped(tmp_path: Path, valid_chain: list[DelegationCredential]) -> None:
    p = tmp_path / "chain.json"
    p.write_text(json.dumps({"chain": _dump(valid_chain)}))
    result = verify_chain_file(p, trusted_root_issuers={valid_chain[0].issuer})
    assert result.hops == 3


def test_verify_chain_file_missing() -> None:
    with pytest.raises(InvalidCredential):
        verify_chain_file("/nonexistent/chain.json", trusted_root_issuers=set())


def test_verify_chain_file_bad_json(tmp_path: Path) -> None:
    p = tmp_path / "chain.json"
    p.write_text("{not json")
    with pytest.raises(InvalidCredential):
        verify_chain_file(p, trusted_root_issuers=set())


def test_verify_chain_file_wrong_shape(tmp_path: Path) -> None:
    p = tmp_path / "chain.json"
    p.write_text(json.dumps({"nope": 1}))
    with pytest.raises(InvalidCredential):
        verify_chain_file(p, trusted_root_issuers=set())


@pytest.mark.parametrize("hop", [None, 1, True, 1.5, "cred", ["credential_id"]])
def test_verify_chain_file_non_object_hop(tmp_path: Path, hop: object) -> None:
    """A hop that is not a JSON object is a malformed credential.

    null, numbers and booleans used to raise TypeError out of from_dict, and
    the verify-chain CLI, which catches CA2AError, printed a traceback.
    """
    p = tmp_path / "chain.json"
    p.write_text(json.dumps([hop]))
    with pytest.raises(InvalidCredential, match="must be a JSON object"):
        verify_chain_file(p, trusted_root_issuers=set())


def test_offline_verifier_rejects_self_consistent_untrusted_chain(
    valid_chain: list[DelegationCredential],
) -> None:
    with pytest.raises(CA2AError, match="root issuer is not trusted"):
        verify_delegation_chain(valid_chain, trusted_root_issuers=set())


def test_verify_chain_cli_requires_a_trusted_root(
    tmp_path: Path, valid_chain: list[DelegationCredential]
) -> None:
    path = tmp_path / "chain.json"
    path.write_text(json.dumps(_dump(valid_chain)))

    with pytest.raises(SystemExit) as exc:
        cli_main(["verify-chain", "--chain", str(path)])

    assert exc.value.code == 2


def test_verify_chain_cli_accepts_an_explicit_trusted_root(
    tmp_path: Path, valid_chain: list[DelegationCredential]
) -> None:
    path = tmp_path / "chain.json"
    path.write_text(json.dumps(_dump(valid_chain)))

    assert (
        cli_main(
            [
                "verify-chain",
                "--chain",
                str(path),
                "--trusted-root-issuer",
                valid_chain[0].issuer,
            ]
        )
        == 0
    )


def test_verify_dag_cli_requires_a_trusted_root_when_cross_checking_chain(
    tmp_path: Path,
) -> None:
    dag_path = tmp_path / "dag.json"
    chain_path = tmp_path / "chain.json"
    dag_path.write_text("[]")
    chain_path.write_text("[]")

    with pytest.raises(SystemExit) as exc:
        cli_main(
            [
                "verify-dag",
                "--dag",
                str(dag_path),
                "--chain",
                str(chain_path),
            ]
        )

    assert exc.value.code == 2


def test_verify_chain_file_rejects_duplicate_json_keys(
    tmp_path: Path, valid_chain: list[DelegationCredential]
) -> None:
    dumped = _dump(valid_chain)
    hop_json = json.dumps(dumped[0])
    # Inject a duplicate credential_id key before the legitimate one.
    dup_hop = '{"credential_id": "shadowed", ' + hop_json[1:]
    p = tmp_path / "dup-hop.json"
    p.write_text(f"[{dup_hop}]", encoding="utf-8")
    with pytest.raises(InvalidCredential, match="invalid JSON") as exc_info:
        verify_chain_file(p, trusted_root_issuers={valid_chain[0].issuer})
    assert "duplicate JSON object key" in (exc_info.value.detail or "")

    p_top = tmp_path / "dup-top.json"
    p_top.write_text(
        f'{{"chain": [], "chain": {json.dumps(dumped)}}}',
        encoding="utf-8",
    )
    with pytest.raises(InvalidCredential, match="invalid JSON") as exc_top:
        verify_chain_file(p_top, trusted_root_issuers={valid_chain[0].issuer})
    assert "duplicate JSON object key" in (exc_top.value.detail or "")


def test_load_revocation_snapshot_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    p = tmp_path / "dup-revocations.json"
    p.write_text('{"as_of": 100, "as_of": 200, "revocations": []}', encoding="utf-8")
    with pytest.raises(InvalidRevocation, match="invalid JSON") as exc_info:
        load_revocation_snapshot(p)
    assert "duplicate JSON object key" in (exc_info.value.detail or "")

