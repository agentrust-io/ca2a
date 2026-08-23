"""Tests for the offline ca2a-verify layer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ca2a_runtime.cli import main as cli_main
from ca2a_runtime.delegation import DelegationCredential
from ca2a_runtime.errors import CA2AError, InvalidCredential, ScopeEscalation
from ca2a_verify import ChainResult, verify_chain_file, verify_delegation_chain
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
