"""Authenticated lineage and unsigned structural diagnostics are distinct (#168)."""

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from ca2a_runtime.cli import main
from ca2a_runtime.provenance import record_for
from ca2a_runtime.trace_binding import HopContext, HopSpec, digest, emit_dag, sign_trace_record
from tests.unit.conftest import build_chain_with_keys


@pytest.fixture
def evidence(tmp_path):
    chain, keys = build_chain_with_keys([frozenset({"read"})] * 3)
    context = HopContext.software(
        model_provider="test",
        model_id="test",
        image_label="test",
        policy_bundle_hash=digest(b"policy"),
    )
    signed = emit_dag(
        [
            HopSpec(f"did:web:peer{i}", keys[i], context, 1750000000, c.credential_id)
            for i, c in enumerate(chain)
        ]
    )
    native = []
    for i, c in enumerate(chain):
        native.append(record_for(c, f"r{i}", native[-1].record_hash() if native else None))
    chain_path = tmp_path / "chain.json"
    chain_path.write_text(json.dumps([c.body() | {"signature": c.signature} for c in chain]))
    return chain, keys, signed, native, chain_path, tmp_path / "dag.json"


def run(evidence, capsys, records, command="verify-lineage", extra=()):
    chain, _, _, _, chain_path, dag_path = evidence
    dag_path.write_text(json.dumps(records))
    rc = main(
        [
            command,
            "--dag",
            str(dag_path),
            "--chain",
            str(chain_path),
            "--trusted-root-issuer",
            chain[0].issuer,
            *extra,
        ]
    )
    return rc, json.loads(capsys.readouterr().out)


def test_signed_path_authenticates(evidence, capsys):
    rc, out = run(evidence, capsys, evidence[2])
    assert rc == 0
    assert out["verified"] is True
    assert out["verification"] == "authenticated_lineage"
    assert out["cross_checked"] is True
    assert out["revocation"] == "not_checked"


def test_native_default_is_not_a_verification_success(evidence, capsys):
    rc, out = run(evidence, capsys, [r.body() for r in evidence[3]], "verify-dag")
    assert rc == 1
    assert out["verified"] is False
    assert out["code"] == "UNAUTHENTICATED_LINEAGE"


def test_signed_path_requires_independent_root_configuration(evidence):
    with pytest.raises(SystemExit) as exc:
        main(["verify-lineage", "--dag", str(evidence[5]), "--chain", str(evidence[4])])
    assert exc.value.code == 2


def test_invalid_credential_signature_is_refused(evidence, capsys):
    chain = json.loads(evidence[4].read_text())
    chain[1]["signature"] = "00" * 64
    evidence[4].write_text(json.dumps(chain))
    rc, out = run(evidence, capsys, evidence[2])
    assert rc == 1 and out["verified"] is False


@pytest.mark.parametrize("substitute", [False, True])
def test_native_history_never_authenticates(evidence, capsys, substitute):
    records = []
    for rec in evidence[3]:
        if substitute:
            rec = replace(
                rec,
                record_id="replacement-" + rec.record_id,
                caller_attestation="hardware",
                parent_record_hash=records[-1].record_hash() if records else None,
            )
        records.append(rec)
    body = [r.body() for r in records]
    rc, out = run(evidence, capsys, body)
    assert rc == 1 and out["verified"] is False
    rc, out = run(evidence, capsys, body, "verify-dag")
    assert rc == 1 and out["verified"] is False
    assert out["structural_verified"] is True
    assert out["code"] == "UNAUTHENTICATED_LINEAGE"
    rc, out = run(evidence, capsys, body, "verify-dag", ("--structural-only",))
    assert rc == 0 and out["verified"] is False


@pytest.mark.parametrize("index", range(3))
def test_each_signature_is_required(evidence, capsys, index):
    records = deepcopy(evidence[2])
    records[index]["subject"] = "did:web:substituted"
    rc, out = run(evidence, capsys, records)
    assert rc == 1 and out["code"] == "TRACE_RECORD_INVALID"


def test_valid_signatures_do_not_bypass_credential_crosscheck(evidence, capsys):
    records = deepcopy(evidence[2])
    records[-1]["delegation"]["credential_id"] = "other-credential"
    records[-1] = sign_trace_record(records[-1], evidence[1][-1])
    rc, out = run(evidence, capsys, records)
    assert rc == 1 and out["code"] == "PROVENANCE_LINK_BROKEN"


def test_signed_reparenting_is_rejected(evidence, capsys):
    records = deepcopy(evidence[2])
    records[-1]["delegation"]["parent_record_hash"] = "sha256:" + "0" * 64
    records[-1] = sign_trace_record(records[-1], evidence[1][-1])
    rc, out = run(evidence, capsys, records)
    assert rc == 1 and out["code"] == "PROVENANCE_LINK_BROKEN"


def test_untrusted_root_is_rejected(evidence, capsys):
    evidence[4].write_text(
        json.dumps(
            [
                c.body() | {"signature": c.signature}
                for c in build_chain_with_keys([frozenset({"read"})] * 3)[0]
            ]
        )
    )
    rc, out = run(evidence, capsys, evidence[2])
    assert rc == 1 and out["code"] == "UNTRUSTED_DELEGATION_ROOT"


@pytest.mark.parametrize("bad", [None, {}, [], [None], ["record"], [{"cnf": None}]])
def test_malformed_signed_path_fails_closed(evidence, capsys, bad):
    rc, out = run(evidence, capsys, bad)
    assert rc == 1 and out["verified"] is False


def test_cli_rejects_duplicate_json_keys_and_non_string_record_fields(evidence, capsys):
    chain, _, _, native, chain_path, dag_path = evidence
    # Duplicate key in DAG JSON
    raw_rec = json.dumps(native[0].body())
    dup_dag = "[" + raw_rec[:-1] + ', "decision": "allow", "decision": "deny"}]'
    dag_path.write_text(dup_dag, encoding="utf-8")
    rc = main(["verify-dag", "--dag", str(dag_path), "--structural-only"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["code"] == "PROVENANCE_LINK_BROKEN"

    # String scope instead of list (previously split into characters)
    bad_scope = native[0].body()
    bad_scope["scope"] = "read"
    dag_path.write_text(json.dumps([bad_scope]), encoding="utf-8")
    rc = main(["verify-dag", "--dag", str(dag_path), "--structural-only"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["code"] == "PROVENANCE_LINK_BROKEN"

    # Non-string record_id (previously coerced via str(...))
    bad_id = native[0].body()
    bad_id["record_id"] = 123
    dag_path.write_text(json.dumps([bad_id]), encoding="utf-8")
    rc = main(["verify-dag", "--dag", str(dag_path), "--structural-only"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["code"] == "PROVENANCE_LINK_BROKEN"

    # Invalid decision value
    bad_dec = native[0].body()
    bad_dec["decision"] = "maybe"
    dag_path.write_text(json.dumps([bad_dec]), encoding="utf-8")
    rc = main(["verify-dag", "--dag", str(dag_path), "--structural-only"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["code"] == "PROVENANCE_LINK_BROKEN"

    # Duplicate key in chain JSON
    raw_cred = json.dumps(chain[0].body() | {"signature": chain[0].signature})
    dup_chain = "[" + raw_cred[:-1] + ', "depth": 0}]'
    chain_path.write_text(dup_chain, encoding="utf-8")
    rc = main(
        [
            "verify-lineage",
            "--dag",
            str(dag_path),
            "--chain",
            str(chain_path),
            "--trusted-root-issuer",
            chain[0].issuer,
        ]
    )
    out = json.loads(capsys.readouterr().out)
    assert rc == 1 and out["code"] == "INVALID_CREDENTIAL"

