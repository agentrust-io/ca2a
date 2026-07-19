"""ca2a command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from ca2a_runtime import __version__
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.delegation import DelegationCredential, verify_chain
from ca2a_runtime.errors import CA2AError, ConfigError, InvalidCredential, ProvenanceLinkBroken
from ca2a_runtime.provenance import DelegationRecord, cross_check_chain, verify_dag
from ca2a_verify import verify_chain_file


def _cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        cfg = Ca2aConfig.load(args.config)
    except CA2AError as exc:
        print(f"invalid config: {exc}", file=sys.stderr)
        return 1
    print(f"ok: provider={cfg.provider} enforcement={cfg.enforcement_mode}")
    return 0


def _cmd_verify_chain(args: argparse.Namespace) -> int:
    try:
        result = verify_chain_file(Path(args.chain), max_depth=args.max_depth)
    except CA2AError as exc:
        print(json.dumps({"verified": False, "code": exc.code, "error": str(exc)}))
        return 1
    print(json.dumps({"verified": True, "hops": result.hops, "leaf_scope": result.leaf_scope}))
    return 0


def _load_chain(path: str) -> list[DelegationCredential]:
    p = Path(path)
    if not p.is_file():
        raise InvalidCredential(f"chain file not found: {p}")
    try:
        data: Any = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InvalidCredential(f"invalid JSON in {p}", detail=str(exc)) from exc
    if isinstance(data, dict) and "chain" in data:
        data = data["chain"]
    if not isinstance(data, list):
        raise InvalidCredential('chain document must be a list or {"chain": [...]}')
    return [DelegationCredential.from_dict(item) for item in data]


def _load_records(path: str) -> list[DelegationRecord]:
    p = Path(path)
    if not p.is_file():
        raise ProvenanceLinkBroken(f"dag file not found: {p}")
    try:
        data: Any = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ProvenanceLinkBroken(f"invalid JSON in {p}", detail=str(exc)) from exc
    if isinstance(data, dict) and "records" in data:
        data = data["records"]
    if not isinstance(data, list):
        raise ProvenanceLinkBroken('dag document must be a list or {"records": [...]}')
    records: list[DelegationRecord] = []
    for item in data:
        try:
            records.append(
                DelegationRecord(
                    record_id=str(item["record_id"]),
                    credential_id=str(item["credential_id"]),
                    subject=str(item["subject"]),
                    scope=frozenset(str(s) for s in item["scope"]),
                    parent_record_hash=(
                        None
                        if item.get("parent_record_hash") is None
                        else str(item["parent_record_hash"])
                    ),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProvenanceLinkBroken("malformed provenance record", detail=str(exc)) from exc
    return records


def _cmd_verify_dag(args: argparse.Namespace) -> int:
    try:
        records = verify_dag(_load_records(args.dag))
        cross_checked = False
        if args.chain:
            chain = _load_chain(args.chain)
            verify_chain(chain, max_depth=args.max_depth)
            cross_check_chain(records, chain)
            cross_checked = True
    except CA2AError as exc:
        print(json.dumps({"verified": False, "code": exc.code, "error": str(exc)}))
        return 1
    out = {
        "verified": True,
        "records": len(records),
        "leaf_scope": sorted(records[-1].scope),
    }
    if args.chain:
        out["cross_checked"] = cross_checked
    print(json.dumps(out))
    return 0


def _cmd_start(args: argparse.Namespace) -> int:
    """Start the live A2A JSON-RPC peer listener (``ca2a start``)."""
    try:
        import uvicorn
    except ImportError:
        print(
            "ca2a start requires the 'serve' extra: pip install 'ca2a-runtime[serve]'",
            file=sys.stderr,
        )
        return 1

    from ca2a_runtime.policy_loader import load_policy
    from ca2a_runtime.server import (
        PeerRuntime,
        create_app,
        load_enclave_private_key,
        parse_listen_addr,
    )

    try:
        cfg = Ca2aConfig.load(args.config)
        config_path = Path(args.config).resolve()
        policy = load_policy(cfg, config_dir=config_path.parent)
        key_hex = (
            args.enclave_key_hex
            or os.environ.get("CA2A_ENCLAVE_PRIVATE_KEY_HEX")
            or cfg.enclave_private_key_hex
        )
        enclave_key = load_enclave_private_key(key_hex)
        host, port = parse_listen_addr(cfg.listen_addr)
    except ConfigError as exc:
        print(f"invalid config: {exc}", file=sys.stderr)
        return 1

    if cfg.enforcement_mode != "enforcing":
        print(
            f"note: enforcement_mode={cfg.enforcement_mode!r} is accepted in config, "
            "but the live listener always fails closed on cA2A denials",
            file=sys.stderr,
        )

    runtime = PeerRuntime(config=cfg, policy=policy, enclave_private_key=enclave_key)
    app = create_app(runtime)
    print(
        f"ca2a starting: listen={cfg.listen_addr} provider={cfg.provider} "
        f"enforcement={cfg.enforcement_mode} "
        f"(live serving only; no attestation handshake / seal-to-measurement binding)"
    )
    uvicorn.run(app, host=host, port=port)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ca2a", description="Confidential agent-to-agent")
    parser.add_argument("--version", action="version", version=f"ca2a {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    vc = sub.add_parser("validate-config", help="Validate a ca2a config file")
    vc.add_argument("--config", required=True)
    vc.set_defaults(func=_cmd_validate_config)

    vch = sub.add_parser("verify-chain", help="Verify a delegation chain offline")
    vch.add_argument("--chain", required=True)
    vch.add_argument("--max-depth", type=int, default=8)
    vch.set_defaults(func=_cmd_verify_chain)

    vd = sub.add_parser("verify-dag", help="Verify a provenance DAG offline")
    vd.add_argument("--dag", required=True)
    vd.add_argument(
        "--chain",
        help="Optional delegation chain to cross-check the DAG against",
    )
    vd.add_argument("--max-depth", type=int, default=8)
    vd.set_defaults(func=_cmd_verify_dag)

    st = sub.add_parser(
        "start",
        help="Start the live A2A JSON-RPC peer listener",
    )
    st.add_argument("--config", required=True, help="Path to ca2a-config.yaml")
    st.add_argument(
        "--enclave-key-hex",
        default=None,
        help="X25519 private key as 32-byte hex (overrides config / CA2A_ENCLAVE_PRIVATE_KEY_HEX)",
    )
    st.set_defaults(func=_cmd_start)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
