"""ca2a command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ca2a_runtime import __version__
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.delegation import (
    DelegationCredential,
    RevocationSnapshot,
    RevocationStatus,
    verify_chain,
)
from ca2a_runtime.errors import CA2AError, ConfigError, InvalidCredential, ProvenanceLinkBroken
from ca2a_runtime.provenance import (
    CALLER_NOT_OFFERED,
    DelegationRecord,
    cross_check_chain,
    verify_dag,
)
from ca2a_verify import (
    cross_check_trace_dag,
    load_revocation_snapshot,
    verify_chain_file,
    verify_trace_dag,
)


def _cmd_validate_config(args: argparse.Namespace) -> int:
    try:
        cfg = Ca2aConfig.load(args.config)
    except CA2AError as exc:
        print(f"invalid config: {exc}", file=sys.stderr)
        return 1
    print(f"ok: provider={cfg.provider} enforcement={cfg.enforcement_mode}")
    return 0


def _revocation_fields(status: RevocationStatus) -> dict[str, Any]:
    # Printed always, including "not_checked". A chain that verified offline
    # with no revocation data may still have been revoked, and output that only
    # mentioned revocation when it was checked would let a reader miss that.
    out: dict[str, Any] = {"revocation": status.state}
    if status.checked:
        out["revocation_as_of"] = status.as_of
    return out


def _load_revocations(args: argparse.Namespace) -> RevocationSnapshot | None:
    return None if args.revocations is None else load_revocation_snapshot(args.revocations)


def _cmd_verify_chain(args: argparse.Namespace) -> int:
    try:
        result = verify_chain_file(
            Path(args.chain),
            trusted_root_issuers=args.trusted_root_issuer,
            max_depth=args.max_depth,
            at_time=args.at_time,
            revocations=_load_revocations(args),
            max_revocation_staleness=args.max_revocation_staleness,
        )
    except CA2AError as exc:
        print(json.dumps({"verified": False, "code": exc.code, "error": str(exc)}))
        return 1
    out: dict[str, Any] = {"verified": True, "hops": result.hops, "leaf_scope": result.leaf_scope}
    out.update(
        _revocation_fields(RevocationStatus(result.revocation_checked, result.revocation_as_of))
    )
    print(json.dumps(out))
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
                    decision=str(item.get("decision", "allow")),
                    requested_capability=(
                        None
                        if item.get("requested_capability") is None
                        else str(item["requested_capability"])
                    ),
                    effective_scope=(
                        None
                        if item.get("effective_scope") is None
                        else frozenset(str(s) for s in item["effective_scope"])
                    ),
                    denial_reason=(
                        None if item.get("denial_reason") is None else str(item["denial_reason"])
                    ),
                    # A record written before this field existed hashes as
                    # "not_offered", which is what its emitter could honestly have
                    # claimed: it never appraised a caller.
                    caller_attestation=str(item.get("caller_attestation", CALLER_NOT_OFFERED)),
                )
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ProvenanceLinkBroken("malformed provenance record", detail=str(exc)) from exc
    return records


def _cmd_verify_dag(args: argparse.Namespace) -> int:
    try:
        records = verify_dag(_load_records(args.dag))
        cross_checked = False
        revocation: RevocationStatus | None = None
        if args.chain:
            chain = _load_chain(args.chain)
            revocation = verify_chain(
                chain,
                max_depth=args.max_depth,
                trusted_root_issuers=args.trusted_root_issuer,
                at_time=args.at_time,
                revocations=_load_revocations(args),
                max_revocation_staleness=args.max_revocation_staleness,
            )
            cross_check_chain(records, chain)
            cross_checked = True
    except CA2AError as exc:
        print(json.dumps({"verified": False, "code": exc.code, "error": str(exc)}))
        return 1
    leaf = records[-1]
    out: dict[str, Any] = {
        "verified": False,
        "verification": "structural_only",
        "structural_verified": True,
        "code": "UNAUTHENTICATED_LINEAGE",
        "records": len(records),
        "leaf_scope": sorted(leaf.scope),
        # Printed always, including "not_offered". A verifier that only mentioned
        # attestation when there was some would let a reader skim past its absence.
        "leaf_caller_attestation": leaf.caller_attestation,
    }
    if leaf.denied:
        # The DAG verifies AND it documents a refusal. Both are true, and a
        # verifier that only printed "verified" would bury the interesting part.
        out["outcome"] = "denied"
        out["requested_capability"] = leaf.requested_capability
        out["effective_scope"] = sorted(leaf.effective_scope or frozenset())
        out["denial_reason"] = leaf.denial_reason
    if args.chain:
        out["cross_checked"] = cross_checked
    if revocation is not None:
        out.update(_revocation_fields(revocation))
    print(json.dumps(out))
    return 0 if args.structural_only else 1


def _cmd_verify_lineage(args: argparse.Namespace) -> int:
    """Authenticate the submitted signed path against an independently trusted chain."""
    try:
        chain = _load_chain(args.chain)
        revocation = verify_chain(
            chain,
            max_depth=args.max_depth,
            trusted_root_issuers=args.trusted_root_issuer,
            at_time=args.at_time,
            revocations=_load_revocations(args),
            max_revocation_staleness=args.max_revocation_staleness,
        )
        records = json.loads(Path(args.dag).read_text(encoding="utf-8"))
        if isinstance(records, dict):
            records = records.get("records")
        if not isinstance(records, list) or not all(isinstance(r, dict) for r in records):
            raise ProvenanceLinkBroken("signed DAG must be a list of record objects")
        # Trust delegates only after their chain verifies against the caller's root.
        keys = [Ed25519PublicKey.from_public_bytes(bytes.fromhex(c.subject)) for c in chain]
        result = verify_trace_dag(records, trusted_keys=keys, max_age_seconds=args.max_age_seconds)
        cross_check_trace_dag(records, chain)
    except CA2AError as exc:
        print(json.dumps({"verified": False, "code": exc.code, "error": str(exc)}))
        return 1
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        print(json.dumps({"verified": False, "code": "MALFORMED_LINEAGE", "error": str(exc)}))
        return 1
    out = {
        "verified": True,
        "verification": "authenticated_lineage",
        "records": result.hops,
        "cross_checked": True,
        **_revocation_fields(revocation),
    }
    print(json.dumps(out))
    return 0


def _cmd_start(args: argparse.Namespace) -> int:
    """Serve the reference HTTP transport from a config file (``ca2a start``)."""
    from ca2a_runtime.bootstrap import build_peer_node
    from ca2a_runtime.transport.server import serve

    try:
        cfg = Ca2aConfig.load(args.config)
        node = build_peer_node(cfg, config_dir=Path(args.config).resolve().parent)
        host, port = cfg.listen_host_port()
    except ConfigError as exc:
        # The detail is the part that says what to change, so it goes with the message.
        suffix = f" ({exc.detail})" if exc.detail else ""
        print(f"invalid config: {exc}{suffix}", file=sys.stderr)
        return 1

    if cfg.enforcement_mode != "enforcing":
        print(
            f"note: enforcement_mode={cfg.enforcement_mode!r} is accepted in config, "
            "but the peer path always fails closed on cA2A denials",
            file=sys.stderr,
        )

    if cfg.provider == "software-only":
        # The callee cannot claim an assurance level; the caller appraises the
        # offer. Say what that appraisal will be so it is not a surprise.
        print(
            "note: software-only provider, callers appraise this channel key as "
            'assurance="none" and the seal carries no hardware guarantee',
            file=sys.stderr,
        )

    if node.caller_verifier is None:
        # "Demands nothing" still refuses a caller whose offer is present and does
        # not appraise, and with no verifier every hardware offer is exactly that.
        # Say so, or the first hardware-attested caller looks like a bug.
        print(
            f"note: require_caller_attestation={node.require_caller_attestation} with no "
            "caller_verifier; software offers appraise, hardware offers are refused as "
            "unappraisable",
            file=sys.stderr,
        )

    try:
        server = serve(node, host=host, port=port)
    except OSError as exc:
        print(f"cannot bind {host}:{port}: {exc}", file=sys.stderr)
        return 1

    # Flushed, because an operator redirecting stdout to a log needs to see the
    # peer come up rather than wait on a full buffer.
    print(
        f"ca2a listening on {host}:{port} (provider={node.provider.platform}, "
        f"require_caller_attestation={node.require_caller_attestation})",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("ca2a stopped", file=sys.stderr)
    finally:
        server.server_close()
    return 0


def _add_revocation_args(p: argparse.ArgumentParser, note: str = "") -> None:
    p.add_argument(
        "--revocations",
        default=None,
        help="Revocation snapshot JSON to check every hop against" + note,
    )
    p.add_argument(
        "--max-revocation-staleness",
        type=int,
        default=None,
        help="Fail closed unless a revocation snapshot no older than this many "
        "seconds (relative to the evaluation time) is supplied" + note,
    )


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
    vch.add_argument(
        "--trusted-root-issuer",
        action="append",
        required=True,
        help="Trusted root issuer public key in lowercase hex (repeatable)",
    )
    vch.add_argument(
        "--at-time",
        type=int,
        default=None,
        help="Unix time validity windows are evaluated at (default: now)",
    )
    _add_revocation_args(vch)
    vch.set_defaults(func=_cmd_verify_chain)

    vd = sub.add_parser("verify-dag", help="Check unsigned DAG structure (not authenticity)")
    vd.add_argument(
        "--structural-only",
        action="store_true",
        help="Exit 0 on valid structure; verified remains false",
    )
    vd.add_argument("--dag", required=True)
    vd.add_argument(
        "--chain",
        help="Optional delegation chain to cross-check the DAG against",
    )
    vd.add_argument("--max-depth", type=int, default=8)
    vd.add_argument(
        "--trusted-root-issuer",
        action="append",
        default=[],
        help="Trusted root issuer public key in lowercase hex (required with --chain; repeatable)",
    )
    vd.add_argument(
        "--at-time",
        type=int,
        default=None,
        help="Unix time validity windows are evaluated at (default: now)",
    )
    _add_revocation_args(vd, note=" (applies with --chain)")
    vd.set_defaults(func=_cmd_verify_dag)

    vl = sub.add_parser("verify-lineage", help="Authenticate a signed TRACE path and its chain")
    vl.add_argument("--dag", required=True, help="Signed TRACE record list or records wrapper")
    vl.add_argument("--chain", required=True)
    vl.add_argument("--trusted-root-issuer", action="append", required=True)
    vl.add_argument("--max-depth", type=int, default=8)
    vl.add_argument(
        "--at-time",
        type=int,
        default=None,
        help="Credential validity/revocation evaluation time; not the TRACE clock",
    )
    vl.add_argument(
        "--max-age-seconds",
        type=int,
        default=None,
        help="TRACE record age bound against the current clock (default: no age bound)",
    )
    _add_revocation_args(vl)
    vl.set_defaults(func=_cmd_verify_lineage)

    st = sub.add_parser(
        "start",
        help="Serve the reference HTTP peer transport from a config file",
    )
    st.add_argument("--config", required=True, help="Path to ca2a-config.yaml")
    st.set_defaults(func=_cmd_start)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "verify-dag" and args.chain and not args.trusted_root_issuer:
        parser.error("verify-dag with --chain requires --trusted-root-issuer")
    if (
        args.command == "verify-dag"
        and not args.chain
        and (args.revocations is not None or args.max_revocation_staleness is not None)
    ):
        # Revocation applies to credentials, and without --chain none are checked.
        # Accepting the flag silently would look like a check that never ran.
        parser.error("verify-dag revocation options require --chain")
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
