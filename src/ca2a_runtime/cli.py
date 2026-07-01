"""ca2a command-line interface."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ca2a_runtime import __version__
from ca2a_runtime.config import Ca2aConfig
from ca2a_runtime.errors import CA2AError
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

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    result: int = args.func(args)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
