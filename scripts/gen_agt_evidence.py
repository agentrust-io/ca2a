#!/usr/bin/env python3
"""Generate agt-evidence.json describing cA2A's governance state.

Run from the repo root:
    python scripts/gen_agt_evidence.py [output-path]

The output path defaults to agt-evidence.json in the current directory.
Policy file paths in the evidence are relative to the output file so that
`agt verify --evidence agt-evidence.json` can locate them.
"""

from __future__ import annotations

import importlib.metadata
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


def _pkg_version(package: str) -> str:
    try:
        return importlib.metadata.version(package)
    except importlib.metadata.PackageNotFoundError:
        return "not-installed"


def generate_evidence() -> dict:
    """Return the evidence dict describing this cA2A deployment's governance state.

    All policy file paths are relative to the evidence file location (repo root)
    so that ``agt verify --evidence agt-evidence.json`` resolves them correctly
    in any working directory.
    """
    return {
        "schema": "agt-runtime-evidence/v1",
        "generated_at": "",  # populated by main()
        "toolkit_version": _pkg_version("agent-governance-toolkit-core"),
        "deployment": {
            # Relative to this evidence file (repo root).
            # governance/ca2a-enforcement.yaml has deny_by_default: true.
            "policy_files_loaded": [
                "governance/ca2a-enforcement.yaml",
            ],
            "registered_tools": [],
            "audit_sink": {
                "enabled": True,
                "target": "src/ca2a_runtime/delegation/credential.py",
                "type": "linked-trace-dag",
            },
            "identity": {
                "enabled": True,
                "type": "delegation-chain",
                "backend": "agent_manifest",
            },
            "packages": [
                {
                    "package": "ca2a-runtime",
                    "version": _pkg_version("ca2a-runtime"),
                },
                {
                    "package": "agent-governance-toolkit-core",
                    "version": _pkg_version("agent-governance-toolkit-core"),
                },
                {
                    "package": "agentrust-trace",
                    "version": _pkg_version("agentrust-trace"),
                },
            ],
        },
    }


def main(out_path: str = "agt-evidence.json") -> None:
    evidence = generate_evidence()
    evidence["generated_at"] = datetime.now(timezone.utc).isoformat()
    path = Path(out_path)
    path.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    print(f"Generated {path} ({path.stat().st_size} bytes)")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "agt-evidence.json")
