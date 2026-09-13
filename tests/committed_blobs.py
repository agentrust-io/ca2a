"""Read committed blobs out of git rather than the working tree.

Tests that verify committed artifacts (delegation chains, provenance DAGs, the
ACTION fixture bundles) must read what is *in the repository*, not what a demo
or a generator just wrote beside them. Otherwise a run that regenerates the
artifact makes its own test pass, and a change to a hashed body that forgets to
regenerate the committed copy still goes green. Reading the committed blob means
a stale artifact fails instead.

Both ``tests/unit/test_committed_examples_verify.py`` and
``tests/conformance/test_action_fixture_bundles.py`` import from here so the one
helper backs both suites.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

# tests/committed_blobs.py -> parents[1] is the repository root.
REPO_ROOT = Path(__file__).resolve().parents[1]


def committed(path: str) -> str | None:
    """The blob at HEAD for ``path``, or None if git cannot tell us."""
    try:
        out = subprocess.run(  # noqa: S603
            ["git", "show", f"HEAD:{path}"],  # noqa: S607
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
            check=False,
        )
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None
