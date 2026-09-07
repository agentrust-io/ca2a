"""Keep dependency floors above versions with known release-blocking advisories."""

from __future__ import annotations

import tomllib
from pathlib import Path


def _project() -> dict:
    with Path("pyproject.toml").open("rb") as stream:
        return tomllib.load(stream)["project"]


def test_runtime_cryptography_floor_includes_2026_security_fixes() -> None:
    assert "cryptography>=50.0" in _project()["dependencies"]


def test_agent_manifest_floor_includes_v02_cose_verification() -> None:
    assert "agent-manifest>=0.11.1" in _project()["dependencies"]


def test_a2a_sdk_extra_cannot_resolve_vulnerable_aiohttp() -> None:
    extras = _project()["optional-dependencies"]
    assert "aiohttp>=3.14.3" in extras["a2a-sdk"]
    assert "aiohttp>=3.14.3" in extras["dev"]


def test_docs_floor_excludes_vulnerable_pymdown_extensions() -> None:
    # Compare parsed versions rather than the literal pin, so that raising the
    # floor (which is always safer) does not fail this test. 11.0.1 is the first
    # release without the advisory; anything at or above it is acceptable.
    requirements = Path("requirements-docs.txt").read_text(encoding="utf-8").splitlines()
    pins = [line for line in requirements if line.startswith("pymdown-extensions>=")]
    assert len(pins) == 1, f"expected exactly one pymdown-extensions floor, got {pins}"
    floor = tuple(int(part) for part in pins[0].split(">=", 1)[1].strip().split("."))
    assert floor >= (11, 0, 1)


def test_governance_tooling_cannot_downgrade_runtime_dependencies() -> None:
    """AGT stays in its own venv, and cryptography is lifted past its ceiling there.

    AGT 4.1 declares cryptography>=46.0.7,<49.0 while this runtime requires
    >=50.0, so the two genuinely cannot be resolved together. The invariant is
    that the scanner never shares an environment with the package under test,
    and that the override still happens inside the isolated venv.

    Asserted against the lock files rather than the literal install lines, so
    that pinning or re-pinning does not break a test about isolation.
    """
    for workflow in ("ci.yml", "release.yml"):
        contents = Path(".github/workflows", workflow).read_text(encoding="utf-8")
        assert "python -m venv .agt-venv" in contents
        assert ".agt-venv/bin/pip install --require-hashes -r requirements/agt.txt" in contents
        assert (
            ".agt-venv/bin/pip install --require-hashes --no-deps -r requirements/agt-override.txt"
        ) in contents
        # AGT is never installed into the environment holding the package.
        assert 'pip install -e ".[dev]" "agent-governance-toolkit' not in contents
        assert 'pip install -e "." "agent-governance-toolkit' not in contents
        assert "agent-governance-toolkit" not in contents.replace(
            "requirements/agt.txt", ""
        ).replace("requirements/agt-override.txt", "")


def test_agt_override_lifts_cryptography_past_the_toolkit_ceiling() -> None:
    """The override lock must actually carry a cryptography at or above the floor."""
    override = Path("requirements/agt-override.txt").read_text(encoding="utf-8")
    pins = [
        line.split("==", 1)[1].split()[0]
        for line in override.splitlines()
        if line.startswith("cryptography==")
    ]
    assert len(pins) == 1, f"expected exactly one cryptography pin, got {pins}"
    floor = tuple(int(part) for part in pins[0].split("."))
    assert floor >= (50, 0), floor
