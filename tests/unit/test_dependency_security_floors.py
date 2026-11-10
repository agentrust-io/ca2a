"""Keep dependency floors above versions with known release-blocking advisories."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path


def _project() -> dict:
    with Path("pyproject.toml").open("rb") as stream:
        return tomllib.load(stream)["project"]


def _normalize(name: str) -> str:
    # PEP 503 normalization: pip-compile is case- and separator-insensitive
    # when matching a requirement name to its locked entry.
    return re.sub(r"[-_.]+", "-", name).lower()


def _direct_dev_requirement_names() -> set[str]:
    """Every package dev.in asks for directly, with extras/markers/specifiers stripped."""
    names = set()
    for line in Path("requirements/dev.in").read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)", line)
        assert match, f"could not parse a requirement name from dev.in line: {line!r}"
        names.add(_normalize(match.group(1)))
    return names


def _locked_package_names(lock_text: str) -> set[str]:
    """Every top-level package name that dev.txt actually pins, extras stripped."""
    names = set()
    for line in lock_text.splitlines():
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==", line)
        if match:
            names.add(_normalize(match.group(1)))
    return names


def test_dev_lock_contains_every_direct_dev_in_requirement() -> None:
    """A regenerated dev.txt must still lock every package dev.in asks for directly.

    This is the regression class behind the setuptools security floor silently
    disappearing from the lock during a Dependabot group update (dev.in kept
    "setuptools>=83.0.0", but the regenerated dev.txt dropped the package
    entirely): `pip install --require-hashes -r requirements/dev.txt` succeeded
    anyway, so nothing caught it short of diffing the lock by hand. Catching a
    dropped *direct* requirement here is cheap and general; it would have
    caught this incident regardless of which package was dropped.
    """
    direct = _direct_dev_requirement_names()
    locked = _locked_package_names(Path("requirements/dev.txt").read_text(encoding="utf-8"))
    missing = sorted(direct - locked)
    assert not missing, (
        f"requirements/dev.txt is missing a lock entry for direct dev.in "
        f"requirement(s) {missing}; regenerate with the command in "
        f"requirements/dev.in's header comment and verify each dropped "
        f"package reappears with hashes before committing."
    )


def test_dev_lock_setuptools_floor_matches_pysec_2026_3447() -> None:
    """setuptools must be locked at >=83.0.0, the fix for PYSEC-2026-3447.

    dev.in pins this floor specifically because CI installs only from the
    hash-pinned lock (`pip install --require-hashes -r requirements/dev.txt`),
    never from dev.in directly, so an unenforced floor in dev.in alone does
    nothing to the installed environment or to pip-audit's findings.
    """
    lock = Path("requirements/dev.txt").read_text(encoding="utf-8")
    pins = [
        line.split("==", 1)[1].split()[0]
        for line in lock.splitlines()
        if line.startswith("setuptools==")
    ]
    assert len(pins) == 1, f"expected exactly one setuptools pin in dev.txt, got {pins}"
    floor = tuple(int(part) for part in pins[0].split("."))
    assert floor >= (83, 0, 0), floor


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
        assert (
            ".agt-venv/bin/pip install --require-hashes --no-deps -r requirements/agt.txt"
        ) in contents
        # AGT is never installed into the environment holding the package.
        assert 'pip install -e ".[dev]" "agent-governance-toolkit' not in contents
        assert 'pip install -e "." "agent-governance-toolkit' not in contents
        assert "agent-governance-toolkit" not in contents.replace("requirements/agt.txt", "")


def test_agt_lock_carries_no_cryptography_below_the_floor() -> None:
    """The scanner lock is compiled with an override, so it must land at or above 50.

    A lock that names a vulnerable cryptography is one Dependabot will flag
    forever, even when install order means it never runs. Compiling the override
    in keeps the vulnerable version out of the file entirely.
    """
    override = Path("requirements/agt.txt").read_text(encoding="utf-8")
    pins = [
        line.split("==", 1)[1].split()[0]
        for line in override.splitlines()
        if line.startswith("cryptography==")
    ]
    assert len(pins) == 1, f"expected exactly one cryptography pin, got {pins}"
    floor = tuple(int(part) for part in pins[0].split("."))
    assert floor >= (50, 0), floor
