"""Release integrity gates: publish only artifacts that were actually exercised."""

from __future__ import annotations

from importlib.metadata import version
from pathlib import Path

import yaml

import ca2a_runtime


def _release_workflow() -> dict:
    return yaml.safe_load(Path(".github/workflows/release.yml").read_text(encoding="utf-8"))


def test_runtime_version_comes_from_installed_package_metadata() -> None:
    assert ca2a_runtime.__version__ == version("ca2a-runtime")


def test_release_has_no_manual_publish_trigger() -> None:
    workflow = _release_workflow()
    triggers = workflow[True]  # PyYAML 1.1 parses the YAML key `on` as True.
    assert set(triggers) == {"release"}
    assert triggers["release"]["types"] == ["published"]


def test_publish_waits_for_both_artifact_install_smoke_tests() -> None:
    workflow = _release_workflow()
    build_steps = workflow["jobs"]["build"]["steps"]
    names = {step.get("name") for step in build_steps}
    assert "Verify release tag matches package version" in names
    assert "Check distribution metadata" in names
    assert "Install and smoke-test wheel" in names
    assert "Install and smoke-test source distribution" in names
    assert workflow["jobs"]["publish"]["needs"] == "build"
