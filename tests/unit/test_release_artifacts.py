"""Release integrity gates: publish only artifacts that were actually exercised."""

from __future__ import annotations

import copy
import shutil
import tomllib
from importlib.metadata import version
from pathlib import Path

import pytest
import yaml

import ca2a_runtime

# Reviewed under agentrust-io/.github#54. Codecov is the sole test-job exception.
OIDC_JOBS = {
    ("ci.yml", "test"),  # Codecov tokenless coverage upload
    ("release.yml", "publish"),  # PyPI trusted publishing
    ("docker.yml", "build-and-push"),  # Container signing and attestation
    ("scorecard.yml", "scorecard"),  # Scorecard
}


def _oidc_write(permissions: dict | str) -> bool:
    if isinstance(permissions, str):
        assert permissions in {"read-all", "write-all"}, "unsupported permission shorthand"
        return permissions == "write-all"
    assert isinstance(permissions, dict), "permissions must be a mapping or shorthand"
    return permissions.get("id-token") == "write"


def _assert_oidc_jobs(directory: Path) -> None:
    grants = set()
    paths = sorted([*directory.glob("*.yml"), *directory.glob("*.yaml")])
    assert paths, "no workflow files found"
    for path in paths:
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        defaults = workflow.get("permissions", {})
        assert not _oidc_write(defaults), f"{path.name}: workflow-wide OIDC grant"
        for name, job in workflow["jobs"].items():
            permissions = job.get("permissions", defaults)
            assert permissions != "write-all", f"{path.name}/{name}: write-all grant"
            if _oidc_write(permissions):
                grants.add((path.name, name))
    assert grants == OIDC_JOBS, f"OIDC job drift: {grants ^ OIDC_JOBS}"


def test_workflow_oidc_grants() -> None:
    _assert_oidc_jobs(Path(".github/workflows"))


@pytest.mark.parametrize(
    "case",
    [
        "validation-job",
        "sbom-job",
        "workflow-inheritance",
        "workflow-write-all",
        "allowed-job-write-all",
        "other-job-write-all",
        "new-yml",
        "new-yaml",
        "removed-allowance",
    ],
)
def test_oidc_guard_detects_permission_drift(tmp_path: Path, case: str) -> None:
    directory = tmp_path / "workflows"
    shutil.copytree(".github/workflows", directory)
    _assert_oidc_jobs(directory)
    if case in {"new-yml", "new-yaml"}:
        extension = case.removeprefix("new-")
        (directory / f"unexpected.{extension}").write_text(
            "permissions: {contents: read}\njobs:\n"
            "  validation:\n    permissions: {id-token: write}\n",
            encoding="utf-8",
        )
    else:
        filename = "sbom.yml" if case == "sbom-job" else "release-validation.yml"
        if case in {"allowed-job-write-all", "removed-allowance"}:
            filename = "ci.yml"
        path = directory / filename
        workflow = yaml.safe_load(path.read_text(encoding="utf-8"))
        job = workflow["jobs"]["sbom" if case == "sbom-job" else "test"]
        if case == "workflow-inheritance":
            workflow["permissions"]["id-token"] = "write"
            job.pop("permissions", None)
        elif case == "workflow-write-all":
            workflow["permissions"] = "write-all"
        elif case in {"allowed-job-write-all", "other-job-write-all"}:
            job["permissions"] = "write-all"
        elif case == "removed-allowance":
            job["permissions"].pop("id-token")
        else:
            job.setdefault("permissions", {})["id-token"] = "write"
        path.write_text(yaml.safe_dump(workflow), encoding="utf-8")
    with pytest.raises(AssertionError):
        _assert_oidc_jobs(directory)


def test_oidc_guard_accepts_read_only_inheritance(tmp_path: Path) -> None:
    directory = tmp_path / "workflows"
    shutil.copytree(".github/workflows", directory)
    (directory / "read-only.yaml").write_text(
        "permissions: read-all\njobs:\n  validation:\n    runs-on: ubuntu-latest\n",
        encoding="utf-8",
    )
    _assert_oidc_jobs(directory)


def _release_workflow() -> dict:
    return yaml.safe_load(Path(".github/workflows/release.yml").read_text(encoding="utf-8"))


def test_runtime_version_comes_from_installed_package_metadata() -> None:
    assert ca2a_runtime.__version__ == version("ca2a-runtime")


def test_public_release_metadata_is_stable() -> None:
    project = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert project["version"] == "0.4.0"
    assert "Development Status :: 4 - Beta" in project["classifiers"]
    assert not any("Alpha" in classifier for classifier in project["classifiers"])


def test_current_adoption_docs_do_not_require_prerelease_install() -> None:
    for filename in ("README.md", "ADOPTERS.md", "LIMITATIONS.md", "docs/quickstart.md"):
        text = Path(filename).read_text(encoding="utf-8").lower()
        assert "alpha" not in text
        assert "pre-release" not in text
        assert "--pre" not in text


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


def test_release_reuses_complete_ci_validation() -> None:
    jobs = _release_workflow()["jobs"]
    assert jobs["validate"]["uses"] == "./.github/workflows/release-validation.yml"
    ci = yaml.safe_load(
        Path(".github/workflows/release-validation.yml").read_text(encoding="utf-8")
    )
    assert "workflow_call" in ci[True]
    matrix = ci["jobs"]["test"]["strategy"]["matrix"]
    assert matrix["python-version"] == ["3.11", "3.12", "3.13"]
    assert matrix["os"] == ["ubuntu-latest", "windows-latest"]
    assert any(
        "pytest tests/unit/ tests/conformance/" in step.get("run", "")
        for step in ci["jobs"]["test"]["steps"]
    )
    assert jobs["validate"]["permissions"] == {"contents": "read"}
    assert "environment" not in jobs["validate"]


@pytest.mark.parametrize("validation_result", ["success", "failure", "cancelled", "skipped"])
def test_release_dependency_graph_blocks_unsuccessful_validation(validation_result: str) -> None:
    jobs = _release_workflow()["jobs"]
    results = {"validate": validation_result}
    for name in ("build", "publish", "governance-release"):
        job = jobs[name]
        # Jobs without an explicit status function retain GitHub's implicit
        # success() guard. A future custom guard needs its own execution model.
        assert "if" not in job
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        assert all(dependency in results for dependency in needs)
        results[name] = (
            "success"
            if all(results[dependency] == "success" for dependency in needs)
            else "skipped"
        )
    expected = "success" if validation_result == "success" else "skipped"
    assert results["build"] == expected
    assert results["publish"] == expected
    assert results["governance-release"] == expected
    assert jobs["build"]["needs"] == "validate"
    assert jobs["governance-release"]["needs"] == "publish"


def test_release_validation_matches_ci() -> None:
    ci = yaml.safe_load(Path(".github/workflows/ci.yml").read_text(encoding="utf-8"))
    release_ci = yaml.safe_load(
        Path(".github/workflows/release-validation.yml").read_text(encoding="utf-8")
    )
    expected = copy.deepcopy(ci["jobs"])
    expected["test"]["permissions"].pop("id-token")
    steps = expected["test"]["steps"]
    coverage = [step for step in steps if step.get("name") == "Upload coverage report"]
    assert len(coverage) == 1
    assert coverage[0]["if"] == "github.event_name != 'release'"
    steps.remove(coverage[0])
    assert release_ci["jobs"] == expected
    assert release_ci["permissions"] == {"contents": "read"}
    assert set(release_ci[True]) == {"workflow_call"}
    for job in release_ci["jobs"].values():
        assert job.get("permissions", {}).get("id-token", "none") == "none"
        assert not any("codecov/" in step.get("uses", "") for step in job["steps"])


def test_only_publish_can_mint_release_oidc() -> None:
    workflow = _release_workflow()
    assert workflow["permissions"] == {"contents": "read"}
    assert [
        name
        for name, job in workflow["jobs"].items()
        if job.get("permissions", {}).get("id-token") == "write"
    ] == ["publish"]
