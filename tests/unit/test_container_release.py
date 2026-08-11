"""Static guarantees for the releasable, least-privilege runtime container."""

from __future__ import annotations

from pathlib import Path

import yaml


def test_runtime_image_is_multistage_non_root_and_offline_installed() -> None:
    dockerfile = Path("Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("FROM python:3.11.15-slim-bookworm") == 2
    assert "AS builder" in dockerfile
    assert "pip wheel --wheel-dir /wheels ." in dockerfile
    assert "pip install --no-index --find-links=/wheels ca2a-runtime" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert 'ENTRYPOINT ["ca2a"]' in dockerfile


def test_container_context_excludes_development_and_vcs_state() -> None:
    ignored = set(Path(".dockerignore").read_text(encoding="utf-8").splitlines())
    assert {".git", ".github", ".venv", "tests", "docs", "examples", "dist"} <= ignored


def test_pull_requests_build_without_registry_or_signing_privileges() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/docker.yml").read_text(encoding="utf-8"))
    triggers = workflow[True]
    job = workflow["jobs"]["build-pr"]
    steps = job["steps"]
    build = next(step for step in steps if step.get("name") == "Build image without publishing")

    assert "pull_request" in triggers
    assert job["permissions"] == {"contents": "read"}
    assert build["with"]["push"] is False
    assert "github.sha" in build["with"]["tags"]
    assert all("login-action" not in step.get("uses", "") for step in steps)
    assert all("cosign" not in step.get("uses", "") for step in steps)


def test_third_party_container_actions_are_pinned() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/docker.yml").read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            uses = step.get("uses")
            if uses:
                ref = uses.rsplit("@", 1)[1].split()[0]
                assert len(ref) == 40
                assert all(char in "0123456789abcdef" for char in ref)


def test_release_job_retains_version_latest_signing_and_attestation() -> None:
    workflow = yaml.safe_load(Path(".github/workflows/docker.yml").read_text(encoding="utf-8"))
    job = workflow["jobs"]["build-and-push"]
    steps = job["steps"]
    build = next(step for step in steps if step.get("name") == "Build and push")
    names = {step.get("name") for step in steps}

    assert job["permissions"]["packages"] == "write"
    assert job["permissions"]["id-token"] == "write"
    assert build["with"]["push"] is True
    assert "steps.tag.outputs.tag" in build["with"]["tags"]
    assert "ca2a-runtime:latest" in build["with"]["tags"]
    assert {"Sign the image (keyless, by digest)", "Attest build provenance (SLSA)"} <= names
