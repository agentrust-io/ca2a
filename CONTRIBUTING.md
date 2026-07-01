# Contributing to cA2A

Thank you for contributing. This document covers everything you need to get started.

## Before you start

cA2A is a confidential delegation profile on top of A2A. Changes to the delegation chain, sealed channel, attestation path, or TRACE record generation require extra care: these are security-critical components. When in doubt, open an issue first.

## Developer certificate of origin

All commits must include a `Signed-off-by` line. This is a lightweight way to certify you wrote the code or have the right to contribute it. No CLA required.

```
git commit -s -m "feat: your change"
```

The sign-off certifies the [Developer Certificate of Origin v1.1](https://developercertificate.org/).

## Development setup

Requires Python 3.11+.

```bash
git clone https://github.com/agentrust-io/ca2a
cd ca2a
pip install -e ".[dev]"
```

## Running checks locally

```bash
ruff check src/ tests/                      # lint
mypy src/ca2a_runtime/ src/ca2a_verify/     # type check
bandit -r src/ -c pyproject.toml            # security scan
pytest tests/unit/ -v                        # unit tests
```

All four must pass before a PR is mergeable.

## Commit format

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add sealed peer channel handshake
fix: reject child scope that exceeds parent grant
docs: clarify delegation-link fields in the TRACE profile
test: add coverage for cross-chain replay rejection
refactor: extract scope intersection helper
```

Keep commits small and focused. One logical change per commit. Do not bundle unrelated fixes.

## Pull request process

1. Branch from `main`: `git checkout -b feat/your-change`
2. Write tests for new behavior: the test suite must pass
3. Run all four checks locally (see above)
4. Open a PR against `main` with the template filled in
5. At least one maintainer must approve before merge
6. Squash if the commit history is noisy; preserve meaningful commits

## Security-critical components

Changes to these paths require two maintainer approvals and a comment explaining the security impact:

- `src/ca2a_runtime/delegation/`: delegation chain verification and scope attenuation
- `src/ca2a_runtime/channel/`: sealed peer channel
- `src/ca2a_runtime/tee/`: TEE provider integration
- `src/ca2a_verify/`: offline chain and DAG verification

## Reporting security vulnerabilities

Do **not** open a public issue. Use [GitHub Security Advisories](https://github.com/agentrust-io/ca2a/security/advisories/new) for private disclosure. See [SECURITY.md](SECURITY.md).

## Code conventions

- Python 3.11+ syntax throughout (`X | Y`, `match`, etc.)
- `ruff` enforces style; do not add `# noqa` without a comment explaining why
- `mypy --strict` on `src/`; new public functions need type annotations
- No comments that describe *what* the code does: only *why* when non-obvious
- Tests live in `tests/unit/` and follow the existing `test_<module>.py` naming

## Questions

Open a [GitHub Discussion](https://github.com/agentrust-io/ca2a/discussions) for design questions or proposals before writing code.
