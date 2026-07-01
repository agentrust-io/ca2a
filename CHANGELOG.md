# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial cA2A profile draft: attested, attenuated agent-to-agent delegation on top of A2A
- `ca2a-verify`: offline delegation-chain verification skeleton (scope attenuation, signature, depth, replay checks)
- `ca2a-runtime`: config, error registry, and delegation credential model
- `ca2a_runtime.provenance`: linked delegation-record DAG with tamper and reparent detection, bound to authority via `cross_check_chain`
- `experiments/`: reproducible claim suite C1-C6. C1 (attenuation), C2 (cross-chain replay), and C5 (provenance DAG) are fully reproducible; C3, C4, C6 SKIP until their Tier 2/3 dependency lands. Each claim has a CI test.
- Repository scaffold: governance, CI/CD, docs framework, and packaging at parity with the agentrust-io house standard

### Not yet implemented

- Runtime peer-delegation enforcement (Tier 2, see ROADMAP.md)
- Sealed peer channel (Tier 2)
- Real hardware attestation backends (Tier 3, shared critical path with cmcp)

[Unreleased]: https://github.com/agentrust-io/ca2a/commits/main
