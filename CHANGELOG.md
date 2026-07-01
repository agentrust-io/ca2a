# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Initial cA2A profile draft: attested, attenuated agent-to-agent delegation on top of A2A
- `ca2a-verify`: offline delegation-chain verification skeleton (scope attenuation, signature, depth, replay checks)
- `ca2a-runtime`: config, error registry, and delegation credential model
- Repository scaffold: governance, CI/CD, docs framework, and packaging at parity with the agentrust-io house standard

### Not yet implemented

- Runtime peer-delegation enforcement (Tier 2, see ROADMAP.md)
- Sealed peer channel (Tier 2)
- Real hardware attestation backends (Tier 3, shared critical path with cmcp)

[Unreleased]: https://github.com/agentrust-io/ca2a/commits/main
