# Configuration

The cA2A runtime reads a YAML config. Offline commands validate it with `ca2a validate-config`. `ca2a start` consumes the same file to build a [`PeerNode`](https://ca2a.agentrust-io.com/docs/spec/component-model/index.md) and serve it over the reference HTTP transport.

## Reference

```
attestation:
  provider: auto            # auto | tpm | sev-snp | tdx | opaque | software-only
  enforcement_mode: enforcing  # enforcing | advisory | silent

max_delegation_depth: 8     # reject chains deeper than this
listen_addr: "127.0.0.1:8443"
trusted_root_issuers:
  - "<root Ed25519 public key as raw hex>"

local_policy: ["read", "write"]   # allow-set for scope intersection (or use Cedar below)
# policy_bundle_path: policy.cedar

# Optional: verify and bind this peer's Agent Manifest identity at startup.
# agent_manifest:
#   path: manifest.cose             # v0.2 COSE envelope, or signed v0.1 JSON
#   trust_anchor_path: manifest-key.json
#   authenticated_subject: spiffe://example.test/agent/ca2a
```

## Fields

| Field                                  | Default          | Description                                                                                                                                                                                                       |
| -------------------------------------- | ---------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `attestation.provider`                 | `auto`           | TEE provider for peer attestation. `auto` selects a detected hardware provider and fails if there is none; it never falls back to `software-only`, which has to be named explicitly. `opaque` is not implemented. |
| `attestation.enforcement_mode`         | `enforcing`      | Intended mode. The peer path always fails closed on cA2A denials today; advisory and silent are accepted in config but not applied on the wire.                                                                   |
| `max_delegation_depth`                 | `8`              | Chains deeper than this are rejected with `DELEGATION_DEPTH_EXCEEDED`.                                                                                                                                            |
| `listen_addr`                          | `127.0.0.1:8443` | Address `ca2a start` binds. The host is never defaulted, so serving on every interface has to be written out.                                                                                                     |
| `trusted_root_issuers`                 | none             | Ed25519 public keys allowed to originate delegation chains. At least one is required by `ca2a start`; an internally valid chain from any other root is denied before policy evaluation.                           |
| `local_policy`                         | none             | Capability allow set for `LocalPolicy`. Required for `ca2a start` unless `policy_bundle_path` is set.                                                                                                             |
| `policy_bundle_path`                   | none             | Path to a Cedar policy file, resolved relative to the config file. When set, used instead of `local_policy`.                                                                                                      |
| `agent_manifest.path`                  | none             | Optional signed Agent Manifest. Content is sniffed: v0.1 JSON and v0.2 COSE are accepted; a bare v0.2 JSON payload is rejected because its COSE envelope is the signature.                                        |
| `agent_manifest.trust_anchor_path`     | none             | JSON trust anchor containing one `public_key_base64url` or a `keys` array. Relative paths resolve against the config file.                                                                                        |
| `agent_manifest.authenticated_subject` | none             | SPIFFE URI independently configured for this peer. Startup fails unless it equals the verified manifest's `agent_id`. All three `agent_manifest` fields must be configured together.                              |

There is no key field: a `PeerNode` generates its own X25519 channel keypair at startup and publishes the public half through the attestation handshake, so a caller seals to a key the node attested rather than one written into a file.

## Validate and start

```
ca2a validate-config --config examples/minimal/ca2a-config.yaml
# ok: provider=software-only enforcement=enforcing

ca2a start --config examples/minimal/ca2a-config.yaml
# note: software-only provider, callers appraise this channel key as
# assurance="none" and the seal carries no hardware guarantee
# ca2a listening on 127.0.0.1:8443 (provider=software-only)
```

`ca2a start` needs no extra install: the reference transport is standard library only. It is one way to run the peer path, not part of the profile. A program that already has a `Policy` and a provider can build a `PeerNode` and serve it from its own A2A server instead.

Invalid values fail fast with a `CONFIG_ERROR` and a message naming the offending field.

When `agent_manifest` is configured, startup verifies the signature, supported version, expiry and revocation state before constructing the node. The verified identity is available as `PeerNode.agent_manifest`. cA2A does not claim runtime policy or tool-catalog artifact matching here: unlike cMCP it has no tool catalog, and its policy may be an inline allow set rather than a hash-addressed bundle.
