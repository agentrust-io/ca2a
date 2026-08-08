# Configuration

The cA2A runtime reads a YAML config. Offline commands validate it with
`ca2a validate-config`. `ca2a start` consumes the same file to build a
[`PeerNode`](spec/component-model.md) and serve it over the reference HTTP
transport.

## Reference

```yaml
attestation:
  provider: auto            # auto | tpm | sev-snp | tdx | opaque | software-only
  enforcement_mode: enforcing  # enforcing | advisory | silent

max_delegation_depth: 8     # reject chains deeper than this
listen_addr: "127.0.0.1:8443"

local_policy: ["read", "write"]   # allow-set for scope intersection (or use Cedar below)
# policy_bundle_path: policy.cedar
```

## Fields

| Field | Default | Description |
|---|---|---|
| `attestation.provider` | `auto` | TEE provider for peer attestation. `auto` selects a detected hardware provider and fails if there is none; it never falls back to `software-only`, which has to be named explicitly. `opaque` is not implemented. |
| `attestation.enforcement_mode` | `enforcing` | Intended mode. The peer path always fails closed on cA2A denials today; advisory and silent are accepted in config but not applied on the wire. |
| `max_delegation_depth` | `8` | Chains deeper than this are rejected with `DELEGATION_DEPTH_EXCEEDED`. |
| `listen_addr` | `127.0.0.1:8443` | Address `ca2a start` binds. The host is never defaulted, so serving on every interface has to be written out. |
| `local_policy` | none | Capability allow set for `LocalPolicy`. Required for `ca2a start` unless `policy_bundle_path` is set. |
| `policy_bundle_path` | none | Path to a Cedar policy file, resolved relative to the config file. When set, used instead of `local_policy`. |

There is no key field: a `PeerNode` generates its own X25519 channel keypair at
startup and publishes the public half through the attestation handshake, so a
caller seals to a key the node attested rather than one written into a file.

## Validate and start

```bash
ca2a validate-config --config examples/minimal/ca2a-config.yaml
# ok: provider=software-only enforcement=enforcing

ca2a start --config examples/minimal/ca2a-config.yaml
# note: software-only provider, callers appraise this channel key as
# assurance="none" and the seal carries no hardware guarantee
# ca2a listening on 127.0.0.1:8443 (provider=software-only)
```

`ca2a start` needs no extra install: the reference transport is standard library
only. It is one way to run the peer path, not part of the profile. A program that
already has a `Policy` and a provider can build a `PeerNode` and serve it from
its own A2A server instead.

Invalid values fail fast with a `CONFIG_ERROR` and a message naming the offending field.
