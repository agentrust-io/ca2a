# Configuration

The cA2A runtime reads a YAML config. Offline commands validate it with
`ca2a validate-config`. `ca2a start` consumes the same file for the live
JSON-RPC listener.

## Reference

```yaml
attestation:
  provider: auto            # auto | tpm | sev-snp | tdx | opaque | software-only
  enforcement_mode: enforcing  # enforcing | advisory | silent

max_delegation_depth: 8     # reject chains deeper than this
listen_addr: "0.0.0.0:8443"

local_policy: ["read", "write"]   # allow-set for scope intersection (or use Cedar below)
# policy_bundle_path: policy.cedar
# enclave_private_key_hex: "<64 hex chars>"  # optional; opens sealed_payload
```

## Fields

| Field | Default | Description |
|---|---|---|
| `attestation.provider` | `auto` | TEE provider for peer attestation. `auto` selects the strongest available hardware; `software-only` requires no hardware. `opaque` is explicit opt-in and never auto-selected. Live attestation on the call is not wired yet. |
| `attestation.enforcement_mode` | `enforcing` | Intended mode. The live listener always fails closed on cA2A denials today; advisory/silent are accepted in config but not applied on the wire. |
| `max_delegation_depth` | `8` | Chains deeper than this are rejected with `DELEGATION_DEPTH_EXCEEDED`. |
| `listen_addr` | `0.0.0.0:8443` | Address `ca2a start` binds. |
| `local_policy` | none | Capability allow set for `LocalPolicy`. Required for `ca2a start` unless `policy_bundle_path` is set. |
| `policy_bundle_path` | none | Path to a Cedar policy file. When set, used instead of `local_policy`. |
| `enclave_private_key_hex` | none | Optional 32-byte X25519 private key (hex) for opening `sealed_payload`. Override with `--enclave-key-hex` or `CA2A_ENCLAVE_PRIVATE_KEY_HEX`. Software-configured only; not measurement-bound. |

## Validate / start

```bash
ca2a validate-config --config examples/minimal/ca2a-config.yaml
# ok: provider=software-only enforcement=enforcing

pip install 'ca2a-runtime[serve]'
ca2a start --config examples/minimal/ca2a-config.yaml
```

Invalid values fail fast with a `CONFIG_ERROR` and a message naming the offending field.
