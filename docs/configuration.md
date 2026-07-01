# Configuration

The cA2A runtime reads a YAML config. The peer runtime path is under construction; this page documents the surface it consumes, validated today by `ca2a validate-config`.

## Reference

```yaml
attestation:
  provider: auto            # auto | tpm | sev-snp | tdx | opaque | software-only
  enforcement_mode: enforcing  # enforcing | advisory | silent

max_delegation_depth: 8     # reject chains deeper than this
listen_addr: "0.0.0.0:8443"

policy_bundle_path: policy/  # optional: Cedar bundle for local scope intersection
```

## Fields

| Field | Default | Description |
|---|---|---|
| `attestation.provider` | `auto` | TEE provider for peer attestation. `auto` selects the strongest available hardware; `software-only` requires no hardware. `opaque` is explicit opt-in and never auto-selected. |
| `attestation.enforcement_mode` | `enforcing` | `enforcing` denies peer calls that fail verification; `advisory` logs and proceeds; `silent` evaluates without logging or blocking. |
| `max_delegation_depth` | `8` | Chains deeper than this are rejected with `DELEGATION_DEPTH_EXCEEDED`. |
| `listen_addr` | `0.0.0.0:8443` | Address the peer runtime listens on. |
| `policy_bundle_path` | none | Directory of Cedar policy the runtime intersects with a delegated scope. |

## Validate

```bash
ca2a validate-config --config examples/minimal/ca2a-config.yaml
# ok: provider=auto enforcement=advisory
```

Invalid values fail fast with a `CONFIG_ERROR` and a message naming the offending field.
