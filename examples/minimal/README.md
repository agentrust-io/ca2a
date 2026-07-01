# Minimal example

A three-hop delegation chain and a minimal runtime config.

## Files

- `ca2a-config.yaml`: minimal runtime config (software-only, advisory).
- `chain.json`: a valid delegation chain, `admin` narrowing to `read+write` to `read`. Regenerate with `python scripts/gen_example_chain.py`.

## Verify

```bash
ca2a verify-chain --chain chain.json
ca2a validate-config --config ca2a-config.yaml
```

See [docs/tutorials/verify-a-delegation-chain.md](../../docs/tutorials/verify-a-delegation-chain.md) for a walkthrough that breaks each invariant.
