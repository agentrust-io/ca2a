# Minimal example

A three-hop delegation chain and a minimal runtime config.

## Files

- `ca2a-config.yaml`: minimal runtime config (software-only, enforcing).
- `chain.json`: a valid delegation chain, `admin` narrowing to `read+write` to `read`. Regenerate with `python scripts/gen_example_chain.py`.

## Verify

```bash
ca2a verify-chain --chain chain.json --trusted-root-issuer eda38c446da3db3eba68852ca9869260c36badd48b2cab16ec8d8faf607eb162
ca2a validate-config --config ca2a-config.yaml
```

See [docs/tutorials/verify-a-delegation-chain.md](../../docs/tutorials/verify-a-delegation-chain.md) for a walkthrough that breaks each invariant.
