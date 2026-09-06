# Scope-Policy Intersection (Cedar)

A delegated capability is usable only when the callee's local policy also allows it. The runtime implements this intersection with either `LocalPolicy`, a capability allow set, or `CedarPolicy`, backed by `cedarpy`. Both implement the `Policy` protocol and run in the live peer path.

```text
effective scope = delegated leaf scope intersected with local policy
```

For example, a leaf delegated `read` and `write` meeting a policy that permits `read` and `audit` receives only `read`. Local policy cannot add undelegated authority, and delegation cannot override a local denial.

## Cedar policy

This reference fragment assumes `chain` is a signed chain and `trusted_roots` contains independently approved root issuer keys. Use the [quick start](../quickstart.md) to create a local chain first.

```python
from ca2a_runtime.cedar import CedarPolicy
from ca2a_runtime.peer import effective_scope

policy = CedarPolicy('permit(principal, action == Action::"read", resource);')
allowed = effective_scope(chain, policy, trusted_root_issuers=trusted_roots)
```

`CedarPolicy` maps each delegated capability to a Cedar request whose action ID is that capability. Only Cedar `Allow` results survive. See `ca2a_runtime.cedar` for the principal, resource, context, and entity inputs supported by the API.

## Runtime configuration

`ca2a start --config ca2a.yaml` uses `bootstrap.load_policy` to load `policy_bundle_path` when set, or otherwise the `local_policy` allow set. A relative bundle path resolves against the configuration file's directory. A missing or empty bundle is a configuration error. Startup requires one of these policy sources.

`Ca2aConfig.enforcement_mode` accepts `enforcing`, `advisory`, and `silent`, but the peer path currently **always blocks a denied capability**. The latter two values do not enable an observation-only rollout. See [configuration](../configuration.md).

## Where it runs

The full inbound handler verifies the chain and holder proof before evaluating local policy. It then appraises the caller, decides the requested capability, and opens any sealed payload only after acceptance. `SCOPE_NOT_PERMITTED` carries a denial record when the capability falls outside the effective scope. The exact sequence is in [inbound peer-call decision](call-graph.md).

## Reproduce the behavior

From an installed source checkout:

```bash
python experiments/claim3-scope-policy-intersection/run.py
pytest tests/unit/test_cedar.py tests/unit/test_peer.py tests/unit/test_bootstrap.py
```

C3 checks the intersection using `LocalPolicy`; the Cedar tests exercise the actual Cedar engine. Passing the allow-set experiment alone does not validate a Cedar policy bundle.
