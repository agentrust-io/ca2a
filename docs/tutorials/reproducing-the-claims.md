# Reproducing the Claims

Run six software experiments from the source checkout. They exercise delegation, policy intersection, encrypted payloads, hash links, and synthetic attestation. None requires a TEE. Their results establish the specific cases below, not hardware protection or complete profile conformance.

## Install and run

Use Python 3.11 or later:

```bash
git clone https://github.com/agentrust-io/ca2a.git
cd ca2a
python -m venv .venv
```

Activate with `source .venv/bin/activate` on macOS/Linux or `.venv\Scripts\Activate.ps1` in PowerShell. Then:

```bash
python -m pip install -e ".[dev]"
python experiments/claim1-attenuation-soundness/run.py
python experiments/claim2-cross-chain-replay/run.py
python experiments/claim3-scope-policy-intersection/run.py
python experiments/claim4-sealed-payload-confidentiality/run.py
python experiments/claim5-provenance-dag-integrity/run.py
python experiments/claim6-cross-operator-attestation/run.py
```

Each script should exit 0 and print `KEY RESULT`. A traceback, nonzero exit, or `SKIP` is not a successful reproduction. The delegation experiments retain the locally generated root authority separately and pass it explicitly to verification. Do not infer production trust from an incoming chain's own root.

## Read the results

| Experiment | Expected result | Boundary |
|---|---|---|
| C1: attenuation soundness | 200 narrowing chains accepted; 200 correctly signed escalations rejected with `ScopeEscalation` | Exercises scope attenuation on generated chains |
| C2: cross-chain replay | Two control chains accepted; duplicate ID and splice rejected | No global single-use credential database |
| C3: scope-policy intersection | `read` allowed; `write`, `audit`, and `admin` denied | Uses `LocalPolicy`; separate tests cover Cedar |
| C4: sealed-payload confidentiality | Four encryption checks pass, including wrong-key and tamper rejection | Keys live in software memory; no enclave custody demonstrated |
| C5: provenance integrity | Unrepaired parent changes, reparenting, and credential-ID mismatch detected | Unsigned hash links do not authenticate the producer or prevent a fully recomputed rewrite |
| C6: cross-operator attestation | Four checks pass with synthetic reports and certificates | Locally generated test root; no genuine hardware quote or live cross-operator deployment |

C5's changed-bit count varies because the keys are random. The exact count is not a security acceptance threshold. C6's measurement mismatch is simulated by changing a synthetic report, not by swapping a binary on real hardware.

## CI coverage

`tests/unit/test_documented_experiments.py` runs these exact script entry points and checks their positive-control results. To reproduce that check:

```bash
python -m pytest tests/unit/test_documented_experiments.py
```

For the actual Cedar engine and the runtime's authentication/appraisal ordering:

```bash
python -m pytest tests/unit/test_cedar.py tests/unit/test_holder_binding.py tests/unit/test_mutual_attestation.py
```

Continue to [hardware validation](../hardware-validation.md) for recorded hardware evidence, or [integrating with A2A](integrating-with-a2a.md) for a local transport walkthrough.
