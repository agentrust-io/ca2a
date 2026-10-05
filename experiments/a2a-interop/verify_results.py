"""Verify the saved report's claims without rerunning external test peers."""

import json
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

root = Path(__file__).resolve().parent / "results"


def cases(path):
    found = {}
    for case in ET.parse(path).getroot().iter("testcase"):
        key = case.attrib["classname"] + "::" + case.attrib["name"]
        assert key not in found, key
        found[key] = next(
            (tag for tag in ["failure", "error", "skipped"] if case.find(tag) is not None), "passed"
        )
    return found


baseline = cases(root / "baseline/junit.xml")
assert baseline == cases(root / "ca2a/junit.xml")
assert Counter(baseline.values()) == {"passed": 183, "failure": 5, "skipped": 47}
assert Counter(cases(root / "sdk-tests.xml").values()) == {"passed": 55}
for mode in ["baseline", "ca2a"]:
    assert json.loads((root / f"{mode}/command.json").read_text())["exit"] == 1
    results = json.loads((root / f"itk/{mode}-results.json").read_text())
    assert len(results) == 6 and all(x["passed"] is True for x in results.values())
    card = json.loads((root / f"itk/{mode}-python_v10-card.json").read_text())
    extensions = card.get("capabilities", {}).get("extensions", [])
    assert bool(extensions) == (mode == "ca2a")
protected = json.loads((root / "protected-ts.json").read_text())
assert protected["callee_assurance"] == "none"
assert protected["protected_handler_invocations"] == 3
checks = protected["results"]
assert sum(v.get("passed") is True for v in checks.values()) == 6
assert checks["signed_read"]["canonical_credentials_preserved"] is True
assert checks["duplicate_message_observation"]["protected_handler_invocations"] == 2
assert checks["replay_observation"]["accepted"] is True
assert checks["fractional_depth"]["error"] == "TRANSPORT_ERROR"
assert checks["tampered_signature"]["error"] == "INVALID_CREDENTIAL"
print(
    "Saved evidence agrees: TCK 183/5/47 in both runs; ITK 6+6; SDK 55; protected checks 6 plus 2 accepted replay observations."
)
