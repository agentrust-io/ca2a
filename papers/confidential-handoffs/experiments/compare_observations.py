"""Compare composed-harness observation records across runs.

Usage: python compare_observations.py REFERENCE.jsonl OTHER.jsonl [OTHER.jsonl ...]

Transaction identifiers and the locally built container image digest differ per
run by design and are removed before comparison. Exit status 1 means a record
in OTHER is absent from REFERENCE or an oracle did not pass.
"""
import collections
import json
import sys


def load(path):
    records = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            record = json.loads(line)
            record.pop("transaction", None)
            record.get("confinement", {}).pop("image", None)
            records.append(json.dumps(record, sort_keys=True))
    return collections.Counter(records)


def main(reference, *others):
    base = load(reference)
    status = 0
    for path in others:
        run = load(path)
        failed = sum(1 for r in run.elements() if json.loads(r)["oracle"] != "passed")
        extra = sum((run - base).values())
        missing = sum((base - run).values())
        print(f"{path}: {sum(run.values())} records, {failed} oracle failures, "
              f"{extra} not in reference, {missing} reference records absent")
        if failed or extra:
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
