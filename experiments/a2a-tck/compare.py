"""Fail on missing, failed, or changed per-test outcomes in paired TCK runs."""
import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


def outcomes(directory):
    manifest = json.loads((directory / 'manifest.json').read_text())
    if manifest['exit_code'] != 0 or manifest['timed_out']:
        raise ValueError('TCK run did not complete successfully')
    rows = {}
    for case in ET.parse(directory / 'junit.xml').iter('testcase'):
        key = case.attrib['classname'] + '::' + case.attrib['name']
        if key in rows:
            raise ValueError('duplicate test identity: ' + key)
        rows[key] = next((tag for tag in ('failure', 'error', 'skipped') if case.find(tag) is not None), 'passed')
    if not rows or 'passed' not in rows.values():
        raise ValueError('empty test coverage')
    if any(status in {'failure', 'error'} for status in rows.values()):
        raise ValueError('failed tests')
    return manifest, rows


def compare(baseline, extension):
    left, a = outcomes(baseline)
    right, b = outcomes(extension)
    if left['mode'] != 'baseline' or right['mode'] != 'extension':
        raise ValueError('expected baseline then extension')
    for key in ('ca2a_commit', 'tck_commit', 'tck_lock_sha256', 'runner_sha256', 'sdk'):
        if left[key] != right[key]:
            raise ValueError('mismatched provenance: ' + key)
    if a != b:
        raise ValueError('per-test outcomes differ')
    return {'identical_test_outcomes': True, 'counts': dict(Counter(a.values())),
            'protected_handler_invocations': [left['protected_handler_invocations'], right['protected_handler_invocations']]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('baseline', type=Path)
    parser.add_argument('extension', type=Path)
    args = parser.parse_args()
    sys.stdout.write(json.dumps(compare(args.baseline, args.extension), indent=2) + "\n")
