"""Negative controls for the evidence comparator."""
import json
from pathlib import Path

import pytest
from compare import compare


def write_run(root: Path, mode: str):
    root.mkdir()
    (root / 'manifest.json').write_text(json.dumps({
        'mode': mode, 'exit_code': 0, 'timed_out': False,
        'ca2a_commit': 'ca2a', 'tck_commit': 'tck', 'tck_lock_sha256': 'lock',
        'runner_sha256': 'runner', 'sdk': '1.2.2', 'protected_handler_invocations': 0,
    }))
    (root / 'junit.xml').write_text('<testsuite><testcase classname="suite" name="one"/></testsuite>')


@pytest.mark.parametrize('mutation', ['failure', 'missing', 'rename', 'skip', 'provenance', 'exit'])
def test_rejects_false_equivalence(tmp_path, mutation):
    left, right = tmp_path / 'baseline', tmp_path / 'extension'
    write_run(left, 'baseline')
    write_run(right, 'extension')
    assert compare(left, right)['identical_test_outcomes']
    path = right / 'junit.xml'
    if mutation == 'failure':
        path.write_text('<testsuite><testcase classname="suite" name="one"><failure/></testcase></testsuite>')
    elif mutation == 'missing':
        path.write_text('<testsuite/>')
    elif mutation == 'rename':
        path.write_text(path.read_text().replace('one', 'two'))
    elif mutation == 'skip':
        path.write_text('<testsuite><testcase classname="suite" name="one"><skipped/></testcase></testsuite>')
    else:
        path = right / 'manifest.json'
        data = json.loads(path.read_text())
        data['sdk' if mutation == 'provenance' else 'exit_code'] = 'changed'
        path.write_text(json.dumps(data))
    with pytest.raises(ValueError):
        compare(left, right)
