"""Negative controls for the evidence comparator."""
import json
from pathlib import Path

import pytest
from compare import compare


def write_run(root: Path, mode: str):
    root.mkdir()
    (root / 'manifest.json').write_text(json.dumps({
        'mode': mode, 'exit_code': 0, 'timed_out': False, 'ca2a_tracked_changes': '',
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


@pytest.mark.parametrize('counts', [(0, 7), (7, 0), (7, 7), (False, 0), (0, 0.0), (0, None), (0, -1)])
def test_protected_handler_zero_is_enforced(tmp_path, counts):
    left, right = tmp_path / 'baseline', tmp_path / 'extension'
    write_run(left, 'baseline')
    write_run(right, 'extension')
    assert compare(left, right)['protected_handler_invocations'] == [0, 0]
    for root, count in zip((left, right), counts, strict=True):
        path = root / 'manifest.json'
        data = json.loads(path.read_text())
        data['protected_handler_invocations'] = count
        path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='protected-handler'):
        compare(left, right)


@pytest.mark.parametrize('mode', ['baseline', 'extension'])
def test_dirty_source_cannot_compare_equal(tmp_path, mode):
    left, right = tmp_path / 'baseline', tmp_path / 'extension'
    write_run(left, 'baseline')
    write_run(right, 'extension')
    root = left if mode == 'baseline' else right
    path = root / 'manifest.json'
    data = json.loads(path.read_text())
    data['ca2a_tracked_changes'] = ' M src/ca2a_runtime/peer.py'
    path.write_text(json.dumps(data))
    with pytest.raises(ValueError, match='tracked files'):
        compare(left, right)
