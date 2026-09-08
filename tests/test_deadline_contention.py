# SPDX-License-Identifier: GPL-2.0-only
"""Ensure the loaded probe rejects incomplete work and timing regressions."""
import contextlib
import io
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from test_deadline_contention import validate


def fixture():
    lines = []
    for r in range(1, 4):
        base = r * 150_000_000
        for name, release, start, end, cpu in (
            ('owner', 0, 1000, 22_000_000, 20_000_000),
            ('earlier', 3_000_000, 3_100_000, 4_100_000, 1_000_000),
            ('equal', 3_000_000, 22_000_000, 23_000_000, 1_000_000),
            ('later', 3_000_000, 23_000_000, 24_000_000, 1_000_000)):
            lines.append(f'job name={name} job={r} release={base+release} '
                         f'start={base+start} end={base+end} cpu={cpu}')
    return '\n'.join(lines)


class Gates(unittest.TestCase):
    def check(self, data):
        with contextlib.redirect_stdout(io.StringIO()):
            return validate(data, False)

    def test_valid(self):
        self.assertEqual(len(self.check(fixture())), 12)

    def test_missing_job(self):
        with self.assertRaises(RuntimeError):
            self.check('\n'.join(fixture().splitlines()[:-1]))

    def test_duplicate(self):
        with self.assertRaises(RuntimeError):
            self.check(fixture() + '\n' + fixture().splitlines()[0])

    def test_incomplete_cpu_work(self):
        with self.assertRaises(RuntimeError):
            self.check(fixture().replace('cpu=20000000', 'cpu=1000000'))

    def test_missed_preemption(self):
        with self.assertRaises(RuntimeError):
            self.check(fixture().replace('start=153100000 end=154100000',
                                        'start=173100000 end=174100000'))


if __name__ == '__main__':
    unittest.main()
