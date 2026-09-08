#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Wake an earlier Deadline job during a 20ms Deadline callback, three times."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import time

from test_background_server import ROOT, stop


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--housekeeping-cpu', type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() or args.cpu == args.housekeeping_cpu or min(args.cpu, args.housekeeping_cpu) < 0:
        parser.error('requires root and two distinct nonnegative CPUs')
    if Path('/sys/kernel/sched_ext/state').read_text().strip() != 'disabled':
        parser.error('another scheduler is active')
    output = Path(tempfile.mkdtemp(prefix='scx-deadline-test-'))
    pin = Path('/sys/fs/bpf') / f'scx-deadline-test-{os.getpid()}'
    print(f'Raw logs: {output}', flush=True)
    loader = None
    try:
        with (output / 'loader.log').open('w') as log:
            loader = subprocess.Popen(['taskset', '-c', str(args.housekeeping_cpu),
                str(ROOT / 'build/scx_fresh'), '--pin', str(pin)], stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 10
            while not (pin / 'task_hints').exists():
                if loader.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError('scheduler did not attach')
                time.sleep(0.05)
            for repetition in range(1, 4):
                result = subprocess.run(['taskset', '-c', str(args.housekeeping_cpu),
                    str(ROOT / 'build/deadline_workload'), str(pin), str(args.cpu)],
                    capture_output=True, text=True, timeout=10)
                (output / f'workload-{repetition}.log').write_text(result.stdout + result.stderr)
                print(result.stdout, end='', flush=True)
                if result.returncode or loader.poll() is not None:
                    raise RuntimeError(f'repetition {repetition}: preemption gate failed')
        print('Three earlier-deadline wakeups passed the 5ms start-delay gate.')
    finally:
        stop(loader)
        for name in ('task_hints', 'events'):
            (pin / name).unlink(missing_ok=True)
        if pin.exists():
            pin.rmdir()
        if 'SUDO_UID' in os.environ:
            for path in [output, *output.iterdir()]:
                os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))


if __name__ == '__main__':
    main()
