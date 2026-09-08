#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check repeated Deadline contention, alone and with other service classes."""
import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import time

from test_background_server import ROOT, stop


def validate(output, mixed):
    rows = {}
    names = {'owner', 'earlier', 'equal', 'later'}
    if mixed:
        names |= {'demoted', 'background', 'urgent'}
    for line in output.splitlines():
        if not line.startswith('job '):
            continue
        fields = dict(item.split('=', 1) for item in line.split()[1:])
        name = fields.pop('name')
        fields = {k: int(v) for k, v in fields.items()}
        key = (fields['job'], name)
        if key in rows:
            raise RuntimeError('duplicate job result')
        rows[key] = fields
    if set(rows) != {(r, n) for r in range(1, 4) for n in names}:
        raise RuntimeError('missing or unexpected job results')
    for r in range(1, 4):
        jobs = {n: rows[r, n] for n in names}
        for name, s in jobs.items():
            work = {'owner': 20, 'demoted': 6, 'background': 6}.get(name, 1)
            if not (s['release'] <= s['start'] < s['end'] <= s['release'] + 120_000_000):
                raise RuntimeError(f'{name} job {r}: progress/window gate failed')
            if not work * 1_000_000 <= s['cpu'] <= (work + 1) * 1_000_000:
                raise RuntimeError(f'{name} job {r}: CPU work gate failed')
        if not mixed:
            owner, early, later = (jobs[n] for n in ('owner', 'earlier', 'later'))
            if not owner['start'] < early['release'] <= early['start'] < owner['end']:
                raise RuntimeError('earlier arrival did not overlap the running owner')
            if early['start'] - early['release'] > 5_000_000:
                raise RuntimeError('earlier arrival exceeded 5ms start-delay gate')
            # Equal deadlines have no promised FIFO completion order.
            if not early['end'] < owner['end'] < later['end']:
                raise RuntimeError('deadline completion order failed')
        else:
            urgent = jobs['urgent']
            if urgent['start'] - urgent['release'] > 5_000_000:
                raise RuntimeError('Urgent start-delay gate failed')
            if jobs['background']['start'] >= jobs['owner']['end']:
                raise RuntimeError('Background did not start during Deadline contention')
        order = ','.join(sorted(names, key=lambda n: jobs[n]['end']))
        delays = ' '.join(f'{n}={(jobs[n]["start"]-jobs[n]["release"])/1000:.1f}us'
                          for n in sorted(names))
        print(f'round={r} completion_order={order} start_delays: {delays}')
        print('cpu_ms: ' + ' '.join(f'{n}={jobs[n]["cpu"]/1e6:.3f}' for n in sorted(names)))
    return rows


def cell(args, output, mixed):
    name = 'mixed' if mixed else 'deadline'
    pin = Path('/sys/fs/bpf') / f'scx-contention-{os.getpid()}-{name}'
    loader = None
    try:
        with (output / f'{name}.loader.log').open('w') as log:
            command = ['taskset', '-c', str(args.housekeeping_cpu),
                       str(ROOT / 'build/scx_fresh'), '--pin', str(pin)]
            if mixed:
                command += ['--background-server-us', '2000/10000']
            loader = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            end = time.monotonic() + 10
            while not (pin / 'task_hints').exists():
                if loader.poll() is not None or time.monotonic() > end:
                    raise RuntimeError(f'{name}: scheduler did not attach')
                time.sleep(.05)
            result = subprocess.run(['taskset', '-c', str(args.housekeeping_cpu),
                str(ROOT / 'build/deadline_contention'), str(pin), str(args.cpu),
                str(int(mixed))], capture_output=True, text=True, timeout=10)
            (output / f'{name}.workload.log').write_text(result.stdout + result.stderr)
            if result.returncode or loader.poll() is not None:
                raise RuntimeError(f'{name}: workload or scheduler failed')
            print(f'cell={name}', flush=True)
            validate(result.stdout, mixed)
    finally:
        stop(loader)
        for entry in ('task_hints', 'events'):
            (pin / entry).unlink(missing_ok=True)
        if pin.exists():
            pin.rmdir()
    if mixed:
        log = (output / f'{name}.loader.log').read_text()
        for job in range(1, 4):
            if f'BUDGET_DEMOTION stage=0 job={job} ' not in log:
                raise RuntimeError(f'missing budget demotion for job {job}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cpu', type=int, required=True)
    parser.add_argument('--housekeeping-cpu', type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() or args.cpu == args.housekeeping_cpu or min(args.cpu, args.housekeeping_cpu) < 0:
        parser.error('requires root and two distinct nonnegative CPUs')
    if Path('/sys/kernel/sched_ext/state').read_text().strip() != 'disabled':
        parser.error('another scheduler is active')
    output = Path(tempfile.mkdtemp(prefix='scx-contention-'))
    print(f'Raw logs: {output}', flush=True)
    try:
        cell(args, output, False)
        cell(args, output, True)
        print('Contention gates passed; this is not a schedulability guarantee.')
    finally:
        if 'SUDO_UID' in os.environ:
            for path in [output, *output.iterdir()]:
                os.chown(path, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))


if __name__ == '__main__':
    main()
