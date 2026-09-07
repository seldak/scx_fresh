#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Loaded allocation test on an otherwise quiet CPU; Q/P is fixed at 2ms/10ms."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_NS = 2_000_000
PERIOD_NS = 10_000_000


def validate_service(name, rows, gaps, window_ns):
    expected = window_ns * RUNTIME_NS // PERIOD_NS
    # Two boundary periods plus two ~100us observation chunks. These are
    # finite-window test tolerances, not scheduler guarantees or policy knobs.
    tolerance = 2 * PERIOD_NS + 200_000
    background = rows["background"] + rows["demoted"]
    if abs(background - expected) > tolerance:
        raise RuntimeError(f"{name}: Background allocation {background / 1e6:.3f}ms "
                           f"outside {expected / 1e6:.3f}ms +/- {tolerance / 1e6:.3f}ms")
    if abs(rows["background"] - rows["demoted"]) > tolerance:
        raise RuntimeError(f"{name}: native/demoted Background service is unbalanced")
    if max(gaps["background"], gaps["demoted"]) > 5 * PERIOD_NS:
        raise RuntimeError(f"{name}: Background service gap exceeds five periods")


def stop(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def run_cell(args, name, server, urgent, output):
    pin = Path("/sys/fs/bpf") / f"scx-fresh-server-test-{os.getpid()}"
    loader = workload = None
    with (output / f"{name}.loader.log").open("w+") as log, \
         (output / f"{name}.workload.log").open("w+") as worklog:
        try:
            command = ["taskset", "-c", str(args.housekeeping_cpu),
                       str(ROOT / "build/scx_fresh"), "--pin", str(pin)]
            if server:
                command += ["--background-server-us", f"{RUNTIME_NS // 1000}/{PERIOD_NS // 1000}"]
            loader = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
            for _ in range(100):
                if loader.poll() is not None:
                    raise RuntimeError(f"{name}: scheduler load/attachment failed")
                if (pin / "task_hints").exists():
                    break
                time.sleep(0.05)
            else:
                raise RuntimeError(f"{name}: scheduler did not pin maps")
            workload = subprocess.Popen(["taskset", "-c", str(args.housekeeping_cpu),
                str(ROOT / "build/background_workload"), str(pin),
                str(args.cpu), str(int(urgent))], stdout=worklog, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 8
            end_ns = None
            while time.monotonic() < deadline:
                worklog.flush()
                text = (output / f"{name}.workload.log").read_text()
                ready = next((line for line in text.splitlines() if line.startswith("ready ")), None)
                if ready:
                    window = dict(item.split("=", 1) for item in ready.split()[1:])
                    begin_ns, end_ns = int(window["begin_ns"]), int(window["end_ns"])
                    break
                if workload.poll() is not None:
                    raise RuntimeError(f"{name}: workload failed before readiness")
                time.sleep(0.05)
            if end_ns is None:
                raise RuntimeError(f"{name}: no measurement window")
            while time.monotonic_ns() < end_ns + 100_000_000:
                if loader.poll() is not None:
                    raise RuntimeError(f"{name}: scheduler exited during measurement")
                time.sleep(0.05)
            # A starved Background worker cannot exit until the scheduler is
            # detached. Measurement ends before detachment in every cell.
            stop(loader)
            if loader.returncode != 0:
                raise RuntimeError(f"{name}: loader failed")
            workload.wait(timeout=5)
            if workload.returncode:
                raise RuntimeError(f"{name}: workload failed")
            text = (output / f"{name}.workload.log").read_text()
            rows = {}
            gaps = {}
            for line in text.splitlines():
                if line.startswith("worker "):
                    row = dict(item.split("=", 1) for item in line.split()[1:])
                    rows[row["name"]] = int(row["cpu_ns"])
                    gaps[row["name"]] = int(row["max_gap_ns"])
            if set(rows) != {"deadline", "background", "demoted"} | ({"urgent"} if urgent else set()):
                raise RuntimeError(f"{name}: incomplete accounting")
            print(f"{name}: " + " ".join(f"{key}_cpu_ms={value / 1e6:.3f}" for key, value in rows.items()), flush=True)
            for line in (output / f"{name}.loader.log").read_text().splitlines():
                if line.startswith("background_server_lifetime:"):
                    print(line, flush=True)
            if server and (min(rows["background"], rows["demoted"]) < 100_000_000 or rows["deadline"] < 1_000_000_000):
                raise RuntimeError(f"{name}: Background or Deadline did not make sustained progress")
            if urgent and rows["urgent"] < 100_000_000:
                raise RuntimeError(f"{name}: Urgent did not make sustained progress")
            if server:
                validate_service(name, rows, gaps, end_ns - begin_ns)
                print(f"{name}: max_background_gap_ms="
                      f"{max(gaps['background'], gaps['demoted']) / 1e6:.3f}", flush=True)
            return rows
        except Exception:
            log.flush(); worklog.flush()
            print((output / f"{name}.loader.log").read_text())
            print((output / f"{name}.workload.log").read_text())
            raise
        finally:
            stop(loader)
            stop(workload)
            for entry in ("task_hints", "events"):
                (pin / entry).unlink(missing_ok=True)
            if pin.exists():
                pin.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cpu", type=int, required=True)
    parser.add_argument("--housekeeping-cpu", type=int, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("run with sudo after building make all build/background_workload")
    if args.cpu == args.housekeeping_cpu or min(args.cpu, args.housekeeping_cpu) < 0:
        parser.error("worker and housekeeping CPUs must be distinct and nonnegative")
    if Path("/sys/kernel/sched_ext/state").read_text().strip() != "disabled":
        parser.error("another sched_ext scheduler is active")
    output = Path(tempfile.mkdtemp(prefix="scx-fresh-server-"))
    # Let the invoking developer inspect the logs after this root-only test.
    if "SUDO_UID" in os.environ and "SUDO_GID" in os.environ:
        os.chown(output, int(os.environ["SUDO_UID"]), int(os.environ["SUDO_GID"]))
    print(f"Raw logs: {output}", flush=True)
    baseline = run_cell(args, "disabled", False, False, output)
    enabled = run_cell(args, "server", True, False, output)
    run_cell(args, "server-urgent", True, True, output)
    if sum(enabled[k] for k in ("background", "demoted")) <= sum(baseline[k] for k in ("background", "demoted")) + 200_000_000:
        raise RuntimeError("server did not improve Background service over leftovers")
    print("Allocation, fairness, and progress gates passed for this fixed test window.")


if __name__ == "__main__":
    main()
