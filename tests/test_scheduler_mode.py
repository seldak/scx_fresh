# SPDX-License-Identifier: MIT
"""Inspect the built loader's embedded object without BPF load/attach privileges."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest


LOADER = os.environ.get(
    "LOADER_BIN", str(Path(__file__).resolve().parents[1] / "build/scx_fresh")
)


class SchedulerModeTests(unittest.TestCase):
    def test_background_server_pair(self):
        config = subprocess.check_output([LOADER, "--print-config"], text=True)
        self.assertIn("background_runtime_us=0 background_period_us=0", config)
        for q, p in ((1000, 10000), (1, 1), (2000, 2000)):
            config = subprocess.check_output([LOADER, "--print-config",
                "--background-server-us", f"{q}/{p}"], text=True)
            self.assertIn(f"background_runtime_us={q} background_period_us={p}", config)
        for pair in ("", "0/10", "10/0", "11/10", "-1/10", "+1/10", "1/+10",
                     "1/-10", " 1/10", "1/10 ", "1/", "/10", "1/2/3", "10",
                     "1/18446744073709552", "18446744073709551616/20"):
            result = subprocess.run([LOADER, "--print-config", "--background-server-us", pair],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0, pair)

    def test_be_slice_cap_is_opt_in_and_validated(self):
        default = subprocess.check_output([LOADER, "--print-config"], text=True)
        self.assertIn("be_slice_cap_us=0", default)
        for cap in ("0", "2000", "5000"):
            config = subprocess.check_output(
                [LOADER, "--print-config", "--be-slice-cap-us", cap], text=True)
            self.assertIn(f"be_slice_cap_us={cap}", config)
            self.assertIn("expiry_policy=application", config)
            self.assertIn("urgent_preempt=wakeup", config)
        for cap in ("-1", "", "+1", "1x", "18446744073709552"):
            result = subprocess.run([LOADER, "--print-config", "--be-slice-cap-us", cap],
                                    capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_probe_is_opt_in(self):
        default = subprocess.check_output([LOADER, "--print-config"], text=True)
        self.assertIn("urgent_preempt=wakeup trace_urgent=0", default)
        self.assertIn("execution_cpu=-1", default)
        self.assertIn("trace_stage=0", default)
        self.assertIn("expiry_policy=application", default)
        always = subprocess.check_output([LOADER, "--print-config", "--urgent-preempt", "always", "--trace-urgent"], text=True)
        self.assertIn("urgent_preempt=always trace_urgent=1", always)
        execution = subprocess.check_output([LOADER, "--print-config", "--trace-execution-cpu", "0",
                                             "--trace-worker-name", "worker"], text=True)
        self.assertIn("urgent_preempt=wakeup trace_urgent=0 execution_cpu=0", execution)
        stage = subprocess.check_output([LOADER, "--print-config", "--trace-stage", "2"], text=True)
        self.assertIn("urgent_preempt=wakeup trace_urgent=0 execution_cpu=-1 trace_stage=1", stage)
        for args in (("--urgent-preempt", "invalid", "--print-config"), ("--urgent-preempt",)):
            result = subprocess.run([LOADER, *args], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
        for cpu in ("-1", "", "abc", "9999999999999999999999", "1x"):
            result = subprocess.run([LOADER, "--print-config", "--trace-execution-cpu", cpu], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
        for grace in ("0", "1000", "33000"):
            result = subprocess.run([LOADER, "--print-config", "--deadline-grace-us", grace],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("expiry is application-owned", result.stderr)

    def test_embedded_flags(self):
        result = subprocess.run([LOADER, "--print-ops-flags"],
                                capture_output=True, text=True, check=True, timeout=10)
        flags = int(result.stdout.strip(), 16)
        expected = 0 if os.environ.get("EXPECTED_FULL_SWITCH", "0") == "1" else 8
        self.assertEqual(flags, expected)
        self.assertNotIn("setrlimit", result.stderr)
        print(f"Embedded scheduler flags: {flags:#x}", flush=True)

    def test_trace_selectors_are_explicit_and_validated(self):
        for value in ("0", "12345", "4294967295"):
            result = subprocess.run([LOADER, "--print-config", "--trace-stage", value],
                                    capture_output=True)
            self.assertEqual(result.returncode, 0)
        for args in (("--trace-stage", "-1"), ("--trace-stage", "4294967296"),
                     ("--trace-stage", ""), ("--trace-worker-name", ""),
                     ("--trace-worker-name", "1234567890123456"),
                     ("--trace-execution-cpu", "0")):
            result = subprocess.run([LOADER, "--print-config", *args], capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_inspection_cannot_be_combined_with_attach(self):
        with tempfile.TemporaryDirectory(prefix="scx-mode-test-") as directory:
            pin_dir = Path(directory) / "pins"
            result = subprocess.run([LOADER, "--print-ops-flags", "--pin", str(pin_dir)],
                                    capture_output=True, text=True, timeout=10)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(pin_dir.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
