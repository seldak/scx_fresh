# SPDX-License-Identifier: GPL-2.0-only
"""Compile the production slice helper on the host; no BPF privileges needed."""

import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest


REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "bpf/scx_fresh.bpf.c"


class SliceTests(unittest.TestCase):
    def test_actual_helper_preserves_explicit_hints_and_refills_zero(self):
        source = SOURCE.read_text()
        helper = re.search(r"static __always_inline u64 enqueue_slice_ns\([^)]*\)\n\{.*?\n\}",
                           source, re.S)
        self.assertIsNotNone(helper)
        vmlinux = Path(os.environ.get("VMLINUX_H", REPO / "build/vmlinux.h")).read_text()
        default = re.search(r"\bSCX_SLICE_DFL = (\d+)", vmlinux)
        self.assertIsNotNone(default)
        self.assertEqual(int(default[1]), 20_000_000)
        program = '''
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include "scx_fresh_shared.h"
typedef uint64_t u64;
enum { SCX_SLICE_DFL = DEFAULT_NS };
uint64_t be_slice_cap_ns = 0;
HELPER
int main(void) {
    struct fresh_task_hint hint = {};
    assert(enqueue_slice_ns(NULL) == SCX_SLICE_DFL);
    assert(enqueue_slice_ns(&hint) == SCX_SLICE_DFL);
    assert(hint.slice_ns == 0); // Translation never mutates userspace metadata.
    const uint64_t explicit_slices[] = {1, 150000, 5000000, 20000000, UINT64_MAX};
    for (size_t i = 0; i < sizeof(explicit_slices) / sizeof(explicit_slices[0]); i++) {
        uint64_t slice = explicit_slices[i];
        hint.slice_ns = slice;
        assert(enqueue_slice_ns(&hint) == slice);
    }
    // A zero hint refills on EVERY enqueue, independent of prior residual.
    hint.slice_ns = 0;
    const uint64_t residuals[] = {0, 1, 1000, SCX_SLICE_DFL};
    for (size_t i = 0; i < sizeof(residuals) / sizeof(residuals[0]); i++) {
        uint64_t residual = residuals[i];
        const uint64_t request = enqueue_slice_ns(&hint);
        // Model the documented kernel insertion rule, not a benchmark.
        const uint64_t next = request ? request : (residual ? residual : 1);
        assert(next == SCX_SLICE_DFL);
    }
    const uint64_t caps[] = {2000000, 5000000};
    const uint64_t requests[] = {0, 1, 150000, 2000000, 5000000, 20000000, UINT64_MAX};
    for (size_t c = 0; c < sizeof(caps) / sizeof(caps[0]); c++) {
        be_slice_cap_ns = caps[c];
        assert(enqueue_slice_ns(NULL) == caps[c]); // Unhinted EXT hog.
        for (unsigned stage = 0; stage < 32; stage++) {
            for (unsigned cls = FRESH_CLASS_BACKGROUND; cls <= FRESH_CLASS_URGENT; cls++) {
                hint.stage_id = stage;
                hint.class_id = cls;
                for (size_t i = 0; i < sizeof(requests) / sizeof(requests[0]); i++) {
                    hint.slice_ns = requests[i];
                    uint64_t original = requests[i] ? requests[i] : SCX_SLICE_DFL;
                    bool eligible = cls == FRESH_CLASS_BACKGROUND;
                    uint64_t expected = eligible && original > caps[c] ? caps[c] : original;
                    assert(enqueue_slice_ns(&hint) == expected);
                    assert(hint.slice_ns == requests[i]);
                }
            }
        }
    }
}
'''.replace("DEFAULT_NS", default[1]).replace("HELPER", helper[0])
        with tempfile.TemporaryDirectory(prefix="scx-slice-test-") as directory:
            binary = Path(directory) / "test"
            subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=gnu2x", "-Wall", "-Wextra",
                            "-Werror", "-I", str(REPO / "include"), "-x", "c", "-", "-o", str(binary)],
                           input=program, text=True, check=True)
            subprocess.run([str(binary)], check=True)

    def test_every_enqueue_route_uses_translation(self):
        source = SOURCE.read_text()
        body = source.split("void BPF_STRUCT_OPS(scx_fresh_enqueue,", 1)[1].split(
            "void BPF_STRUCT_OPS(scx_fresh_dispatch,", 1)[0]
        self.assertIn("u64 slice = enqueue_slice_ns(h);", body)
        calls = re.findall(r"\b(?:scx_insert(?:_vtime)?|enqueue_background)\(p, [^,]+, (slice|enqueue_slice_ns\(h\))[,)]", body)
        self.assertEqual(len(calls), 5)
        self.assertEqual(calls.count("enqueue_slice_ns(h)"), 1)  # No-state fallback.
        self.assertEqual(len(re.findall(r"\b(?:scx_insert(?:_vtime)?|enqueue_background)\(", body)), len(calls))

    def test_be_cap_is_default_off(self):
        self.assertIn("const volatile __u64 be_slice_cap_ns = 0;", SOURCE.read_text())

    def test_stage_probe_observes_every_route_without_changing_it(self):
        source = SOURCE.read_text()
        enqueue = source.split("void BPF_STRUCT_OPS(scx_fresh_enqueue,", 1)[1].split(
            "void BPF_STRUCT_OPS(scx_fresh_dispatch,", 1)[0]
        helper = source.split("static __always_inline void trace_urgent_enqueue(", 1)[1].split(
            "/* -----------------------------\n * sched_ext ops", 1)[0]
        self.assertEqual(helper.count("trace_stage_enqueue(p, st, flags, dsq);"), 1)
        self.assertEqual(enqueue.count("trace_urgent_enqueue(p, st,"), 5)
        self.assertEqual(enqueue.count("scx_insert(p,"), 1)
        self.assertEqual(enqueue.count("scx_insert_vtime(p,"), 2)
        self.assertEqual(enqueue.count("enqueue_background(p,"), 2)
        self.assertIn("if (!trace_stage_enqueues)\n        return;", source)

    def test_age_demotion_queue_and_flag_are_absent(self):
        source = SOURCE.read_text()
        self.assertNotIn("DSQ_STALE", source)
        self.assertNotIn("deadline_grace_ns", source)
        self.assertNotIn("FRESH_HINT_EXECUTOR_OWNED", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
