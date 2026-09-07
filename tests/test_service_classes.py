# SPDX-License-Identifier: GPL-2.0-only
"""Exercise production enqueue decisions with host substitutes for kernel calls."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "bpf/scx_fresh.bpf.c").read_text()


def function(name):
    match = re.search(r"(?:static (?:__always_inline )?[^\n]*\b" + name +
                      r"\([^)]*\)|void BPF_STRUCT_OPS\(" + name +
                      r",[^)]*\))\n\{.*?\n\}", SOURCE, re.S)
    if not match:
        raise AssertionError(f"Missing production function {name}")
    return match[0]


class ServiceClasses(unittest.TestCase):
    def test_client_rejects_incompatible_hints_before_map_update(self):
        program = r'''
#include <assert.h>
#include <errno.h>
#include <bpf/bpf.h>
#include "freshqos.h"
static unsigned writes;
int bpf_map_update_elem(int fd, const void *key, const void *value, __u64 flags) {
    (void)fd; (void)key; (void)value; (void)flags; writes++; return 0;
}
int main(void) {
    struct freshqos q = {.map_fd=42};
    struct fresh_task_hint h = {.api_version=1, .class_id=FRESH_CLASS_URGENT};
    assert(freshqos_publish_hint(&q, &h)==-EINVAL);
    assert(freshqos_publish_hint_for(&q, 123, &h)==-EINVAL);
    h.api_version=FRESH_API_VERSION; h.class_id=99;
    assert(freshqos_publish_hint(&q, &h)==-EINVAL);
    assert(freshqos_publish_hint_for(&q, 123, &h)==-EINVAL);
    assert(writes==0);
    for (unsigned cls=0; cls<=FRESH_CLASS_URGENT; cls++) {
        h.class_id=cls; h.stage_id=UINT32_MAX;
        assert(freshqos_publish_hint(&q, &h)==0);
        assert(freshqos_publish_hint_for(&q, 123, &h)==0);
    }
    assert(writes==6);
}
'''
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "client"
            subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=gnu2x",
                "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "include"),
                "-I", str(ROOT / "src"), "-x", "c", "-", str(ROOT / "src/freshqos.c"),
                "-lbpf", "-o", str(binary)], input=program, text=True, check=True)
            subprocess.run([str(binary)], check=True)

    def test_stage_identity_never_selects_service(self):
        program = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include "scx_fresh_shared.h"
typedef uint64_t u64;
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define SCX_ENQ_WAKEUP 1
#define SCX_ENQ_PREEMPT 2
#define SCX_DSQ_LOCAL 99
#define SCX_SLICE_DFL 20000000ULL
DSQS
struct task_struct { int unused; };
struct task_state {
    u64 last_job_id, exec_ns_in_job, vruntime;
    u64 last_reported_deadline_miss_job;
    u64 last_reported_budget_demotion_job;
    bool overrun;
    bool background_member, background_queued;
};
static struct task_state state;
static struct fresh_task_hint hint;
static bool present = true, has_state = true;
static int task_hints;
static u64 now = 100000000, destination, inserted_flags, inserted_slice, order;
static u64 be_slice_cap_ns;
static bool urgent_preempt_always;
static void *bpf_map_lookup_elem(void *map, const void *key) {
    (void)map; (void)key; return present ? &hint : NULL;
}
static u64 scx_now_ns(void) { return now; }
static u64 task_pid_tgid(struct task_struct *p) { (void)p; return 42; }
static struct task_state *get_state(u64 key) { (void)key; return has_state ? &state : NULL; }
#define trace_urgent_enqueue(...) ((void)0)
#define emit_evt(...) ((void)0)
static void scx_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags) {
    (void)p; destination=dsq; inserted_slice=slice; inserted_flags=flags;
}
static void scx_insert_vtime(struct task_struct *p, u64 dsq, u64 slice, u64 vtime, u64 flags) {
    scx_insert(p, dsq, slice, flags); order=vtime;
}
/* This suite freezes the disabled routing contract. Enabled server hooks
 * and real enqueue_background are exercised by test_background_server.py. */
static void enqueue_background(struct task_struct *p, struct task_state *st,
                               u64 slice, u64 flags, u64 time) {
    scx_insert_vtime(p, DSQ_BACKGROUND, slice, st ? st->vruntime : time, flags);
}
FUNCTIONS
static void run(u64 flags, u64 dsq, bool preempt) {
    struct task_struct p = {};
    scx_fresh_enqueue(&p, flags);
    assert(destination == dsq);
    assert(!!(inserted_flags & SCX_ENQ_PREEMPT) == preempt);
}
int main(void) {
    const uint32_t stages[] = {0, 1, 2, 15, 31, 12345, UINT32_MAX};
    for (unsigned i=0; i<sizeof(stages)/sizeof(stages[0]); i++) {
        state = (struct task_state){.last_job_id=7};
        hint = (struct fresh_task_hint){.api_version=FRESH_API_VERSION,
            .stage_id=stages[i], .job_id=7, .release_ts_ns=now-1000,
            .deadline_ts_ns=now+5000, .stale_ns=10000};
        hint.class_id=FRESH_CLASS_URGENT;
        run(SCX_ENQ_WAKEUP, SCX_DSQ_LOCAL, true);
        run(0, DSQ_URGENT, false);
        hint.class_id=FRESH_CLASS_DEADLINE;
        run(SCX_ENQ_WAKEUP, DSQ_DEADLINE, false);
        assert(order==hint.deadline_ts_ns);
        hint.class_id=FRESH_CLASS_BACKGROUND;
        be_slice_cap_ns=2000000;
        run(SCX_ENQ_WAKEUP, DSQ_BACKGROUND, false);
        assert(inserted_slice==2000000);
        hint.deadline_ts_ns=now-2000000;
        hint.class_id=FRESH_CLASS_DEADLINE;
        run(0, DSQ_DEADLINE, false);
        // An already-expired freshness bound affects ordering, never routing.
        hint.release_ts_ns=1; hint.stale_ns=1;
        run(SCX_ENQ_WAKEUP, DSQ_DEADLINE, false);
        assert(order==2);
        // Simulate a callback tail re-enqueued much later with its slot intact.
        now+=1000000000;
        run(0, DSQ_DEADLINE, false);
        assert(hint.job_id==7 && state.last_job_id==7);
        hint.class_id=FRESH_CLASS_BACKGROUND;
        run(0, DSQ_BACKGROUND, false);
        assert(inserted_slice==2000000);
        hint.class_id=FRESH_CLASS_DEADLINE;
        state.overrun=true;
        run(0, DSQ_BACKGROUND, false);
        assert(inserted_slice==SCX_SLICE_DFL); // Original Deadline class is not capped.
        hint.class_id=FRESH_CLASS_URGENT;
        run(SCX_ENQ_WAKEUP, SCX_DSQ_LOCAL, true); // Preserved Urgent overrun exemption.
        assert(inserted_slice==SCX_SLICE_DFL);
        hint.class_id=FRESH_CLASS_DEADLINE;
        hint.job_id++;
        run(0, DSQ_DEADLINE, false);
        assert(!state.overrun && state.exec_ns_in_job==0);
        hint.api_version=2;
        hint.class_id=FRESH_CLASS_URGENT;
        run(SCX_ENQ_WAKEUP, DSQ_BACKGROUND, false);
        hint.api_version=FRESH_API_VERSION;
        hint.class_id=999;
        run(SCX_ENQ_WAKEUP, DSQ_BACKGROUND, false);
    }
    present=false;
    run(SCX_ENQ_WAKEUP, DSQ_BACKGROUND, false);
    has_state=false;
    run(SCX_ENQ_WAKEUP, DSQ_BACKGROUND, false);
}
'''
        program = program.replace("DSQS", "\n".join(re.findall(r"^#define DSQ_.*", SOURCE, re.M)))
        program = program.replace("FUNCTIONS", "\n".join(function(n) for n in
            ("get_hint", "sync_job", "safe_age_ns", "effective_deadline_ns", "enqueue_slice_ns", "scx_fresh_enqueue")))
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "classes"
            subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=gnu2x",
                "-Wall", "-Wextra", "-Werror", "-I", str(ROOT / "include"),
                "-x", "c", "-", "-o", str(binary)], input=program, text=True, check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
