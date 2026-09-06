/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * scx_fresh: freshness-aware sched_ext scheduler for application-selected jobs.
 *
 * Policy summary:
 * - Urgent class: always route to DSQ_URGENT (highest priority),
 *   never stale-demote / late-demote. Periodic tasks may "arm" hints with future
 *   release_ts_ns; all age math guards against underflow.
 * - Deadline: EDF-like ordering using DSQ vtime = effective deadline
 * - Stale work: demoted to DSQ_STALE
 * - Budget overrun: Deadline task demoted to Background for remainder of job
 * - Background: vtime fairness using vruntime
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "scx_fresh_shared.h"

char LICENSE[] SEC("license") = "GPL";

/* -----------------------------
 * Minimal helper / compat layer
 * -----------------------------
 *
 * sched_ext kfuncs were renamed across kernel versions (aliases may later vanish).
 * We use weak ksyms + bpf_ksym_exists() to call whichever name exists.
 */

#ifndef __weak
#define __weak __attribute__((weak))
#endif

#ifndef bpf_ksym_exists
#define bpf_ksym_exists(sym) ({ \
    _Static_assert(!__builtin_constant_p(!!sym), #sym " should be marked as __weak"); \
    !!sym; \
})
#endif

#ifndef BPF_STRUCT_OPS
#define BPF_STRUCT_OPS(name, args...) \
    SEC("struct_ops/"#name) \
    BPF_PROG(name, ##args)
#endif

#ifndef BPF_STRUCT_OPS_SLEEPABLE
#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
    SEC("struct_ops.s/"#name) \
    BPF_PROG(name, ##args)
#endif

#ifndef SCX_OPS_DEFINE
#define SCX_OPS_DEFINE(name, ...) \
    SEC(".struct_ops.link") \
    struct sched_ext_ops name = { __VA_ARGS__ };
#endif

/* -----------------------------
 * Kfunc prototypes
 * ----------------------------- */

extern s32  scx_bpf_create_dsq(u64 dsq_id, s32 node) __ksym;
extern void scx_bpf_destroy_dsq(u64 dsq_id) __ksym;

/* CPU selection helper: keep weak and fallback. */
extern s32 scx_bpf_select_cpu_dfl(struct task_struct *p, s32 prev_cpu,
                                  u64 wake_flags, bool *is_idle) __ksym __weak;

/* Time source. */
extern u64 scx_bpf_now(void) __ksym __weak;
static __always_inline u64 scx_now_ns(void)
{
    /* Use monotonic . */
    return bpf_ktime_get_ns();
}

/* dispatch -> dsq_insert */
extern void scx_bpf_dsq_insert(struct task_struct *p, u64 dsq_id, u64 slice,
                               u64 enq_flags) __ksym __weak;
extern void scx_bpf_dispatch(struct task_struct *p, u64 dsq_id, u64 slice,
                             u64 enq_flags) __ksym __weak;
static __always_inline void scx_insert(struct task_struct *p, u64 dsq_id,
                                       u64 slice, u64 enq_flags)
{
    if (bpf_ksym_exists(scx_bpf_dsq_insert))
        scx_bpf_dsq_insert(p, dsq_id, slice, enq_flags);
    else
        scx_bpf_dispatch(p, dsq_id, slice, enq_flags);
}

/* dispatch_vtime -> dsq_insert_vtime */
extern void scx_bpf_dsq_insert_vtime(struct task_struct *p, u64 dsq_id, u64 slice,
                                     u64 vtime, u64 enq_flags) __ksym __weak;
extern void scx_bpf_dispatch_vtime(struct task_struct *p, u64 dsq_id, u64 slice,
                                   u64 vtime, u64 enq_flags) __ksym __weak;
static __always_inline void scx_insert_vtime(struct task_struct *p, u64 dsq_id,
                                             u64 slice, u64 vtime, u64 enq_flags)
{
    if (bpf_ksym_exists(scx_bpf_dsq_insert_vtime))
        scx_bpf_dsq_insert_vtime(p, dsq_id, slice, vtime, enq_flags);
    else
        scx_bpf_dispatch_vtime(p, dsq_id, slice, vtime, enq_flags);
}

/* consume -> dsq_move_to_local */
extern bool scx_bpf_dsq_move_to_local(u64 dsq_id) __ksym __weak;
extern bool scx_bpf_consume(u64 dsq_id) __ksym __weak;
static __always_inline bool scx_move_to_local(u64 dsq_id)
{
    if (bpf_ksym_exists(scx_bpf_dsq_move_to_local))
        return scx_bpf_dsq_move_to_local(dsq_id);
    return scx_bpf_consume(dsq_id);
}

/* -----------------------------
 * Policy configuration
 * ----------------------------- */

#ifndef FRESH_FULL_SWITCH
#define FRESH_FULL_SWITCH 0
#endif

/* DSQ ids (arbitrary but stable). */
#define DSQ_URGENT    0x1A01ULL
#define DSQ_DEADLINE     0xFE01ULL
#define DSQ_BACKGROUND     0xBE01ULL
#define DSQ_STALE  0x5A1EULL

/* Demote tasks that are already past their deadline by this grace period.
 * The loader may set this to zero for a default-off diagnostic A/B.
 */
const volatile __u64 deadline_grace_ns = 1000000ULL; /* 1ms */
/* Default-off service-timing experiment: cap only BE/unhinted insertion.
 * FE (including budget-demoted FE) and the dedicated URGENT path are unchanged.
 */
const volatile __u64 be_slice_cap_ns = 0;

/* Opt-in diagnostic A/B probe, selected by the loader before attachment.
 * Default policy is unchanged. Both variants use the same BPF binary.
 */
const volatile bool urgent_preempt_always = false;
const volatile bool trace_urgent_enqueues = false;
const volatile bool trace_stage_enqueues = false;
const volatile __u32 trace_stage_id = FRESH_STAGE_UNSPECIFIED;
const volatile char trace_worker_name[16] = {};

static __always_inline u64 enqueue_slice_ns(const struct fresh_task_hint *h)
{
    /* Kernel insertion with slice=0 keeps the residual, or uses 1ns if it
     * is exhausted. Translate our API's 0=default to an explicit finite
     * SCX_SLICE_DFL; passing zero does not refill the kernel default.
     * A missing hint uses the same default, including the no-state fallback.
     */
    u64 slice = h && h->slice_ns ? h->slice_ns : SCX_SLICE_DFL;
    bool be = !h || h->class_id == FRESH_CLASS_BACKGROUND;
    if (be && be_slice_cap_ns && slice > be_slice_cap_ns)
        slice = be_slice_cap_ns;
    return slice;
}


/* -----------------------------
 * Maps
 * ----------------------------- */

struct task_state {
    u64 last_start_ns;

    u64 exec_ns_in_job;
    u64 last_job_id;
    u8  overrun; /* budget exceeded for current job */

    u64 vruntime;

    u64 last_reported_deadline_miss_job;
    u64 last_reported_budget_overrun_job;
    u64 last_reported_budget_demotion_job;
    u64 last_reported_stale_job;
    u64 urgent_trace_job;
    u32 urgent_trace_stage;
    u32 urgent_trace_mask;
    u64 trace_insert_dsq;
    u64 trace_insert_ns;
    u64 trace_requested_slice;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u64); /* pid_tgid */
    __type(value, struct fresh_task_hint);
} task_hints SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16384);
    __type(key, u64); /* pid_tgid */
    __type(value, struct task_state);
} task_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB */
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct fresh_urgent_trace_stats);
} urgent_trace_stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct fresh_stage_trace_stats);
} stage_trace_stats SEC(".maps");

/* -----------------------------
 * Helpers
 * ----------------------------- */

static __always_inline u64 task_pid_tgid(const struct task_struct *p)
{
    u32 pid = BPF_CORE_READ(p, pid);
    u32 tgid = BPF_CORE_READ(p, tgid);
    return ((u64)tgid << 32) | pid;
}

static __always_inline struct task_state *get_state(u64 key)
{
    struct task_state *st = bpf_map_lookup_elem(&task_states, &key);
    if (st)
        return st;

    struct task_state init = {};
    init.vruntime = scx_now_ns();
    bpf_map_update_elem(&task_states, &key, &init, BPF_NOEXIST);
    return bpf_map_lookup_elem(&task_states, &key);
}

static __always_inline struct fresh_task_hint *get_hint(u64 key)
{
    struct fresh_task_hint *h = bpf_map_lookup_elem(&task_hints, &key);
    if (!h || h->api_version != FRESH_API_VERSION || h->class_id > FRESH_CLASS_URGENT)
        return NULL;
    return h;
}

static __always_inline u64 safe_age_ns(u64 now_ns, u64 release_ns)
{
    /* Guard underflow for "armed next tick" hints where release may be in the future. */
    if (!release_ns)
        return 0;
    if (now_ns < release_ns)
        return 0;
    return now_ns - release_ns;
}

static __always_inline void emit_evt(u32 kind, u64 key,
                                     const struct fresh_task_hint *h,
                                     const struct task_state *st,
                                     u64 now_ns)
{
    struct fresh_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return;

    e->ts_ns = now_ns;
    e->pid_tgid = key;

    e->stage_id = h ? h->stage_id : FRESH_STAGE_UNSPECIFIED;
    e->kind = kind;

    e->job_id = h ? h->job_id : 0;
    e->release_ts_ns = h ? h->release_ts_ns : 0;
    e->deadline_ts_ns = h ? h->deadline_ts_ns : 0;

    e->exec_ns_in_job = st ? st->exec_ns_in_job : 0;
    e->age_ns = (h) ? safe_age_ns(now_ns, h->release_ts_ns) : 0;

    e->class_id = h ? h->class_id : FRESH_CLASS_BACKGROUND;

    bpf_ringbuf_submit(e, 0);
}

/* Compute effective deadline for FE */
static __always_inline u64 effective_deadline_ns(const struct fresh_task_hint *h, u64 now_ns)
{
    u64 eff = h->deadline_ts_ns;

    /* freshness window bounds the effective deadline */
    if (h->stale_ns && h->release_ts_ns) {
        u64 latest_useful = h->release_ts_ns + h->stale_ns;
        if (!eff || latest_useful < eff)
            eff = latest_useful;
    }

    /* no deadline provided => "run soon" */
    if (!eff)
        eff = now_ns;

    return eff;
}

#include "execution_trace.bpf.h"

/* A lane record only: perf supplies the execution/wait timeline. Unsampled
 * enqueue records expose loss explicitly; this never changes routing or hints.
 */
static __always_inline void trace_stage_enqueue(struct task_struct *p,
                                              struct task_state *st,
                                              u64 flags, u64 dsq)
{
    if (!trace_stage_enqueues)
        return;
    u64 key = task_pid_tgid(p);
    struct fresh_task_hint *h = get_hint(key);
    if (!h || h->stage_id != trace_stage_id)
        return;
    u32 zero = 0;
    struct fresh_stage_trace_stats *s = bpf_map_lookup_elem(&stage_trace_stats, &zero);
    if (!s)
        return;
    s->enqueues++;
    struct fresh_stage_enqueue_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        s->lost++;
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->base.kind = FRESH_EVT_STAGE_ENQUEUE;
    e->base.ts_ns = scx_now_ns();
    e->base.pid_tgid = key;
    e->base.stage_id = h->stage_id;
    e->base.class_id = h->class_id;
    e->base.job_id = h->job_id;
    e->base.release_ts_ns = h->release_ts_ns;
    e->base.deadline_ts_ns = h->deadline_ts_ns;
    e->base.age_ns = safe_age_ns(e->base.ts_ns, h->release_ts_ns);
    e->base.exec_ns_in_job = st ? st->exec_ns_in_job : 0;
    e->enq_flags = flags;
    e->dsq_id = dsq;
    e->slice_ns = enqueue_slice_ns(h);
    e->vruntime = st ? st->vruntime : 0;
    e->policy = BPF_CORE_READ(p, policy);
    e->cpu = bpf_get_smp_processor_id();
    e->overrun = st ? st->overrun : 0;
    e->state_present = !!st;
    bpf_ringbuf_submit(e, 0);
    s->emitted++;
}

static __always_inline void trace_urgent_enqueue(struct task_struct *p,
                                              struct task_state *st,
                                              u64 flags, u64 dsq)
{
    execution_enqueue(p, st, dsq);
    trace_stage_enqueue(p, st, flags, dsq);
    if (!trace_urgent_enqueues)
        return;
    const u64 key = task_pid_tgid(p);
    struct fresh_task_hint *h = get_hint(key);
    if (!h || h->class_id != FRESH_CLASS_URGENT) {
        char comm[16] = {};
        bpf_core_read_str(comm, sizeof(comm), &p->comm);
        if (!trace_worker_name[0] || __builtin_memcmp(comm, (const void *)trace_worker_name, 16))
            return;
    }
    u32 zero = 0;
    struct fresh_urgent_trace_stats *s = bpf_map_lookup_elem(&urgent_trace_stats, &zero);
    if (!s)
        return;
    const u64 now = scx_now_ns();
    bool wakeup = !!(flags & SCX_ENQ_WAKEUP);
    bool late = h && h->deadline_ts_ns && now > h->deadline_ts_ns;
    u32 policy = BPF_CORE_READ(p, policy);
    u32 stage = h ? h->stage_id : FRESH_STAGE_UNSPECIFIED;
    u64 job = h ? h->job_id : 0;
    s->enqueues++;
    if (wakeup) {
        s->wakeup++;
        if (late) s->late_wakeup++;
    } else {
        s->nonwakeup++;
        if (late) s->late_nonwakeup++;
    }
    if (dsq == SCX_DSQ_LOCAL) s->local_preempt++;
    if (dsq == DSQ_URGENT) s->dsq_urgent++;
    if (!h) s->missing_hint++;
    else if (h->class_id != FRESH_CLASS_URGENT) s->wrong_class++;
    if (policy != 7) s->wrong_policy++; /* Linux SCHED_EXT */

    /* Unsampled counters above; at most one ring event per job and
     * (wakeup, late) combination, plus stage changes. Never silently hide loss.
     */
    u32 bit = 1U << ((wakeup ? 1 : 0) + (late ? 2 : 0));
    if (st) {
        if (st->urgent_trace_job != job || st->urgent_trace_stage != stage) {
            st->urgent_trace_job = job;
            st->urgent_trace_stage = stage;
            st->urgent_trace_mask = 0;
        }
        if (st->urgent_trace_mask & bit)
            return;
        st->urgent_trace_mask |= bit;
    }
    struct fresh_urgent_enqueue_evt *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        s->lost++;
        return;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->base.kind = FRESH_EVT_URGENT_ENQUEUE;
    e->base.ts_ns = now;
    e->base.pid_tgid = key;
    e->base.stage_id = stage;
    e->base.job_id = job;
    e->base.release_ts_ns = h ? h->release_ts_ns : 0;
    e->base.deadline_ts_ns = h ? h->deadline_ts_ns : 0;
    e->base.class_id = h ? h->class_id : FRESH_CLASS_BACKGROUND;
    e->base.age_ns = h ? safe_age_ns(now, h->release_ts_ns) : 0;
    e->enq_flags = flags;
    e->dsq_id = dsq;
    e->policy = policy;
    e->cpu = bpf_get_smp_processor_id();
    e->wakeup = wakeup;
    e->late = late;
    e->hint_present = !!h;
    s->emitted++;
    bpf_ringbuf_submit(e, 0);
}

/* -----------------------------
 * sched_ext ops
 * ----------------------------- */

s32 BPF_STRUCT_OPS(scx_fresh_select_cpu, struct task_struct *p,
                   s32 prev_cpu, u64 wake_flags)
{
    bool is_idle = false;

    if (bpf_ksym_exists(scx_bpf_select_cpu_dfl))
        return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

    return prev_cpu;
}

void BPF_STRUCT_OPS(scx_fresh_enqueue, struct task_struct *p, u64 enq_flags)
{
    const u64 now_ns = scx_now_ns();
    const u64 key = task_pid_tgid(p);

    struct task_state *st = get_state(key);
    struct fresh_task_hint *h = get_hint(key);

    if (!st) {
        /* Should be rare (state is created in init_task), but never stall. */
        trace_urgent_enqueue(p, st, enq_flags, DSQ_BACKGROUND);
        scx_insert_vtime(p, DSQ_BACKGROUND, enqueue_slice_ns(h), now_ns, enq_flags);
        return;
    }

    /* Default hint: best-effort with no deadlines. */
    struct fresh_task_hint dh = {};
    if (!h) {
        dh.api_version = FRESH_API_VERSION;
        dh.stage_id = FRESH_STAGE_UNSPECIFIED;
        dh.class_id = FRESH_CLASS_BACKGROUND;
        dh.job_id = 0;
        dh.release_ts_ns = now_ns;
        h = &dh;
    }

    /* Job boundary => reset per-job accounting. */
    if (h->job_id != st->last_job_id) {
        st->exec_ns_in_job = 0;
        st->overrun = 0;
        st->last_job_id = h->job_id;
    }

    u64 slice = enqueue_slice_ns(h);

    /*
     * Urgent service class.
     * - Always route to DSQ_URGENT (highest priority)
     * - Never stale-demote or late-demote (preserved urgent-service exemption)
     * - A wakeup must preempt the currently running lower lane. Merely adding
     *   the task to a custom DSQ does not shorten the current task's slice;
     *   SCX_ENQ_PREEMPT takes effect only for a direct local insertion.
     */
    if (h->class_id == FRESH_CLASS_URGENT) {
        u64 vtime = effective_deadline_ns(h, now_ns);

        if (urgent_preempt_always || (enq_flags & SCX_ENQ_WAKEUP)) {
            trace_urgent_enqueue(p, st, enq_flags, SCX_DSQ_LOCAL);
            scx_insert(p, SCX_DSQ_LOCAL, slice,
                       enq_flags | SCX_ENQ_PREEMPT);
            return;
        }

        trace_urgent_enqueue(p, st, enq_flags, DSQ_URGENT);
        scx_insert_vtime(p, DSQ_URGENT, slice, vtime, enq_flags);
        return;
    }

    /* Executor-owned subscriptions enforce age before admission and callback
     * entry. Age demotion cannot safely revoke that ownership: it can strand
     * the owner before its recheck/return/clear path. Leave those jobs in their
     * normal class, with the same budget demotion below. Unflagged clients keep
     * the existing firm-deadline policy. No queue selection happens here.
     */
    /* Staleness check (guard future release timestamps). */
    bool stale = false;
    if (h->stale_ns && h->release_ts_ns) {
        u64 age = safe_age_ns(now_ns, h->release_ts_ns);
        if (age > h->stale_ns)
            stale = true;
    }

    if (stale && !(h->flags & FRESH_HINT_EXECUTOR_OWNED)) {
        if (st->last_reported_stale_job != h->job_id) {
            emit_evt(FRESH_EVT_STALE_DEMOTION, key, h, st, now_ns);
            st->last_reported_stale_job = h->job_id;
        }
        trace_urgent_enqueue(p, st, enq_flags, DSQ_STALE);
        scx_insert_vtime(p, DSQ_STALE, slice, st->vruntime, enq_flags);
        return;
    }

    /*
     * Firm-ish late demotion:
     * If already past deadline, treat as stale/low priority.
     * (URGENT is exempt above.)
     *
     * Grace avoids flapping around the boundary. Keep the subtraction after
     * now > deadline so the comparison cannot overflow near U64_MAX.
     */
    if (!(h->flags & FRESH_HINT_EXECUTOR_OWNED) &&
        h->deadline_ts_ns && now_ns > h->deadline_ts_ns &&
        now_ns - h->deadline_ts_ns > deadline_grace_ns) {
        if (st->last_reported_deadline_miss_job != h->job_id) {
            emit_evt(FRESH_EVT_DEADLINE_MISS, key, h, st, now_ns);
            st->last_reported_deadline_miss_job = h->job_id;
        }
        trace_urgent_enqueue(p, st, enq_flags, DSQ_STALE);
        scx_insert_vtime(p, DSQ_STALE, slice, st->vruntime, enq_flags);
        return;
    }

    if (h->class_id == FRESH_CLASS_DEADLINE) {
        if (!st->overrun) {
            trace_urgent_enqueue(p, st, enq_flags, DSQ_DEADLINE);
            u64 vtime = effective_deadline_ns(h, now_ns);
            scx_insert_vtime(p, DSQ_DEADLINE, slice, vtime, enq_flags);
            return;
        }

        if (st->last_reported_budget_demotion_job != h->job_id) {
            emit_evt(FRESH_EVT_BUDGET_DEMOTION, key, h, st, now_ns);
            st->last_reported_budget_demotion_job = h->job_id;
        }
    }

    /* BE or FE-overrun => DSQ_BACKGROUND */
    trace_urgent_enqueue(p, st, enq_flags, DSQ_BACKGROUND);
    scx_insert_vtime(p, DSQ_BACKGROUND, slice, st->vruntime, enq_flags);
}

void BPF_STRUCT_OPS(scx_fresh_dispatch, s32 cpu, struct task_struct *prev)
{
    /* Move one task per callback. Pre-filling the local DSQ with lower lanes
     * creates a priority inversion: an URGENT task that wakes afterward cannot
     * jump ahead of already-local FE/BE work.
     */
    if (scx_move_to_local(DSQ_URGENT))
        return;
    if (scx_move_to_local(DSQ_DEADLINE))
        return;
    if (scx_move_to_local(DSQ_BACKGROUND))
        return;
    (void)scx_move_to_local(DSQ_STALE);
}

void BPF_STRUCT_OPS(scx_fresh_running, struct task_struct *p)
{
    u64 key = task_pid_tgid(p);
    struct task_state *st = get_state(key);
    if (!st)
        return;

    st->last_start_ns = scx_now_ns();
    execution_callback(p, FRESH_EXEC_RUNNING, true, 0);
}

void BPF_STRUCT_OPS(scx_fresh_stopping, struct task_struct *p, bool runnable)
{
    const u64 now_ns = scx_now_ns();
    const u64 key = task_pid_tgid(p);

    struct task_state *st = get_state(key);
    struct fresh_task_hint *h = get_hint(key);

    if (!st)
        return;

    if (!st->last_start_ns)
        return;

    u64 delta = now_ns - st->last_start_ns;
    execution_callback(p, FRESH_EXEC_STOPPING, runnable, delta);

    st->exec_ns_in_job += delta;
    st->vruntime += delta;

    /* Budget demotion: if exec exceeds budget, mark overrun for this job. */
    if (h && h->budget_ns && st->exec_ns_in_job > h->budget_ns) {
        st->overrun = 1;
        if (st->last_reported_budget_overrun_job != h->job_id) {
            emit_evt(FRESH_EVT_BUDGET_OVERRUN, key, h, st, now_ns);
            st->last_reported_budget_overrun_job = h->job_id;
        }
    }

    /* Deadline miss: best-effort detection (emit once/job). */
    if (h && h->deadline_ts_ns && now_ns > h->deadline_ts_ns) {
        if (st->last_reported_deadline_miss_job != h->job_id) {
            emit_evt(FRESH_EVT_DEADLINE_MISS, key, h, st, now_ns);
            st->last_reported_deadline_miss_job = h->job_id;
        }
    }

    st->last_start_ns = 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(scx_fresh_init)
{
    /* NUMA node -1 means "any". */
    s32 err;

    err = scx_bpf_create_dsq(DSQ_URGENT, -1);
    if (err)
        return err;

    err = scx_bpf_create_dsq(DSQ_DEADLINE, -1);
    if (err)
        return err;

    err = scx_bpf_create_dsq(DSQ_BACKGROUND, -1);
    if (err)
        return err;

    err = scx_bpf_create_dsq(DSQ_STALE, -1);
    if (err)
        return err;

    return 0;
}

void BPF_STRUCT_OPS(scx_fresh_exit, struct scx_exit_info *ei)
{
    scx_bpf_destroy_dsq(DSQ_URGENT);
    scx_bpf_destroy_dsq(DSQ_DEADLINE);
    scx_bpf_destroy_dsq(DSQ_BACKGROUND);
    scx_bpf_destroy_dsq(DSQ_STALE);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(scx_fresh_init_task, struct task_struct *p,
                             struct scx_init_task_args *args)
{
    u64 key = task_pid_tgid(p);
    struct task_state init = {};
    init.vruntime = scx_now_ns();
    bpf_map_update_elem(&task_states, &key, &init, BPF_ANY);
    return 0;
}

void BPF_STRUCT_OPS(scx_fresh_exit_task, struct task_struct *p,
                    struct scx_exit_task_args *args)
{
    u64 key = task_pid_tgid(p);
    bpf_map_delete_elem(&task_states, &key);
}

/*
 * sched_ext ops table.
 *
 * Default: partial switch (safer). Full switch can be selected by building with FRESH_FULL_SWITCH=1.
 * SCX_OPS_SWITCH_PARTIAL is an enum constant, not a preprocessor macro.
 * Require it at compile time instead of silently falling back to full switch.
 */
SCX_OPS_DEFINE(scx_fresh_ops,
    .select_cpu  = (void *)scx_fresh_select_cpu,
    .enqueue     = (void *)scx_fresh_enqueue,
    .dispatch    = (void *)scx_fresh_dispatch,
    .running     = (void *)scx_fresh_running,
    .stopping    = (void *)scx_fresh_stopping,
    .init        = (void *)scx_fresh_init,
    .exit        = (void *)scx_fresh_exit,
    .init_task   = (void *)scx_fresh_init_task,
    .exit_task   = (void *)scx_fresh_exit_task,
    .name        = "scx_fresh",
#if !FRESH_FULL_SWITCH
    .flags       = (u64)SCX_OPS_SWITCH_PARTIAL,
#endif
);
