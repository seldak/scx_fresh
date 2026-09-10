/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * scx_fresh: freshness-aware sched_ext scheduler for application-selected jobs.
 *
 * Policy summary:
 * - Urgent class: always route to DSQ_URGENT (highest priority),
 *   never stale-demote / late-demote. Periodic tasks may "arm" hints with future
 *   release_ts_ns; all age math guards against underflow.
 * - Deadline: EDF-like ordering using DSQ vtime = effective deadline
 * - Expiry and cancellation belong to the application
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
extern struct task_struct *scx_bpf_cpu_curr(s32 cpu) __ksym __weak;

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

/* Default-off service-timing experiment: cap only BE/unhinted insertion.
 * FE (including budget-demoted FE) and the dedicated URGENT path are unchanged.
 */
const volatile __u64 be_slice_cap_ns = 0;
const volatile __u64 background_runtime_ns = 0;
const volatile __u64 background_period_ns = 0;
/* Set by the loader from possible CPUs, not an application tuning parameter. */
const volatile __u32 background_nr_cpus = 1;
#define DSQ_BACKGROUND_CPU_BASE 0x100000000ULL

#include "background_server.h"

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
    u64 job_exec_start;
    u64 last_job_id;
    u8  overrun; /* budget exceeded for current job */

    u64 vruntime;
    u64 background_vruntime;
    u64 background_exec_start;
    u64 background_wall_start;
    u32 background_cpu;
    bool background_member;
    bool background_queued;
    bool background_protected;

    u64 last_reported_deadline_miss_job;
    u64 last_reported_budget_overrun_job;
    u64 last_reported_budget_demotion_job;
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
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1); /* Loader resizes to possible CPUs. */
    __type(key, u32);
    __type(value, struct background_server);
} background_servers SEC(".maps");

struct background_timer {
    struct bpf_timer timer;
    u64 deadline_ns;
    bool active;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1); /* Loader resizes alongside background_servers. */
    __type(key, u32);
    __type(value, struct background_timer);
} background_timers SEC(".maps");

static int background_timer_expired(void *map, u32 *cpu, struct background_timer *t)
{
    if (!t->active)
        return 0;
    /* running may have replaced the slice while an old expiry was pending.
     * CPU pinning serializes this callback with that CPU's scheduling hooks.
     */
    if (scx_now_ns() < t->deadline_ns) {
        int err = bpf_timer_start(&t->timer, t->deadline_ns,
                                  BPF_F_TIMER_ABS | BPF_F_TIMER_CPU_PIN);
        if (err) {
            static char msg[] = "Background timer rearm failed (%d)";
            u64 data[] = {err};
            scx_bpf_error_bstr(msg, data, sizeof(data));
        }
        return 0;
    }
    t->active = false;
    scx_bpf_kick_cpu(*cpu, SCX_KICK_PREEMPT);
    return 0;
}

/* Keep the address-taken map key in a separate verifier frame. Registering
 * an asynchronous callback must not invalidate the caller's loop counter.
 */
static __noinline int init_background_timer(u32 cpu)
{
    struct background_timer *t = bpf_map_lookup_elem(&background_timers, &cpu);
    if (!t)
        return -2;
    int err = bpf_timer_init(&t->timer, &background_timers, 1 /* CLOCK_MONOTONIC */);
    if (err)
        return err;
    return bpf_timer_set_callback(&t->timer, background_timer_expired);
}

static __noinline void stop_background_timer(u32 cpu)
{
    struct background_timer *t = bpf_map_lookup_elem(&background_timers, &cpu);
    if (t)
        t->active = false;
}

static __always_inline void arm_background_timer(struct task_struct *p, bool urgent)
{
    if (!background_period_ns)
        return;
    u32 cpu = scx_bpf_task_cpu(p);
    struct background_timer *t = bpf_map_lookup_elem(&background_timers, &cpu);
    if (!t)
        return;
    t->active = !urgent;
    if (urgent)
        return;
    t->deadline_ns = scx_now_ns() + (p->scx.slice ? p->scx.slice : 1);
    int err = bpf_timer_start(&t->timer, t->deadline_ns,
                              BPF_F_TIMER_ABS | BPF_F_TIMER_CPU_PIN);
    if (err) {
        static char msg[] = "Background timer start failed (%d)";
        u64 data[] = {err};
        scx_bpf_error_bstr(msg, data, sizeof(data));
    }
}

static __always_inline void disarm_background_timer(struct task_struct *p)
{
    if (!background_period_ns)
        return;
    u32 cpu = scx_bpf_task_cpu(p);
    struct background_timer *t = bpf_map_lookup_elem(&background_timers, &cpu);
    if (t)
        t->active = false;
    /* Do not synchronously cancel from a runqueue-locked callback. The
     * pending timer sees inactive, or the next running hook replaces it.
     */
}

static __always_inline struct background_server *background_for_cpu(u32 cpu)
{
    return bpf_map_lookup_elem(&background_servers, &cpu);
}

static __always_inline u64 background_dsq(u32 cpu)
{
    return DSQ_BACKGROUND_CPU_BASE + cpu;
}

static __always_inline u64 task_background_dsq(struct task_struct *p)
{
    return background_period_ns ? background_dsq(scx_bpf_task_cpu(p)) : DSQ_BACKGROUND;
}

static __always_inline void enqueue_background(struct task_struct *p,
                                               struct task_state *st,
                                               u64 slice, u64 flags, u64 now)
{
    if (!background_period_ns) {
        scx_insert_vtime(p, DSQ_BACKGROUND, slice, st ? st->vruntime : now, flags);
        return;
    }
    u32 cpu = scx_bpf_task_cpu(p);
    struct background_server *s = background_for_cpu(cpu);
    u64 vtime = s ? s->vtime : 0;
    if (st) {
        /* A service-class transition joins at the current baseline. Sleeping
         * does not reset membership; clamp sleepers without forgiving debt.
         * Migration joins the destination pool, preserving positive debt.
         */
        if (!st->background_member) {
            st->background_vruntime = vtime;
        } else if (st->background_cpu != cpu) {
            struct background_server *old = background_for_cpu(st->background_cpu);
            u64 old_base = old ? old->vtime : st->background_vruntime;
            u64 debt = st->background_vruntime > old_base ?
                       st->background_vruntime - old_base : 0;
            st->background_vruntime = vtime + debt;
        } else if ((flags & SCX_ENQ_WAKEUP) && st->background_vruntime < vtime) {
            st->background_vruntime = vtime;
        }
        st->background_cpu = cpu;
        st->background_member = true;
        st->background_queued = true;
        vtime = st->background_vruntime;
    }
    scx_insert_vtime(p, background_dsq(cpu), slice, vtime, flags);
}

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
    if (!h || h->class_id > FRESH_CLASS_URGENT ||
        (h->class_id == FRESH_CLASS_DEADLINE && !fresh_hint_has_deadline(h)))
        return NULL;
    return h;
}

static __always_inline void sync_job(struct task_state *st, const struct fresh_task_hint *h)
{
    u64 job = h ? h->job_id : 0;
    if (job != st->last_job_id) {
        st->exec_ns_in_job = 0;
        st->overrun = 0;
        st->last_job_id = job;
    }
}

/* dispatch precedes stopping on a context switch. Checkpoint the server
 * before choosing its next client; stopping charges only the remaining delta.
 */
static __always_inline void account_background(struct task_struct *p,
                                               struct task_state *st, u64 now)
{
    if (!background_period_ns || !st || !st->last_start_ns || !st->background_queued)
        return;
    u64 total = BPF_CORE_READ(p, se.sum_exec_runtime);
    u64 executed = total - st->background_exec_start;
    struct background_server *s = background_for_cpu(scx_bpf_task_cpu(p));
    st->background_vruntime += executed;
    if (s) {
        background_charge(s, st->background_wall_start, now, executed,
                          background_runtime_ns, background_period_ns,
                          st->background_protected);
        struct fresh_task_hint *h = get_hint(task_pid_tgid(p));
        if (h && h->class_id == FRESH_CLASS_DEADLINE)
            s->demoted_cpu_ns += executed;
        else
            s->native_cpu_ns += executed;
    }
    st->background_exec_start = total;
    st->background_wall_start = now;
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

/* Compute the selected job's ordering bound. Zero means unspecified. */
static __always_inline u64 effective_deadline_ns(const struct fresh_task_hint *h, u64 now_ns)
{
    u64 eff = h->deadline_ts_ns;

    /* freshness window bounds the effective deadline */
    if (h->stale_ns && h->release_ts_ns &&
        h->stale_ns <= (u64)-1 - h->release_ts_ns) {
        u64 latest_useful = h->release_ts_ns + h->stale_ns;
        if (!eff || latest_useful < eff)
            eff = latest_useful;
    }

    (void)now_ns;

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

/* Deadline arrivals may displace later Deadline or unprotected Background.
 * Keep the arrival in its DSQ so dispatch still honors Urgent and the server.
 */
static __always_inline void preempt_later_deadline(struct task_struct *p, u64 deadline)
{
    if (!bpf_ksym_exists(scx_bpf_cpu_curr))
        return;
    s32 cpu = scx_bpf_task_cpu(p);
    bpf_rcu_read_lock();
    struct task_struct *current = scx_bpf_cpu_curr(cpu);
    if (current && current != p && BPF_CORE_READ(current, policy) == 7) {
        u64 key = task_pid_tgid(current);
        struct task_state *st = get_state(key);
        struct fresh_task_hint *h = get_hint(key);
        struct background_server *s = background_for_cpu(cpu);
        bool background = !h || h->class_id == FRESH_CLASS_BACKGROUND ||
                          (h->class_id == FRESH_CLASS_DEADLINE && st &&
                           (st->overrun || st->background_queued));
        bool protected = background_period_ns && s && st &&
                         st->background_protected && s->remaining &&
                         scx_now_ns() - s->period_start < background_period_ns;
        if (background && !protected)
            scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
        if (st && h && h->class_id == FRESH_CLASS_DEADLINE &&
            !st->overrun && !st->background_queued &&
            st->last_job_id == h->job_id &&
            (h->deadline_ts_ns || (h->release_ts_ns && h->stale_ns)) &&
            deadline < effective_deadline_ns(h, scx_now_ns()))
            scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
    }
    bpf_rcu_read_unlock();
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

    if (!h) {
        struct fresh_task_hint *raw = bpf_map_lookup_elem(&task_hints, &key);
        if (raw &&
            raw->class_id == FRESH_CLASS_DEADLINE && !fresh_hint_has_deadline(raw))
            emit_evt(FRESH_EVT_INVALID_DEADLINE, key, raw, st, now_ns);
    }

    if (!st) {
        /* Should be rare (state is created in init_task), but never stall. */
        trace_urgent_enqueue(p, st, enq_flags, task_background_dsq(p));
        enqueue_background(p, st, enqueue_slice_ns(h), enq_flags, now_ns);
        return;
    }

    /* Default hint: best-effort with no deadlines. */
    struct fresh_task_hint dh = {};
    if (!h) {
        dh.stage_id = FRESH_STAGE_UNSPECIFIED;
        dh.class_id = FRESH_CLASS_BACKGROUND;
        dh.job_id = 0;
        dh.release_ts_ns = now_ns;
        h = &dh;
    }

    /* Job boundary => reset per-job accounting. */
    sync_job(st, h);

    u64 slice = enqueue_slice_ns(h);
    st->background_queued = false;

    /*
     * Urgent service class.
     * - Always route to DSQ_URGENT (highest priority)
     * - A wakeup must preempt the currently running lower lane. Merely adding
     *   the task to a custom DSQ does not shorten the current task's slice;
     *   SCX_ENQ_PREEMPT takes effect only for a direct local insertion.
     */
    if (h->class_id == FRESH_CLASS_URGENT) {
        st->background_member = false;
        u64 vtime = effective_deadline_ns(h, now_ns);
        if (!vtime)
            vtime = now_ns; /* Preserve unspecified Urgent queue ordering. */

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

    /* Time bounds order service; only the application decides whether a job
     * remains useful. In particular, a late owner must still be able to reach
     * its completion/cancellation path. CPU-budget demotion remains separate.
     */
    if (h->class_id == FRESH_CLASS_DEADLINE) {
        if (!st->overrun) {
            st->background_member = false;
            trace_urgent_enqueue(p, st, enq_flags, DSQ_DEADLINE);
            u64 vtime = effective_deadline_ns(h, now_ns);
            scx_insert_vtime(p, DSQ_DEADLINE, slice, vtime, enq_flags);
            if ((enq_flags & SCX_ENQ_WAKEUP) &&
                (h->deadline_ts_ns || (h->release_ts_ns && h->stale_ns)))
                preempt_later_deadline(p, vtime);
            return;
        }

        if (st->last_reported_budget_demotion_job != h->job_id) {
            emit_evt(FRESH_EVT_BUDGET_DEMOTION, key, h, st, now_ns);
            st->last_reported_budget_demotion_job = h->job_id;
        }
    }

    /* BE or FE-overrun => DSQ_BACKGROUND */
    trace_urgent_enqueue(p, st, enq_flags, task_background_dsq(p));
    enqueue_background(p, st, slice, enq_flags, now_ns);
}

/* The shared Deadline DSQ can contain work pinned to other CPUs. */
static __always_inline bool deadline_waiting_on(u32 cpu)
{
    struct bpf_iter_scx_dsq it;
    struct task_struct *p;
    bool waiting = false;
    bpf_iter_scx_dsq_new(&it, DSQ_DEADLINE, 0);
    while ((p = bpf_iter_scx_dsq_next(&it))) {
        if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
            waiting = true;
            break;
        }
    }
    bpf_iter_scx_dsq_destroy(&it);
    return waiting;
}

/* Compare only the first Background entry with runnable prev. */
static __always_inline bool background_prefer_previous(u64 dsq, struct task_state *st)
{
    struct bpf_iter_scx_dsq it;
    bpf_iter_scx_dsq_new(&it, dsq, 0);
    struct task_struct *head = bpf_iter_scx_dsq_next(&it);
    bool prefer = !head || st->background_vruntime < BPF_CORE_READ(head, scx.dsq_vtime);
    bpf_iter_scx_dsq_destroy(&it);
    return prefer;
}

/* prev is not in the DSQ yet. Compare it with the first CPU-eligible peer. */
static __always_inline bool deadline_prefer_previous(s32 cpu, u64 deadline)
{
    struct bpf_iter_scx_dsq it;
    struct task_struct *p;
    bool prefer = true;
    bpf_iter_scx_dsq_new(&it, DSQ_DEADLINE, 0);
    while ((p = bpf_iter_scx_dsq_next(&it))) {
        if (bpf_cpumask_test_cpu(cpu, p->cpus_ptr)) {
            prefer = deadline < BPF_CORE_READ(p, scx.dsq_vtime);
            break;
        }
    }
    bpf_iter_scx_dsq_destroy(&it);
    return prefer;
}

static __always_inline void keep_background(struct task_struct *p, struct task_state *st,
                                            struct background_server *s, bool protected)
{
    s->protect_next = protected;
    st->background_protected = protected;
    p->scx.slice = background_slice(s, enqueue_slice_ns(get_hint(task_pid_tgid(p))), true);
    u64 boundary = background_period_ns - scx_now_ns() % background_period_ns;
    if (p->scx.slice > boundary)
        p->scx.slice = boundary;
    arm_background_timer(p, false);
}

void BPF_STRUCT_OPS(scx_fresh_dispatch, s32 cpu, struct task_struct *prev)
{
    struct task_state *pst = prev ? get_state(task_pid_tgid(prev)) : NULL;
    struct fresh_task_hint *ph = prev ? get_hint(task_pid_tgid(prev)) : NULL;
    if (prev)
        account_background(prev, pst, scx_now_ns());
    bool runnable = prev && (prev->scx.flags & SCX_TASK_QUEUED);
    bool urgent = runnable && ph && ph->class_id == FRESH_CLASS_URGENT;
    bool deadline = runnable && ph && ph->class_id == FRESH_CLASS_DEADLINE &&
                    pst && !pst->overrun;
    /* Budget enforcement remains at the next enqueue. A spent current job
     * must yield once so stopping/enqueue can perform that transition.
     */
    if (deadline && ph->budget_ns && pst->last_start_ns &&
        pst->exec_ns_in_job + BPF_CORE_READ(prev, se.sum_exec_runtime) - pst->job_exec_start > ph->budget_ns)
        deadline = false;

    /* Move one task per callback. Pre-filling the local DSQ with lower lanes
     * creates a priority inversion: an URGENT task that wakes afterward cannot
     * jump ahead of already-local FE/BE work.
     */
    if (scx_move_to_local(DSQ_URGENT))
        return;
    if (urgent) {
        prev->scx.slice = enqueue_slice_ns(ph);
        arm_background_timer(prev, true);
        return;
    }
    if (background_period_ns) {
        struct background_server *s = background_for_cpu(cpu);
        if (s) {
            background_refresh(s, scx_now_ns(), background_runtime_ns, background_period_ns);
            s->protect_next = false;
            if (s->remaining) {
                bool protected = deadline || deadline_waiting_on(cpu);
                if (runnable && pst && pst->background_queued &&
                    background_prefer_previous(background_dsq(cpu), pst)) {
                    keep_background(prev, pst, s, protected);
                    return;
                }
                if (scx_move_to_local(background_dsq(cpu))) {
                    s->protect_next = protected;
                    return;
                }
            }
        }
        if ((!deadline || !deadline_prefer_previous(cpu, effective_deadline_ns(ph, scx_now_ns()))) &&
            scx_move_to_local(DSQ_DEADLINE))
            return;
        if (deadline) {
            prev->scx.slice = enqueue_slice_ns(ph);
            u64 boundary = background_period_ns - scx_now_ns() % background_period_ns;
            if (prev->scx.slice > boundary)
                prev->scx.slice = boundary;
            arm_background_timer(prev, false);
            return;
        }
        if (s && runnable && pst && pst->background_queued &&
            background_prefer_previous(background_dsq(cpu), pst)) {
            keep_background(prev, pst, s, false);
            return;
        }
        if (!scx_move_to_local(background_dsq(cpu)) && pst)
            pst->background_protected = false;
        return;
    }
    if ((!deadline || !deadline_prefer_previous(cpu, effective_deadline_ns(ph, scx_now_ns()))) &&
        scx_move_to_local(DSQ_DEADLINE))
        return;
    if (deadline) {
        prev->scx.slice = enqueue_slice_ns(ph);
        return;
    }
    (void)scx_move_to_local(DSQ_BACKGROUND);
}

void BPF_STRUCT_OPS(scx_fresh_running, struct task_struct *p)
{
    u64 key = task_pid_tgid(p);
    struct task_state *st = get_state(key);
    if (!st)
        return;

    st->last_start_ns = scx_now_ns();
    st->job_exec_start = BPF_CORE_READ(p, se.sum_exec_runtime);
    /* Enrollment can reach running before enqueue. Establish identity now
     * so the first later enqueue cannot erase already-executed job time.
     */
    struct fresh_task_hint *h = get_hint(key);
    sync_job(st, h);
    if (background_period_ns) {
        /* stopping can run remotely; use the task's CPU, never the callback's. */
        u32 cpu = scx_bpf_task_cpu(p);
        struct background_server *s = background_for_cpu(cpu);
        st->background_exec_start = BPF_CORE_READ(p, se.sum_exec_runtime);
        st->background_wall_start = st->last_start_ns;
        if (s) {
            background_refresh(s, st->last_start_ns, background_runtime_ns, background_period_ns);
            /* A native Background task can also enter directly on enrollment.
             * It must be charged even if enqueue has not classified it yet.
             */
            if ((!h || h->class_id == FRESH_CLASS_BACKGROUND) && !st->background_member) {
                st->background_member = true;
                st->background_queued = true;
                st->background_cpu = cpu;
                st->background_vruntime = s->vtime;
            }
            if (st->background_queued && st->background_vruntime > s->vtime)
                s->vtime = st->background_vruntime;
            st->background_protected = st->background_queued && s->protect_next;
            if (!h || h->class_id != FRESH_CLASS_URGENT) {
                u64 slice = background_slice(s, p->scx.slice,
                                            st->background_queued);
                u64 boundary = background_period_ns -
                               (st->last_start_ns - s->period_start);
                p->scx.slice = slice < boundary ? slice : boundary;
            }
        }
    }
    arm_background_timer(p, h && h->class_id == FRESH_CLASS_URGENT);
    execution_callback(p, FRESH_EXEC_RUNNING, true, 0);
}

void BPF_STRUCT_OPS(scx_fresh_stopping, struct task_struct *p, bool runnable)
{
    disarm_background_timer(p);
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

    u64 cpu_delta = BPF_CORE_READ(p, se.sum_exec_runtime) - st->job_exec_start;
    st->exec_ns_in_job += cpu_delta;
    st->vruntime += cpu_delta;
    account_background(p, st, now_ns);

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
    if (background_period_ns) {
        if (!background_runtime_ns || background_runtime_ns > background_period_ns)
            return -22;
        for (u32 cpu = 0; cpu < background_nr_cpus; cpu++) {
            s32 ret = scx_bpf_create_dsq(background_dsq(cpu), -1);
            if (ret)
                return ret;
            ret = init_background_timer(cpu);
            if (ret)
                return ret;
        }
    }
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

    return 0;
}

void BPF_STRUCT_OPS(scx_fresh_exit, struct scx_exit_info *ei)
{
    if (background_period_ns) {
        for (u32 cpu = 0; cpu < background_nr_cpus; cpu++) {
            stop_background_timer(cpu);
        }
    }
    scx_bpf_destroy_dsq(DSQ_URGENT);
    scx_bpf_destroy_dsq(DSQ_DEADLINE);
    scx_bpf_destroy_dsq(DSQ_BACKGROUND);
}

s32 BPF_STRUCT_OPS_SLEEPABLE(scx_fresh_init_task, struct task_struct *p,
                             struct scx_init_task_args *args)
{
    u64 key = task_pid_tgid(p);
    struct task_state init = {};
    init.vruntime = scx_now_ns();
    int err = bpf_map_update_elem(&task_states, &key, &init, BPF_ANY);
    /* Server accounting requires a state slot for every enrolled worker. */
    if (background_period_ns && err)
        return err;
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
