/* SPDX-License-Identifier: GPL-2.0-only */
/* Opt-in observations only. No dispatch, slice, or scheduling-state mutation. */
const volatile int execution_trace_cpu = -1;
static u64 execution_urgent_key;
static u64 execution_syscall_id = ~0ULL;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 23);
} execution_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct fresh_execution_stats);
} execution_stats SEC(".maps");

static __always_inline void execution_enqueue(struct task_struct *p,
                                               struct task_state *st, u64 dsq)
{
    if (execution_trace_cpu < 0)
        return;
    u64 key = task_pid_tgid(p);
    struct fresh_task_hint *h = get_hint(key);
    if (st) {
        st->trace_insert_dsq = dsq;
        st->trace_insert_ns = scx_now_ns();
        st->trace_requested_slice = h ? h->slice_ns : 0;
    }
    char comm[16] = {};
    bpf_core_read_str(comm, sizeof(comm), &p->comm);
    if (!trace_worker_name[0] || __builtin_memcmp(comm, (const void *)trace_worker_name, 16))
        return;
    if (!execution_urgent_key)
        execution_urgent_key = key;
    else if (execution_urgent_key != key) {
        u32 zero = 0;
        struct fresh_execution_stats *s = bpf_map_lookup_elem(&execution_stats, &zero);
        if (s) s->identity_conflicts++;
    }
}

static __always_inline void execution_task(struct fresh_execution_task *out,
                                            struct task_struct *p)
{
    out->pid_tgid = task_pid_tgid(p);
    out->policy = BPF_CORE_READ(p, policy);
    bpf_core_read_str(out->comm, sizeof(out->comm), &p->comm);
    out->stage = FRESH_STAGE_UNSPECIFIED;
    if (out->policy != 7)
        return;
    out->slice_ns = BPF_CORE_READ(p, scx.slice);
    struct fresh_task_hint *h = get_hint(out->pid_tgid);
    if (h) out->stage = h->stage_id;
    struct task_state *st = bpf_map_lookup_elem(&task_states, &out->pid_tgid);
    if (st) {
        out->last_insert_dsq = st->trace_insert_dsq;
        out->last_insert_ns = st->trace_insert_ns;
        out->requested_slice_ns = st->trace_requested_slice;
    }
}

static __always_inline struct fresh_execution_evt *execution_reserve(u32 kind)
{
    u32 zero = 0;
    struct fresh_execution_stats *s = bpf_map_lookup_elem(&execution_stats, &zero);
    if (!s) return NULL;
    struct fresh_execution_evt *e = bpf_ringbuf_reserve(&execution_events, sizeof(*e), 0);
    if (!e) {
        s->lost++;
        return NULL;
    }
    __builtin_memset(e, 0, sizeof(*e));
    e->ts_ns = scx_now_ns();
    e->kind = kind;
    e->cpu = bpf_get_smp_processor_id();
    e->urgent_pid_tgid = execution_urgent_key;
    e->syscall_id = execution_syscall_id;
    s->emitted++;
    return e;
}

static __always_inline void execution_callback(struct task_struct *p, u32 kind,
                                                bool runnable, u64 delta)
{
    if (execution_trace_cpu < 0 || !execution_urgent_key ||
        task_pid_tgid(p) != execution_urgent_key)
        return;
    struct fresh_execution_evt *e = execution_reserve(kind);
    if (!e) return;
    execution_task(&e->task, p);
    e->runnable = runnable;
    e->callback_delta_ns = delta;
    bpf_ringbuf_submit(e, 0);
}

/* Raw sched_switch arguments are preempt, prev, next, prev_state. Use the
 * saved tracepoint state, not prev->__state (which a concurrent wake can alter).
 * A preempted task is runnable even when its raw state is nonzero.
 */
SEC("raw_tp/sched_switch")
int trace_execution_switch(struct bpf_raw_tracepoint_args *ctx)
{
    if (execution_trace_cpu < 0 || bpf_get_smp_processor_id() != execution_trace_cpu)
        return 0;
    struct task_struct *prev = (void *)ctx->args[1];
    struct task_struct *next = (void *)ctx->args[2];
    struct fresh_execution_evt *e = execution_reserve(FRESH_EXEC_SWITCH);
    if (!e) return 0;
    execution_task(&e->task, prev);
    execution_task(&e->next, next);
    e->prev_state = ctx->args[3];
    e->preempt = !!ctx->args[0];
    e->runnable = e->preempt || !e->prev_state;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("raw_tp/sched_wakeup")
int trace_execution_wakeup(struct bpf_raw_tracepoint_args *ctx)
{
    struct task_struct *p = (void *)ctx->args[0];
    if (execution_trace_cpu < 0 || !execution_urgent_key || task_pid_tgid(p) != execution_urgent_key)
        return 0;
    struct fresh_execution_evt *e = execution_reserve(FRESH_EXEC_WAKEUP);
    if (!e) return 0;
    execution_task(&e->task, p);
    e->runnable = 1;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* Record the enclosing syscall number, not arguments or user data. This
 * separates nanosleep/futex/other blocking without collecting kernel stacks.
 */
SEC("raw_tp/sys_enter")
int trace_execution_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    if (execution_trace_cpu >= 0 && execution_urgent_key && bpf_get_current_pid_tgid() == execution_urgent_key)
        execution_syscall_id = ctx->args[1];
    return 0;
}

SEC("raw_tp/sys_exit")
int trace_execution_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    if (execution_trace_cpu >= 0 && execution_urgent_key && bpf_get_current_pid_tgid() == execution_urgent_key)
        execution_syscall_id = ~0ULL;
    return 0;
}
