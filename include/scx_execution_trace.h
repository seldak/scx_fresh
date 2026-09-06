/* SPDX-License-Identifier: MIT */
#pragma once

/* Diagnostic-only ABI; independent of the application hint ABI. */
enum fresh_execution_kind {
    FRESH_EXEC_SWITCH = 1,
    FRESH_EXEC_WAKEUP = 2,
    FRESH_EXEC_RUNNING = 3,
    FRESH_EXEC_STOPPING = 4,
};

struct fresh_execution_task {
    uint64_t pid_tgid;
    uint64_t slice_ns;
    uint64_t last_insert_dsq;
    uint64_t last_insert_ns;
    uint64_t requested_slice_ns;
    uint32_t policy;
    uint32_t stage;
    char comm[16];
};

struct fresh_execution_evt {
    uint64_t ts_ns;
    uint64_t urgent_pid_tgid;
    uint64_t callback_delta_ns;
    uint64_t prev_state;
    uint64_t syscall_id; /* UINT64_MAX when not in a traced syscall. */
    uint32_t kind;
    uint32_t cpu;
    uint32_t runnable;
    uint32_t preempt;
    struct fresh_execution_task task;
    struct fresh_execution_task next;
};

struct fresh_execution_stats {
    uint64_t emitted;
    uint64_t lost;
    uint64_t identity_conflicts;
};
