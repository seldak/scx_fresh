/* SPDX-License-Identifier: MIT */
/*
 * Shared types between BPF and userspace.
 *
 * Keep this file small and stable: it's part of the "API surface" of the project.
 */

#pragma once

#ifdef __VMLINUX_H__
/* BPF side: vmlinux.h is included first, so use kernel types and avoid libc typedefs. */
typedef __u8  uint8_t;
typedef __u16 uint16_t;
typedef __u32 uint32_t;
typedef __u64 uint64_t;
#else
/* Userspace side */
#include <stdint.h>
#endif

#include "scx_execution_trace.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Scheduling class hint (userspace -> BPF). */
enum fresh_service_class : uint32_t {
    FRESH_CLASS_BACKGROUND = 0,  /* best-effort / background */
    FRESH_CLASS_DEADLINE   = 1,  /* effective-deadline ordering */
    FRESH_CLASS_URGENT     = 2,  /* dedicated queue and wakeup preemption */
};

/* Stage identity is application-defined and diagnostic only. */
#define FRESH_STAGE_UNSPECIFIED ((uint32_t)~0U)
#define FRESH_API_VERSION 1U

struct fresh_task_hint {
    uint32_t stage_id;         /* application-defined diagnostic identity */
    uint32_t class_id;         /* enum fresh_service_class */
    uint32_t flags;            /* reserved; publish zero */
    uint32_t api_version;      /* wire ABI; freshqos fills FRESH_API_VERSION */

    uint64_t job_id;           /* monotonic per stage/thread */
    uint64_t release_ts_ns;    /* when job became ready (CLOCK_MONOTONIC) */
    uint64_t deadline_ts_ns;   /* absolute deadline; 0 => none */
    uint64_t stale_ns;         /* relative ordering bound; 0 => none */

    uint64_t budget_ns;        /* 0 => no budget enforcement */
    uint64_t slice_ns;         /* 0 => scheduler default */

    uint32_t weight;           /* BE fairness weight; 0 => default */
    uint32_t _pad;
};

/* A relative bound must not wrap the monotonic timestamp. */
static inline int fresh_hint_has_deadline(const struct fresh_task_hint *h)
{
    return h->deadline_ts_ns ||
        (h->release_ts_ns && h->stale_ns &&
         h->stale_ns <= (uint64_t)-1 - h->release_ts_ns);
}

/* Events (BPF -> userspace). */
enum fresh_evt_kind : uint32_t {
    FRESH_EVT_DEADLINE_MISS   = 1,
    FRESH_EVT_BUDGET_OVERRUN  = 2,
    /* Event ID 3 was age demotion and is no longer emitted. */
    FRESH_EVT_BUDGET_DEMOTION = 4,
    FRESH_EVT_URGENT_ENQUEUE    = 5, /* Extended diagnostic record below. */
    FRESH_EVT_STAGE_ENQUEUE    = 6, /* Opt-in lane attribution alongside perf sched. */
    FRESH_EVT_INVALID_DEADLINE = 7,
};

struct fresh_evt {
    uint64_t ts_ns;
    uint64_t pid_tgid;

    uint32_t stage_id;
    uint32_t kind;

    uint64_t job_id;

    uint64_t release_ts_ns;
    uint64_t deadline_ts_ns;

    uint64_t exec_ns_in_job;
    uint64_t age_ns;

    uint32_t class_id;
    uint32_t _pad;
};

/* Optional probe: base event layout remains unchanged for existing readers. */
struct fresh_urgent_enqueue_evt {
    struct fresh_evt base;
    uint64_t enq_flags;
    uint64_t dsq_id;
    uint32_t policy;
    uint32_t cpu;
    uint32_t wakeup;
    uint32_t late;
    uint32_t hint_present;
    uint32_t _pad;
};

#define FRESH_URGENT_COUNTER_FIELDS(X) \
    X(enqueues) X(wakeup) X(nonwakeup) X(late_wakeup) X(late_nonwakeup) \
    X(local_preempt) X(dsq_urgent) X(missing_hint) X(wrong_class) X(wrong_policy) \
    X(emitted) X(lost)

struct fresh_urgent_trace_stats {
#define FRESH_COUNTER_FIELD(name) uint64_t name;
    FRESH_URGENT_COUNTER_FIELDS(FRESH_COUNTER_FIELD)
#undef FRESH_COUNTER_FIELD
};

struct fresh_stage_enqueue_evt {
    struct fresh_evt base;
    uint64_t enq_flags;
    uint64_t dsq_id;
    uint64_t slice_ns;
    uint64_t vruntime;
    uint32_t policy;
    uint32_t cpu;
    uint32_t overrun;
    uint32_t state_present;
};

struct fresh_stage_trace_stats {
    uint64_t enqueues;
    uint64_t emitted;
    uint64_t lost;
};

#ifdef __cplusplus
}
#endif
