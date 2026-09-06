/* SPDX-License-Identifier: MIT */
#pragma once

#include <stdint.h>
#include "scx_fresh_shared.h"

#ifdef __cplusplus
extern "C" {
#endif

struct freshqos {
    int map_fd;
};

/* PID/TID packed key used by the BPF map (tgid<<32 | tid). */
uint64_t freshqos_pid_tgid_self(void);

/* Open pinned maps under pin_dir (expects task_hints pinned at pin_dir/task_hints). */
int freshqos_open(struct freshqos *q, const char *pin_dir);

/* Close map fds. */
void freshqos_close(struct freshqos *q);

/* Publish/overwrite the hint for the current thread (pid/tgid key). */
int freshqos_publish_hint(struct freshqos *q, const struct fresh_task_hint *hint);

/* Publish/overwrite the hint for an explicit pid/tgid key (used for producer-driven hinting). */
int freshqos_publish_hint_for(struct freshqos *q, uint64_t pid_tgid, const struct fresh_task_hint *hint);

/* Clear current thread's hint (sets to BE/MISC with job_id=0). */
int freshqos_clear_hint(struct freshqos *q);

/* Convenience helper: build and publish a hint. */
int freshqos_publish_job(struct freshqos *q,
                        uint32_t stage_id,
                        uint32_t class_id,
                        uint64_t job_id,
                        uint64_t release_ts_ns,
                        uint64_t deadline_ts_ns,
                        uint64_t stale_ns,
                        uint64_t budget_ns,
                        uint64_t slice_ns,
                        uint32_t weight);

/* Convenience helper: build+publish a hint for a specific pid_tgid. */
int freshqos_publish_job_for(struct freshqos *q,
                           uint64_t pid_tgid,
                           uint32_t stage_id,
                           uint32_t class_id,
                           uint64_t job_id,
                           uint64_t release_ts_ns,
                           uint64_t deadline_ts_ns,
                           uint64_t stale_ns,
                           uint64_t budget_ns,
                           uint64_t slice_ns,
                           uint32_t weight);

#ifdef __cplusplus
}
#endif
