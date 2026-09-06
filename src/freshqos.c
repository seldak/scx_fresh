/* SPDX-License-Identifier: MIT */
#include "freshqos.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/limits.h>

#include <bpf/bpf.h>

uint64_t freshqos_pid_tgid_self(void)
{
    uint32_t tgid = (uint32_t)getpid();
    uint32_t tid  = (uint32_t)syscall(SYS_gettid);
    return ((uint64_t)tgid << 32) | tid;
}


int freshqos_open(struct freshqos *q, const char *pin_dir)
{
    if (!q || !pin_dir)
        return -EINVAL;

    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s/task_hints", pin_dir);

    q->map_fd = bpf_obj_get(path);
    if (q->map_fd < 0) {
        fprintf(stderr, "freshqos_open: bpf_obj_get(%s) failed: %s\n",
                path, strerror(errno));
        return -errno;
    }
    return 0;
}

void freshqos_close(struct freshqos *q)
{
    if (!q)
        return;
    if (q->map_fd >= 0)
        close(q->map_fd);
    q->map_fd = -1;
}

int freshqos_publish_hint(struct freshqos *q, const struct fresh_task_hint *hint)
{
    if (!q || q->map_fd < 0 || !hint ||
        hint->api_version != FRESH_API_VERSION || hint->class_id > FRESH_CLASS_URGENT)
        return -EINVAL;

    uint64_t key = freshqos_pid_tgid_self();
    int err = bpf_map_update_elem(q->map_fd, &key, hint, BPF_ANY);
    if (err) {
        fprintf(stderr, "freshqos_publish_hint: update failed: %s\n", strerror(errno));
        return -errno;
    }
    return 0;
}

int freshqos_publish_hint_for(struct freshqos *q, uint64_t pid_tgid, const struct fresh_task_hint *hint)
{
    if (!q || q->map_fd < 0 || !hint || !pid_tgid ||
        hint->api_version != FRESH_API_VERSION || hint->class_id > FRESH_CLASS_URGENT)
        return -EINVAL;

    uint64_t key = pid_tgid;
    int err = bpf_map_update_elem(q->map_fd, &key, hint, BPF_ANY);
    if (err) {
        fprintf(stderr, "freshqos_publish_hint_for: update failed: %s\n", strerror(errno));
        return -errno;
    }
    return 0;
}

int freshqos_publish_job(struct freshqos *q,
                        uint32_t stage_id,
                        uint32_t class_id,
                        uint64_t job_id,
                        uint64_t release_ts_ns,
                        uint64_t deadline_ts_ns,
                        uint64_t stale_ns,
                        uint64_t budget_ns,
                        uint64_t slice_ns,
                        uint32_t weight)
{
    struct fresh_task_hint h = {};
    h.api_version = FRESH_API_VERSION;
    h.stage_id = stage_id;
    h.class_id = class_id;
    h.job_id = job_id;
    h.release_ts_ns = release_ts_ns;
    h.deadline_ts_ns = deadline_ts_ns;
    h.stale_ns = stale_ns;
    h.budget_ns = budget_ns;
    h.slice_ns = slice_ns;
    h.weight = weight;
    return freshqos_publish_hint(q, &h);
}
int freshqos_clear_hint(struct freshqos *q)
{
    struct fresh_task_hint h = {};
    h.api_version = FRESH_API_VERSION;
    h.stage_id = FRESH_STAGE_UNSPECIFIED;
    h.class_id = FRESH_CLASS_BACKGROUND;
    h.job_id = 0;
    h.release_ts_ns = 0;
    h.deadline_ts_ns = 0;
    h.stale_ns = 0;
    h.budget_ns = 0;
    h.slice_ns = 0;
    h.weight = 0;
    return freshqos_publish_hint(q, &h);
}
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
                           uint32_t weight)
{
    struct fresh_task_hint h = {};
    h.api_version = FRESH_API_VERSION;
    h.stage_id = stage_id;
    h.class_id = class_id;
    h.job_id = job_id;
    h.release_ts_ns = release_ts_ns;
    h.deadline_ts_ns = deadline_ts_ns;
    h.stale_ns = stale_ns;
    h.budget_ns = budget_ns;
    h.slice_ns = slice_ns;
    h.weight = weight;
    return freshqos_publish_hint_for(q, pid_tgid, &h);
}
