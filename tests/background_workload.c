/* SPDX-License-Identifier: GPL-2.0-only */
/* CPU-service probe: all accounting uses the same monotonic measurement window. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "freshqos.h"

#define EXT_POLICY 7
#define NS_PER_MS 1000000ULL
static uint64_t begin, end;
static unsigned worker_cpu;
static pthread_barrier_t prepared;
static struct freshqos qos;
static atomic_int failed;
struct worker {
    const char *name;
    unsigned class_id;
    uint64_t budget;
    uint64_t cpu_ns, chunks, max_gap_ns;
};

static uint64_t clock_ns(clockid_t clock)
{
    struct timespec ts;
    if (clock_gettime(clock, &ts)) abort();
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static void sleep_until(uint64_t ns)
{
    struct timespec ts = {.tv_sec = ns / 1000000000ULL,
                          .tv_nsec = ns % 1000000000ULL};
    int err;
    do { err = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &ts, NULL); }
    while (err == EINTR);
    if (err) abort();
}

static void *run(void *arg)
{
    struct worker *w = arg;
    cpu_set_t cpus;
    CPU_ZERO(&cpus); CPU_SET(worker_cpu, &cpus);
    if (pthread_setaffinity_np(pthread_self(), sizeof(cpus), &cpus)) {
        perror("worker affinity"); atomic_store(&failed, 1);
    }
    pthread_setname_np(pthread_self(), w->name);
    struct fresh_task_hint h = {
        .class_id = w->class_id,
        .job_id = 1, .deadline_ts_ns = w->budget ? begin - 1 : begin,
        .budget_ns = w->budget,
    };
    if (freshqos_publish_hint(&qos, &h)) {
        fprintf(stderr, "publish failed: %s\n", w->name); atomic_store(&failed, 1);
    }
    /* All workers publish before enrollment. Under the disabled policy a
     * Background worker may never start until the loader detaches.
     */
    pthread_barrier_wait(&prepared);
    if (atomic_load(&failed)) return NULL;
    sleep_until(begin - 1000 * NS_PER_MS);
    struct sched_param param = {};
    if (sched_setscheduler(0, EXT_POLICY, &param)) {
        perror("SCHED_EXT"); atomic_store(&failed, 1); return NULL;
    }
    uint64_t previous_wall = clock_ns(CLOCK_MONOTONIC);
    uint64_t previous_cpu = clock_ns(CLOCK_THREAD_CPUTIME_ID);
    uint64_t urgent_release = previous_wall;
    volatile uint64_t value = 1;
    while (previous_wall < end) {
        uint64_t cpu;
        do {
            for (unsigned i = 0; i < 256; i++) value = value * 6364136223846793005ULL + 1;
            cpu = clock_ns(CLOCK_THREAD_CPUTIME_ID);
        } while (cpu - previous_cpu < 100000); /* ~100us CPU per observation */
        uint64_t wall = clock_ns(CLOCK_MONOTONIC);
        uint64_t left = previous_wall > begin ? previous_wall : begin;
        uint64_t right = wall < end ? wall : end;
        if (right > left) {
            /* Boundary observations have at most one chunk of uncertainty;
             * never count CPU that exceeds the overlapping wall interval.
             */
            uint64_t used = cpu - previous_cpu;
            if (used > right - left) used = right - left;
            w->cpu_ns += used;
            w->chunks++;
            if (right - left > w->max_gap_ns) w->max_gap_ns = right - left;
        }
        previous_wall = wall; previous_cpu = cpu;
        if (w->class_id == FRESH_CLASS_URGENT) {
            urgent_release += NS_PER_MS;
            if (urgent_release < wall) urgent_release = wall + NS_PER_MS;
            sleep_until(urgent_release);
        }
    }
    sched_setscheduler(0, SCHED_OTHER, &param);
    freshqos_clear_hint(&qos);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 4) {
        fprintf(stderr, "usage: %s PIN_DIR CPU URGENT_0_OR_1\n", argv[0]);
        return 1;
    }
    worker_cpu = strtoul(argv[2], NULL, 10);
    if (worker_cpu >= CPU_SETSIZE) return 1;
    unsigned count = atoi(argv[3]) ? 4 : 3;
    if (freshqos_open(&qos, argv[1])) return 1;
    struct worker workers[] = {
        {.name="deadline", .class_id=FRESH_CLASS_DEADLINE},
        {.name="background", .class_id=FRESH_CLASS_BACKGROUND},
        {.name="demoted", .class_id=FRESH_CLASS_DEADLINE, .budget=500000},
        {.name="urgent", .class_id=FRESH_CLASS_URGENT},
    };
    /* Give the demoted worker an earlier ordering key so it can exhaust its
     * job budget once before the continuously runnable Deadline competitor.
     * Equal keys otherwise need not alternate in the current Deadline policy.
     */
    pthread_t threads[4];
    begin = clock_ns(CLOCK_MONOTONIC) + 1500 * NS_PER_MS;
    end = begin + 3000 * NS_PER_MS;
    pthread_barrier_init(&prepared, NULL, count + 1);
    for (unsigned i = 0; i < count; i++)
        if (pthread_create(&threads[i], NULL, run, &workers[i])) abort();
    pthread_barrier_wait(&prepared);
    printf("ready begin_ns=%llu end_ns=%llu\n", (unsigned long long)begin,
           (unsigned long long)end);
    fflush(stdout);
    for (unsigned i = 0; i < count; i++) pthread_join(threads[i], NULL);
    for (unsigned i = 0; i < count; i++)
        printf("worker name=%s cpu_ns=%llu chunks=%llu max_gap_ns=%llu\n",
               workers[i].name, (unsigned long long)workers[i].cpu_ns,
               (unsigned long long)workers[i].chunks,
               (unsigned long long)workers[i].max_gap_ns);
    freshqos_close(&qos);
    pthread_barrier_destroy(&prepared);
    return atomic_load(&failed) ? 1 : 0;
}
