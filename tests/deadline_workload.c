/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include "freshqos.h"

static struct freshqos qos;
static unsigned cpu;
static uint64_t begin;
static atomic_uint_fast64_t owner_start, owner_end, arrival_start;
static atomic_int failed;
static pthread_barrier_t prepared;

static uint64_t ns(clockid_t clock)
{
    struct timespec t;
    if (clock_gettime(clock, &t)) abort();
    return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

static void sleep_to(uint64_t target)
{
    struct timespec t = {.tv_sec=target/1000000000ULL, .tv_nsec=target%1000000000ULL};
    int err;
    do { err=clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &t, NULL); } while (err==EINTR);
    if (err) abort();
}

static void *worker(void *arg)
{
    int arrival=*(int *)arg;
    cpu_set_t mask;
    CPU_ZERO(&mask); CPU_SET(cpu, &mask);
    if (pthread_setaffinity_np(pthread_self(), sizeof(mask), &mask)) abort();
    struct fresh_task_hint hint = {
        .class_id=FRESH_CLASS_DEADLINE, .job_id=1,
        .deadline_ts_ns=begin+(arrival ? 50000000ULL : 100000000ULL),
        .slice_ns=20000000ULL,
    };
    if (freshqos_publish_hint(&qos, &hint)) atomic_store(&failed, 1);
    pthread_barrier_wait(&prepared);
    if (atomic_load(&failed)) return NULL;
    struct sched_param param={};
    if (sched_setscheduler(0, 7, &param)) { atomic_store(&failed, 1); return NULL; }
    sleep_to(begin+(arrival ? 3000000ULL : 0));
    if (arrival) {
        atomic_store(&arrival_start, ns(CLOCK_MONOTONIC));
    } else {
        atomic_store(&owner_start, ns(CLOCK_MONOTONIC));
        uint64_t start=ns(CLOCK_THREAD_CPUTIME_ID);
        while (ns(CLOCK_THREAD_CPUTIME_ID)-start < 20000000ULL) {}
        atomic_store(&owner_end, ns(CLOCK_MONOTONIC));
    }
    if (sched_setscheduler(0, SCHED_OTHER, &param)) atomic_store(&failed, 1);
    if (freshqos_clear_hint(&qos)) atomic_store(&failed, 1);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc!=3) { fprintf(stderr, "usage: %s PIN CPU\n", argv[0]); return 2; }
    cpu=strtoul(argv[2], NULL, 10);
    if (cpu>=CPU_SETSIZE || freshqos_open(&qos, argv[1])) return 2;
    begin=ns(CLOCK_MONOTONIC)+500000000ULL;
    pthread_barrier_init(&prepared, NULL, 3);
    pthread_t threads[2]; int args[]={0,1};
    for (unsigned i=0;i<2;i++) if (pthread_create(&threads[i], NULL, worker, &args[i])) abort();
    pthread_barrier_wait(&prepared);
    for (unsigned i=0;i<2;i++) pthread_join(threads[i], NULL);
    uint64_t start=atomic_load(&owner_start), end=atomic_load(&owner_end);
    uint64_t arrival=atomic_load(&arrival_start), release=begin+3000000ULL;
    printf("deadline_preemption: owner_start_ns=%llu owner_end_ns=%llu release_ns=%llu start_ns=%llu\n",
           (unsigned long long)start, (unsigned long long)end,
           (unsigned long long)release, (unsigned long long)arrival);
    freshqos_close(&qos); pthread_barrier_destroy(&prepared);
    /* Require an actual overlapping owner and start well before its 20ms slice ends. */
    return atomic_load(&failed) || !start || start>=release || arrival<release ||
           arrival>=end || arrival-release>5000000ULL;
}
