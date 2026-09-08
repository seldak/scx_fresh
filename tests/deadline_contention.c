/* SPDX-License-Identifier: GPL-2.0-only */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "freshqos.h"

#define MS 1000000ULL
#define ROUNDS 3
static struct freshqos qos;
static unsigned cpu, count;
static uint64_t epoch;
static pthread_barrier_t ready;
struct sample { uint64_t release, start, end, cpu; };
struct worker {
    const char *name;
    unsigned cls;
    uint64_t offset, deadline, work, budget;
    struct sample samples[ROUNDS];
};
static struct worker workers[] = {
    {.name="owner", .cls=1, .deadline=70, .work=20},
    {.name="earlier", .cls=1, .offset=3, .deadline=40, .work=1},
    {.name="equal", .cls=1, .offset=3, .deadline=70, .work=1},
    {.name="later", .cls=1, .offset=3, .deadline=90, .work=1},
    {.name="demoted", .cls=1, .deadline=30, .work=6, .budget=1},
    {.name="background", .cls=0, .work=6},
    {.name="urgent", .cls=2, .offset=5, .work=1},
};
static uint64_t now(clockid_t id)
{
    struct timespec t;
    if (clock_gettime(id, &t)) abort();
    return (uint64_t)t.tv_sec*1000000000ULL+t.tv_nsec;
}
static void until(uint64_t ns)
{
    struct timespec t={.tv_sec=ns/1000000000ULL, .tv_nsec=ns%1000000000ULL};
    int e;
    do { e=clock_nanosleep(CLOCK_MONOTONIC,TIMER_ABSTIME,&t,NULL); } while(e==EINTR);
    if(e) abort();
}
static void *run(void *arg)
{
    struct worker *w=arg;
    cpu_set_t mask; CPU_ZERO(&mask); CPU_SET(cpu,&mask);
    if(pthread_setaffinity_np(pthread_self(),sizeof(mask),&mask)) abort();
    pthread_setname_np(pthread_self(),w->name);
    for(unsigned r=0;r<ROUNDS;r++) {
        uint64_t base=epoch+r*150*MS;
        struct fresh_task_hint h={.class_id=w->cls,.job_id=r+1,
            .release_ts_ns=base+w->offset*MS,
            .deadline_ts_ns=base+w->deadline*MS,
            .budget_ns=w->budget*MS,.slice_ns=(w->budget?1:20)*MS};
        if(freshqos_publish_hint(&qos,&h)) abort();
        if(!r) {
            pthread_barrier_wait(&ready);
            struct sched_param p={};
            if(sched_setscheduler(0,7,&p)) abort();
        }
        until(h.release_ts_ns);
        struct sample *s=&w->samples[r];
        s->release=h.release_ts_ns;
        s->start=now(CLOCK_MONOTONIC);
        uint64_t c=now(CLOCK_THREAD_CPUTIME_ID);
        while(now(CLOCK_THREAD_CPUTIME_ID)-c<w->work*MS) {}
        s->cpu=now(CLOCK_THREAD_CPUTIME_ID)-c;
        s->end=now(CLOCK_MONOTONIC);
    }
    struct sched_param p={};
    if(sched_setscheduler(0,SCHED_OTHER,&p) || freshqos_clear_hint(&qos)) abort();
    return NULL;
}
int main(int argc,char **argv)
{
    if(argc!=4) return 2;
    char *end;
    unsigned long c=strtoul(argv[2],&end,10);
    if(*end || c>=CPU_SETSIZE) return 2;
    cpu=c;
    count=argv[3][0]=='1'?7:4;
    if(freshqos_open(&qos,argv[1])) return 2;
    epoch=now(CLOCK_MONOTONIC)+500*MS;
    pthread_barrier_init(&ready,NULL,count+1);
    pthread_t threads[7];
    for(unsigned i=0;i<count;i++) if(pthread_create(&threads[i],NULL,run,&workers[i])) abort();
    pthread_barrier_wait(&ready);
    for(unsigned i=0;i<count;i++) pthread_join(threads[i],NULL);
    for(unsigned r=0;r<ROUNDS;r++) for(unsigned i=0;i<count;i++) {
        struct sample *s=&workers[i].samples[r];
        printf("job name=%s job=%u release=%llu start=%llu end=%llu cpu=%llu\n",
            workers[i].name,r+1,(unsigned long long)s->release,
            (unsigned long long)s->start,(unsigned long long)s->end,(unsigned long long)s->cpu);
    }
    freshqos_close(&qos);
    pthread_barrier_destroy(&ready);
    return 0;
}
