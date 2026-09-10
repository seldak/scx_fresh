# SPDX-License-Identifier: GPL-2.0-only
"""Run production server helpers and scheduler hooks with controlled clocks/CPU."""
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
import importlib.util

from test_service_classes import ROOT, SOURCE, function

PREAMBLE = r'''
#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "scx_fresh_shared.h"
typedef uint64_t u64;
typedef uint8_t u8;
typedef uint32_t u32;
typedef int32_t s32;
#define BPF_STRUCT_OPS(name, ...) name(__VA_ARGS__)
#define BPF_CORE_READ(p, field) ((p)->field)
#define SCX_ENQ_WAKEUP 1
#define SCX_ENQ_PREEMPT 2
#define SCX_DSQ_LOCAL 99
#define SCX_SLICE_DFL 20000000ULL
#define SCX_TASK_QUEUED 1
#define SCX_KICK_PREEMPT 1
#define BPF_F_TIMER_ABS 1
#define BPF_F_TIMER_CPU_PIN 2
#include "background_server.h"
DSQS
STATE
struct bpf_timer { u64 expires; };
TIMERTYPE
struct cpumask { unsigned bits; };
struct task_struct {
    unsigned id, cpu, policy;
    struct cpumask *cpus_ptr;
    struct { u64 slice, flags, dsq_vtime; } scx;
    struct { u64 sum_exec_runtime; } se;
};
static struct task_state states[4];
static struct task_struct *cpu_current;
#define bpf_ksym_exists(fn) true
static void bpf_rcu_read_lock(void) {}
static void bpf_rcu_read_unlock(void) {}
static struct task_struct *scx_bpf_cpu_curr(s32 cpu) { (void)cpu; return cpu_current; }
static struct fresh_task_hint hints[4];
static struct background_server servers[2];
static struct background_timer timers[2];
static int background_servers, background_timers, task_hints;
static unsigned kicks;
static int timer_error, reported_timer_error;
static int bpf_timer_start(struct bpf_timer *timer, u64 expiry, u64 flags) {
    assert(flags==(BPF_F_TIMER_ABS | BPF_F_TIMER_CPU_PIN));
    timer->expires=expiry; return timer_error;
}
static void scx_bpf_kick_cpu(u32 cpu, u64 flags) {
    assert(cpu<2 && flags==SCX_KICK_PREEMPT); kicks++;
}
static void scx_bpf_error_bstr(char *msg, void *data, u32 size) {
    assert(data && size==sizeof(u64));
    reported_timer_error=(int)*(u64 *)data;
}
static u64 now, destination, moved, inserted_slice, inserted_order;
static bool urgent_ready, deadline_ready, background_ready;
static struct task_struct queued_head;
static struct task_struct deadline_head;
static struct cpumask deadline_cpus;
/* Persistent queues for callback-lifecycle tests. The current task is absent
 * until stopping/enqueue; dispatch may retain it without either callback. */
static bool model;
static struct task_struct *model_tasks[4], *selected;
static u64 model_dsqs[4];
static struct task_struct *model_head(u64 dsq) {
    struct task_struct *head=NULL;
    for (unsigned i=0; i<4; i++) {
        struct task_struct *p=model_tasks[i];
        if (p && model_dsqs[i]==dsq &&
            (!head || p->scx.dsq_vtime < head->scx.dsq_vtime)) head=p;
    }
    return head;
}
struct bpf_iter_scx_dsq { unsigned index; u64 dsq; };
static int bpf_iter_scx_dsq_new(struct bpf_iter_scx_dsq *it, u64 dsq, u64 flags) {
    it->index=0; it->dsq=dsq; return 0;
}
static struct task_struct *bpf_iter_scx_dsq_next(struct bpf_iter_scx_dsq *it) {
    if (it->index++) return NULL;
    if (model) return model_head(it->dsq);
    if (it->dsq==DSQ_DEADLINE) return deadline_ready ? &deadline_head : NULL;
    return background_ready ? &queued_head : NULL;
}
static void bpf_iter_scx_dsq_destroy(struct bpf_iter_scx_dsq *it) {}
static bool bpf_cpumask_test_cpu(u32 cpu, const struct cpumask *mask) {
    return !!(mask->bits & (1U << cpu));
}
static u64 background_period_ns, background_runtime_ns, be_slice_cap_ns;
static bool urgent_preempt_always;
static void *bpf_map_lookup_elem(void *map, const void *key) {
    if (map == &background_timers) return &timers[*(const u32 *)key];
    if (map == &background_servers) {
        u32 cpu = *(const u32 *)key;
        assert(cpu < 2); return &servers[cpu];
    }
    assert(map == &task_hints);
    return &hints[*(const u64 *)key];
}
static u64 scx_now_ns(void) { return now; }
static u64 task_pid_tgid(struct task_struct *p) { return p->id; }
static u32 scx_bpf_task_cpu(struct task_struct *p) { return p->cpu; }
static struct task_state *get_state(u64 key) { return &states[key]; }
#define trace_urgent_enqueue(...) ((void)0)
#define execution_callback(p, event, runnable, delta) ((void)(delta))
#define emit_evt(...) ((void)0)
static void scx_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags) {
    destination=dsq; inserted_slice=slice; p->scx.slice=slice;
    if (model) { model_tasks[p->id]=p; model_dsqs[p->id]=dsq; }
}
static void scx_insert_vtime(struct task_struct *p, u64 dsq, u64 slice, u64 vtime, u64 flags) {
    scx_insert(p, dsq, slice, flags); inserted_order=vtime;
    p->scx.dsq_vtime=vtime;
}
static bool scx_move_to_local(u64 dsq) {
    if (model) {
        struct task_struct *p=model_head(dsq);
        if (!p) return false;
        selected=p; model_dsqs[p->id]=0; return true;
    }
    bool ready = dsq==DSQ_URGENT ? urgent_ready :
                 dsq==DSQ_DEADLINE ? deadline_ready : background_ready;
    if (ready) moved=dsq;
    return ready;
}
FUNCTIONS
static void reset(void) {
    memset(states, 0, sizeof(states)); memset(hints, 0, sizeof(hints));
    memset(servers, 0, sizeof(servers));
    memset(timers, 0, sizeof(timers)); kicks=0;
    timer_error=reported_timer_error=0;
    now=1000; background_runtime_ns=20; background_period_ns=100;
    urgent_ready=false; deadline_ready=true; background_ready=true;
    queued_head=(struct task_struct){};
    deadline_cpus.bits=3; deadline_head.cpus_ptr=&deadline_cpus;
    servers[0].protect_next=servers[1].protect_next=true;
    for (unsigned i=0; i<4; i++) {
        hints[i].deadline_ts_ns=1000000;
        hints[i].class_id=FRESH_CLASS_BACKGROUND;
        hints[i].job_id=1;
    }
}
static void execute(struct task_struct *p, u64 cpu, u64 wall) {
    scx_fresh_running(p);
    p->se.sum_exec_runtime+=cpu; now+=wall;
    scx_fresh_stopping(p, true);
}
'''

CASES = {
    "deadline_previous_competes_by_deadline": r'''
        for (unsigned enabled=0; enabled<2; enabled++) {
            reset(); background_period_ns=enabled?100:0; background_ready=false;
            struct task_struct p={.scx.flags=SCX_TASK_QUEUED};
            hints[0].class_id=FRESH_CLASS_DEADLINE; hints[0].deadline_ts_ns=1500;
            deadline_head.scx.dsq_vtime=1600; moved=0;
            scx_fresh_dispatch(0,&p); assert(!moved && p.scx.slice);
            deadline_head.scx.dsq_vtime=1400; moved=0;
            scx_fresh_dispatch(0,&p); assert(moved==DSQ_DEADLINE);
            deadline_head.scx.dsq_vtime=1500; moved=0;
            scx_fresh_dispatch(0,&p); assert(moved==DSQ_DEADLINE);
        }
    ''',
    "job_budget_excludes_interrupt_wall_time": r'''
        reset(); struct task_struct p={};
        hints[0].class_id=FRESH_CLASS_DEADLINE; hints[0].budget_ns=10;
        execute(&p,4,1000); assert(states[0].exec_ns_in_job==4 && !states[0].overrun);
        execute(&p,7,1000); assert(states[0].exec_ns_in_job==11 && states[0].overrun);
    ''',
    "funded_background_is_not_preempted": r'''
        reset(); struct task_struct arrival={}, owner={.id=1,.policy=7}; cpu_current=&owner;
        hints[0].class_id=FRESH_CLASS_DEADLINE;
        states[1].background_queued=true; states[1].background_protected=true;
        servers[0].remaining=20; servers[0].period_start=now;
        scx_fresh_enqueue(&arrival,SCX_ENQ_WAKEUP); assert(kicks==0);
        servers[0].remaining=0;
        scx_fresh_enqueue(&arrival,SCX_ENQ_WAKEUP); assert(kicks==1);
    ''',
    "deadline_wakeup_preempts_only_later_eligible_deadline": r'''
        reset(); struct task_struct arrival={}, owner={.id=1, .policy=7};
        cpu_current=&owner;
        hints[0].class_id=hints[1].class_id=FRESH_CLASS_DEADLINE;
        hints[0].deadline_ts_ns=1500; hints[1].deadline_ts_ns=1600;
        states[1].last_job_id=1;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP);
        assert(kicks==1 && destination==DSQ_DEADLINE);
        kicks=0; scx_fresh_enqueue(&arrival, 0); assert(!kicks);
        hints[1].deadline_ts_ns=1500;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(!kicks);
        hints[1].deadline_ts_ns=1400;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(!kicks);
        hints[1].deadline_ts_ns=1600;
        hints[0].deadline_ts_ns=0;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(!kicks);
        hints[0].deadline_ts_ns=1500; hints[1].deadline_ts_ns=0;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(kicks==1); kicks=0;
        hints[1].deadline_ts_ns=1600;
        hints[1].class_id=FRESH_CLASS_URGENT;
        states[1].overrun=true;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(!kicks);
        states[1].overrun=false;
        hints[1].class_id=FRESH_CLASS_BACKGROUND;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(kicks==1); kicks=0;
        hints[1].class_id=FRESH_CLASS_DEADLINE; states[1].overrun=true;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(kicks==1); kicks=0;
        states[1].overrun=false; states[1].background_queued=true;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(kicks==1); kicks=0;
        states[1].background_queued=false; owner.policy=0;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(!kicks);
        owner.policy=7; hints[1].job_id=2;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(!kicks);
        cpu_current=NULL;
        scx_fresh_enqueue(&arrival, SCX_ENQ_WAKEUP); assert(!kicks);
    ''',
    "successive_jobs_rejoin_background_without_refilling_server": r'''
        struct task_struct native={}, deadline={.id=1}; reset();
        hints[1].class_id=FRESH_CLASS_DEADLINE; hints[1].budget_ns=5;
        for (unsigned job=1; job<=8; job++) {
            now=1000+(job-1)*100;
            hints[1].job_id=job;
            scx_fresh_enqueue(&native, 0); execute(&native, 10, 10);
            u64 remaining=servers[0].remaining;
            u64 native_vtime=states[0].background_vruntime;
            assert(remaining==10);
            scx_fresh_enqueue(&deadline, 0);
            assert(destination==DSQ_DEADLINE && !states[1].overrun);
            assert(!states[1].background_member && states[1].exec_ns_in_job==0);
            assert(servers[0].remaining==remaining);
            execute(&deadline, 8, 8);
            assert(states[1].overrun && servers[0].remaining==remaining);
            u64 join=servers[0].vtime;
            scx_fresh_enqueue(&deadline, 0);
            assert(destination==background_dsq(0) && inserted_order==join);
            execute(&deadline, 5, 5);
            assert(states[1].overrun && states[1].exec_ns_in_job==13);
            assert(servers[0].remaining==5);
            assert(states[0].background_vruntime==native_vtime);
            assert(servers[0].native_cpu_ns==job*10);
            assert(servers[0].demoted_cpu_ns==job*5);
        }
    ''',
    "repeated_urgent_bursts_cross_periods_without_spending_background": r'''
        struct task_struct background={}, urgent={.id=1}; reset();
        hints[1].class_id=FRESH_CLASS_URGENT; hints[1].budget_ns=1;
        for (unsigned burst=1; burst<=8; burst++) {
            now=1000+(burst-1)*300;
            scx_fresh_enqueue(&background, 0); execute(&background, 5, 5);
            u64 charged=servers[0].cpu_ns;
            u64 fairness=states[0].background_vruntime;
            hints[1].job_id=burst;
            scx_fresh_enqueue(&urgent, SCX_ENQ_WAKEUP);
            assert(destination==SCX_DSQ_LOCAL);
            execute(&urgent, 120, 120);
            assert(!timers[0].active);
            assert(servers[0].cpu_ns==charged);
            assert(states[0].background_vruntime==fairness);
            scx_fresh_enqueue(&urgent, SCX_ENQ_WAKEUP);
            assert(destination==SCX_DSQ_LOCAL); // Urgent remains exempt from demotion.
            scx_fresh_enqueue(&background, 0); scx_fresh_running(&background);
            assert(servers[0].remaining==20); // Missed allocation does not accumulate.
            assert(background.scx.slice==20 && timers[0].active);
            background.se.sum_exec_runtime+=20; now+=20;
            scx_fresh_stopping(&background, true);
            assert(servers[0].cpu_ns==burst*25 && !servers[0].remaining);
            assert(!servers[0].debt_ns && !servers[1].cpu_ns);
        }
    ''',
    "timer_failure_reports_nonnull_diagnostic": r'''
        reset(); struct task_struct p={.scx.slice=20}; u32 cpu=0;
        timer_error=-22;
        arm_background_timer(&p, false);
        assert(reported_timer_error==-22);
        reported_timer_error=0;
        background_timer_expired(NULL, &cpu, &timers[0]);
        assert(reported_timer_error==-22 && !kicks);
    ''',
    "timer_handles_replacement_urgent_and_idle": r'''
        reset(); struct task_struct p={.scx.slice=20}; u32 cpu=0;
        arm_background_timer(&p, false);
        assert(timers[0].active && timers[0].timer.expires==1020);
        now=1010; p.scx.slice=30; arm_background_timer(&p, false);
        now=1020; background_timer_expired(NULL, &cpu, &timers[0]);
        assert(!kicks && timers[0].timer.expires==1040);
        arm_background_timer(&p, true);
        now=1040; background_timer_expired(NULL, &cpu, &timers[0]);
        assert(!kicks); // A pending lower-class expiry cannot kick Urgent.
        arm_background_timer(&p, false); disarm_background_timer(&p);
        now=1070; background_timer_expired(NULL, &cpu, &timers[0]);
        assert(!kicks); // No periodic timer work while the CPU is idle.
        arm_background_timer(&p, false); now=1100;
        background_timer_expired(NULL, &cpu, &timers[0]);
        assert(kicks==1 && !timers[0].active);
        background_period_ns=0; arm_background_timer(&p, false);
        assert(!timers[0].active);
    ''',
    "continuous_queue_lifecycle": r'''
        for (unsigned tickless=0; tickless<2; tickless++) {
        for (unsigned phase=0; phase<10; phase++) {
        reset(); model=true;
        memset(model_tasks, 0, sizeof(model_tasks));
        memset(model_dsqs, 0, sizeof(model_dsqs));
        background_runtime_ns=2000000; background_period_ns=10000000;
        now=1000000000+phase*100003;
        struct task_struct tasks[3]={};
        for (unsigned i=0; i<3; i++) {
            tasks[i].id=i; tasks[i].cpus_ptr=&deadline_cpus;
            tasks[i].scx.flags=SCX_TASK_QUEUED;
        }
        hints[0].class_id=FRESH_CLASS_DEADLINE;
        hints[2].class_id=FRESH_CLASS_DEADLINE;
        hints[2].budget_ns=500000;
        states[2].last_job_id=1; states[2].overrun=1;
        for (unsigned i=0; i<3; i++) scx_fresh_enqueue(&tasks[i], 0);
        scx_fresh_dispatch(0, NULL);
        struct task_struct *current=selected;
        scx_fresh_running(current);
        u64 measured[3]={};
        for (unsigned tick=0; tick<4000; tick++) {
            u64 elapsed=1000000;
            now+=elapsed; current->se.sum_exec_runtime+=elapsed;
            if (tick>=1000) measured[current->id]+=elapsed;
            current->scx.slice=current->scx.slice>elapsed ?
                               current->scx.slice-elapsed : 0;
            if (tickless) {
                // No scheduler tick: a slice reaching zero is not itself a
                // scheduling event. Only the explicit server timer kicks.
                if (!timers[0].active || now<timers[0].timer.expires) continue;
                u32 cpu=0; unsigned before=kicks;
                background_timer_expired(NULL, &cpu, &timers[0]);
                if (kicks==before) continue;
                current->scx.slice=0;
            }
            if (current->scx.slice) continue;
            selected=NULL; scx_fresh_dispatch(0, current);
            now+=500;
            current->se.sum_exec_runtime+=500;
            if (selected && !current->scx.slice) {
                scx_fresh_stopping(current, true);
                scx_fresh_enqueue(current, 0);
                current=selected;
                scx_fresh_running(current);
            }
        }
        assert(measured[1]+measured[2]>=590000000);
        assert(measured[1]+measured[2]<=610000000);
        assert(measured[1]>=290000000 && measured[1]<=310000000);
        assert(measured[2]>=290000000 && measured[2]<=310000000);
        }
        }
    ''',
    "foreign_cpu_deadline_does_not_charge_spare_debt": r'''
        reset(); deadline_cpus.bits=2;
        assert(!deadline_waiting_on(0) && deadline_waiting_on(1));
        scx_fresh_dispatch(0, NULL);
        assert(moved==background_dsq(0) && !servers[0].protect_next);
        struct task_struct p={}; scx_fresh_enqueue(&p, 0); execute(&p, 30, 30);
        assert(servers[0].spare_cpu_ns==30 && servers[0].debt_ns==0);
    ''',
    "repeated_tick_overshoot_does_not_accumulate_bandwidth": r'''
        struct background_server s={};
        for (u64 i=0; i<300; i++) {
            u64 start=1000+i*100;
            background_refresh(&s, start, 20, 100);
            u64 executed=s.remaining+10; // Simulated late slice expiration.
            background_charge(&s, start, start+executed, executed, 20, 100, true);
        }
        assert(s.cpu_ns==6010 && s.debt_ns==10);
        assert(s.excess_ns-s.repaid_ns==s.debt_ns);
    ''',
    "protected_overshoot_is_repaid_without_spare_debt": r'''
        struct background_server s={};
        background_refresh(&s, 1000, 20, 100);
        background_charge(&s, 1000, 1030, 30, 20, 100, true);
        assert(s.remaining==0 && s.debt_ns==10 && s.excess_ns==10);
        background_refresh(&s, 1100, 20, 100);
        assert(s.remaining==10 && s.debt_ns==0 && s.repaid_ns==10);
        background_charge(&s, 1100, 1130, 30, 20, 100, false);
        assert(s.remaining==0 && s.debt_ns==0 && s.spare_cpu_ns==30);
        background_refresh(&s, 1200, 20, 100);
        assert(s.remaining==20);
        background_charge(&s, 1200, 1280, 80, 20, 100, true);
        assert(s.debt_ns==60);
        background_refresh(&s, 1500, 20, 100);
        assert(s.debt_ns==0 && s.remaining==0 && s.repaid_ns==70);
        background_refresh(&s, 1600, 20, 100); assert(s.remaining==20);
    ''',
    "old_interval_overshoot_not_erased_by_boundary": r'''
        struct background_server s={};
        background_refresh(&s, 1000, 20, 100);
        background_charge(&s, 1000, 1105, 105, 20, 100, true);
        assert(s.cpu_ns==105 && s.remaining==0);
        assert(s.debt_ns==65 && s.repaid_ns==20);
        background_refresh(&s, 1500, 20, 100);
        assert(s.debt_ns==0 && s.remaining==15);
    ''',
    "previous_background_competes_by_service_not_queue_presence": r'''
        struct task_struct p={.scx.flags=SCX_TASK_QUEUED}; reset();
        scx_fresh_enqueue(&p, 0); states[0].background_vruntime=10;
        queued_head.scx.dsq_vtime=30;
        moved=0; scx_fresh_dispatch(0, &p);
        assert(!moved && p.scx.slice==20); // Less-served current beats queued peer.
        states[0].background_vruntime=31;
        scx_fresh_dispatch(0, &p); assert(moved==background_dsq(0));
        // Continuous contenders keep their service deficit on re-enqueue.
        servers[0].vtime=100; states[0].background_vruntime=31;
        scx_fresh_enqueue(&p, 0); assert(inserted_order==31);
        scx_fresh_enqueue(&p, SCX_ENQ_WAKEUP); assert(inserted_order==100);
        // The same fairness comparison applies during spare service.
        servers[0].remaining=0; deadline_ready=false;
        queued_head.scx.dsq_vtime=200; moved=0;
        scx_fresh_dispatch(0, &p); assert(!moved && !states[0].background_protected);
    ''',
    "direct_background_enrollment_is_charged": r'''
        struct task_struct p={}; reset(); p.scx.slice=SCX_SLICE_DFL;
        execute(&p, 10, 10);
        assert(servers[0].cpu_ns==10 && servers[0].remaining==10);
        assert(states[0].background_vruntime==10);
    ''',
    "kernel_dispatch_precedes_stopping": r'''
        struct task_struct p={.scx.flags=SCX_TASK_QUEUED}; reset();
        scx_fresh_enqueue(&p, 0); scx_fresh_running(&p);
        now+=20; p.se.sum_exec_runtime+=20;
        // The kernel chooses next before stopping current, unlike our first model.
        scx_fresh_dispatch(0, &p);
        assert(moved==DSQ_DEADLINE && servers[0].remaining==0);
        assert(servers[0].cpu_ns==20 && states[0].background_vruntime==20);
        scx_fresh_stopping(&p, true);
        assert(servers[0].cpu_ns==20 && states[0].background_vruntime==20);
    ''',
    "runnable_previous_deadline_precedes_spare_background": r'''
        struct task_struct p={.scx.flags=SCX_TASK_QUEUED}; reset();
        hints[0].class_id=FRESH_CLASS_DEADLINE;
        deadline_ready=false; // Current task is NOT in the Deadline DSQ yet.
        scx_fresh_enqueue(&p, 0); scx_fresh_running(&p);
        now+=20; p.se.sum_exec_runtime+=20; servers[0].remaining=0;
        moved=0; scx_fresh_dispatch(0, &p);
        assert(!moved && p.scx.slice>0);
        background_period_ns=0; p.scx.slice=0;
        scx_fresh_dispatch(0, &p); assert(!moved && p.scx.slice>0);
        hints[0].budget_ns=5; scx_fresh_dispatch(0, &p);
        assert(moved==DSQ_BACKGROUND); // Let stopping/enqueue enforce the budget.
    ''',
    "enrollment_before_first_enqueue_keeps_job_accounting": r'''
        struct task_struct p={}; reset();
        hints[0].class_id=FRESH_CLASS_DEADLINE; hints[0].budget_ns=5;
        p.scx.slice=SCX_SLICE_DFL;
        execute(&p, 9, 9); // First running can occur without enqueue on enrollment.
        assert(states[0].overrun && states[0].exec_ns_in_job==9);
        scx_fresh_enqueue(&p, 0);
        assert(states[0].overrun && states[0].exec_ns_in_job==9);
        assert(destination==background_dsq(0));
    ''',
    "continuous_deadline_contention": r'''
        struct task_struct workers[3]={{.id=0}, {.id=1}, {.id=2}};
        reset(); hints[2].class_id=FRESH_CLASS_DEADLINE;
        for (unsigned i=0; i<3; i++) scx_fresh_enqueue(&workers[i], 0);
        while (now < 2000) {
            scx_fresh_dispatch(0, NULL);
            unsigned selected = 2;
            if (moved==background_dsq(0))
                selected=states[0].background_vruntime <= states[1].background_vruntime ? 0 : 1;
            struct task_struct *p=&workers[selected];
            scx_fresh_running(p);
            u64 granted=p->scx.slice;
            assert(granted && now+granted<=2000);
            now+=granted; p->se.sum_exec_runtime+=granted;
            scx_fresh_stopping(p, true); scx_fresh_enqueue(p, 0);
        }
        assert(workers[0].se.sum_exec_runtime==100);
        assert(workers[1].se.sum_exec_runtime==100);
        assert(workers[2].se.sum_exec_runtime==800);
        assert(servers[0].cpu_ns==200);
    ''',
    "dispatch_precedence_and_spare_capacity": r'''
        struct task_struct p={}; reset();
        scx_fresh_dispatch(0, &p); assert(moved==background_dsq(0));
        urgent_ready=true; scx_fresh_dispatch(0, &p); assert(moved==DSQ_URGENT);
        assert(servers[0].remaining==20);
        urgent_ready=false; servers[0].remaining=0;
        scx_fresh_dispatch(0, &p); assert(moved==DSQ_DEADLINE);
        deadline_ready=false; scx_fresh_dispatch(0, &p); assert(moved==background_dsq(0));
        background_period_ns=0; deadline_ready=true;
        scx_fresh_dispatch(0, &p); assert(moved==DSQ_DEADLINE);
        deadline_ready=false; scx_fresh_dispatch(0, &p); assert(moved==DSQ_BACKGROUND);
    ''',
    "actual_cpu_charging_and_urgent_interruption": r'''
        struct task_struct p={}, urgent={.id=1}; reset();
        scx_fresh_enqueue(&p, 0); execute(&p, 5, 8);
        assert(servers[0].remaining==15 && servers[0].cpu_ns==5);
        hints[1].class_id=FRESH_CLASS_URGENT;
        scx_fresh_enqueue(&urgent, SCX_ENQ_WAKEUP);
        scx_fresh_running(&urgent); assert(urgent.scx.slice==SCX_SLICE_DFL);
        urgent.se.sum_exec_runtime+=10; now+=10;
        scx_fresh_stopping(&urgent, true);
        assert(servers[0].remaining==15 && servers[0].cpu_ns==5);
        scx_fresh_enqueue(&p, 0); execute(&p, 15, 15);
        assert(!servers[0].remaining && servers[0].cpu_ns==20);
        scx_fresh_dispatch(0, &p); assert(moved==DSQ_DEADLINE);
        // Both job and server accounting exclude the three interrupt-time units.
        assert(states[0].exec_ns_in_job==20);
    ''',
    "slice_bounds_and_period_replenishment": r'''
        struct task_struct p={}; reset();
        scx_fresh_enqueue(&p, 0); scx_fresh_running(&p);
        assert(p.scx.slice==20);
        p.se.sum_exec_runtime=23; now+=23; scx_fresh_stopping(&p, true);
        assert(servers[0].remaining==0 && servers[0].excess_ns==3);
        now=1095; hints[0].class_id=FRESH_CLASS_DEADLINE;
        scx_fresh_enqueue(&p, 0); scx_fresh_running(&p);
        assert(p.scx.slice==5); // Reconsider the funded pool at replenishment.
        now=1100; scx_fresh_dispatch(0, &p);
        assert(servers[0].remaining==17 && moved==background_dsq(0));
        now=1500; scx_fresh_dispatch(0, &p);
        assert(servers[0].remaining==20); // No credit for unused periods.
        assert(servers[1].remaining==0); // Independent CPU allocation.
        scx_fresh_dispatch(1, &p); assert(servers[1].remaining==20);
    ''',
    "cross_boundary_charge_and_spare_execution": r'''
        struct task_struct p={}; reset(); now=1095;
        scx_fresh_enqueue(&p, 0); scx_fresh_running(&p);
        assert(p.scx.slice==5);
        now=1103; p.se.sum_exec_runtime=8; scx_fresh_stopping(&p, true);
        assert(servers[0].remaining==17 && servers[0].cpu_ns==8);
        servers[0].remaining=0;
        servers[0].protect_next=false;
        scx_fresh_enqueue(&p, 0); scx_fresh_running(&p);
        assert(p.scx.slice==97); // Spare execution isn't given a 1ns slice.
        now+=4; p.se.sum_exec_runtime+=4; scx_fresh_stopping(&p, true);
        assert(servers[0].remaining==0 && servers[0].cpu_ns==12);
    ''',
    "demotion_and_server_do_not_refill_job_budget": r'''
        struct task_struct p={}; reset();
        hints[0].class_id=FRESH_CLASS_DEADLINE; hints[0].budget_ns=5;
        scx_fresh_enqueue(&p, 0); execute(&p, 8, 8);
        assert(states[0].overrun && servers[0].cpu_ns==0);
        servers[0].vtime=100;
        scx_fresh_enqueue(&p, 0);
        assert(destination==background_dsq(0) && inserted_order==100);
        execute(&p, 10, 10);
        assert(states[0].overrun && states[0].exec_ns_in_job==18);
        now=1100; scx_fresh_dispatch(0, &p);
        assert(servers[0].remaining==20 && states[0].overrun);
        assert(states[0].exec_ns_in_job==18);
        scx_fresh_enqueue(&p, 0); assert(destination==background_dsq(0));
        hints[0].job_id++; scx_fresh_enqueue(&p, 0);
        assert(destination==DSQ_DEADLINE && !states[0].overrun);
        assert(states[0].exec_ns_in_job==0 && !states[0].background_member);
    ''',
    "fair_join_sleep_and_migration": r'''
        struct task_struct p={}, other={.id=1}; reset(); servers[0].vtime=100;
        states[0].vruntime=10000000; // Old Deadline execution is irrelevant.
        scx_fresh_enqueue(&p, 0); assert(inserted_order==100);
        execute(&p, 10, 10); assert(states[0].background_vruntime==110);
        scx_fresh_enqueue(&other, 0); assert(inserted_order==100);
        // Sleeping and changing a native Background job ID do not forgive debt.
        hints[0].job_id++; scx_fresh_enqueue(&p, SCX_ENQ_WAKEUP);
        assert(inserted_order==110);
        servers[0].vtime=200; scx_fresh_enqueue(&p, SCX_ENQ_WAKEUP);
        assert(inserted_order==200); // No unbounded sleeper credit either.
        states[0].background_vruntime=220; servers[1].vtime=1000;
        p.cpu=1; scx_fresh_enqueue(&p, 0); assert(inserted_order==1020);
        execute(&p, 5, 5);
        assert(servers[1].cpu_ns==5 && servers[0].cpu_ns==10);
        assert(states[0].background_vruntime==1025);
    ''',
}


class LoadedGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "background_probe", ROOT / "scripts/test_background_server.py")
        cls.probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.probe)

    def check(self, native, demoted, gap=18_000_000):
        self.probe.validate_service("test",
            {"background": native, "demoted": demoted},
            {"background": gap, "demoted": gap}, 3_000_000_000)

    def test_balanced_allocation_passes(self):
        self.check(300_038_048, 299_973_212)

    def test_old_progress_only_pass_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "allocation"):
            self.check(116_137_000, 327_573_000)

    def test_correct_pool_total_cannot_hide_unfairness(self):
        with self.assertRaisesRegex(RuntimeError, "unbalanced"):
            self.check(450_000_000, 150_000_000)

    def test_correct_totals_cannot_hide_long_gaps(self):
        with self.assertRaisesRegex(RuntimeError, "gap"):
            self.check(300_000_000, 300_000_000, 1_024_000_000)


class BackgroundServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.directory.name) / "server"
        program = PREAMBLE.replace("DSQS", "\n".join(re.findall(r"^#define DSQ_.*", SOURCE, re.M)))
        program = program.replace("STATE", re.search(r"struct task_state \{.*?\n\};", SOURCE, re.S)[0])
        program = program.replace("TIMERTYPE",
                                  re.search(r"struct background_timer \{.*?\n\};", SOURCE, re.S)[0])
        program = program.replace("FUNCTIONS", "\n".join(function(n) for n in (
            "get_hint", "sync_job", "safe_age_ns", "effective_deadline_ns", "enqueue_slice_ns",
            "background_timer_expired", "arm_background_timer", "disarm_background_timer",
            "background_for_cpu", "background_dsq", "enqueue_background", "account_background",
            "deadline_waiting_on", "background_prefer_previous", "deadline_prefer_previous", "keep_background",
            "preempt_later_deadline",
            "scx_fresh_enqueue", "scx_fresh_dispatch", "scx_fresh_running", "scx_fresh_stopping")))
        program += "\nint main(int argc, char **argv) { assert(argc==2);\n"
        for name, body in CASES.items():
            program += f'if (!strcmp(argv[1], "{name}")) {{ {body} return 0; }}\n'
        program += "return 1; }\n"
        subprocess.run([*shlex.split(os.environ.get("CC", "cc")), "-std=gnu2x",
                        "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter",
                        "-I", str(ROOT / "include"), "-I", str(ROOT / "bpf"),
                        "-x", "c", "-", "-o", str(cls.binary)],
                       input=program, text=True, check=True)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()


for name in CASES:
    def test(self, case=name):
        subprocess.run([str(self.binary), case], check=True)
    setattr(BackgroundServerTests, "test_" + name, test)

if __name__ == "__main__":
    unittest.main(verbosity=2)
