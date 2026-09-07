/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef FRESH_BACKGROUND_SERVER_H
#define FRESH_BACKGROUND_SERVER_H

/* CPU-local state, serialized by that CPU's runqueue lock. Enqueue on other
 * CPUs may read vtime, but never modifies this state. Times are monotonic ns.
 */
struct background_server {
    u64 period_start;
    u64 remaining;
    u64 vtime;
    u64 cpu_ns;
    u64 excess_ns;
    u64 periods;
    u64 debt_ns;
    u64 repaid_ns;
    u64 protected_cpu_ns;
    u64 spare_cpu_ns;
    u64 native_cpu_ns;
    u64 demoted_cpu_ns;
    bool initialized;
    bool protect_next;
};

static __always_inline void background_refresh(struct background_server *s,
                                               u64 now, u64 runtime, u64 period)
{
    if (!period)
        return;
    u64 start = now - now % period;
    if (!s->initialized || start != s->period_start) {
        u64 intervals = s->initialized ? (start - s->period_start) / period : 1;
        /* Missed intervals retire debt, but never accumulate positive credit.
         * Bound the multiplication by the debt so large idle gaps cannot wrap.
         */
        u64 missed = intervals > 0 ? intervals - 1 : 0;
        u64 paid = runtime && missed <= s->debt_ns / runtime ?
                   missed * runtime : s->debt_ns;
        s->debt_ns -= paid;
        s->repaid_ns += paid;
        paid = s->debt_ns < runtime ? s->debt_ns : runtime;
        s->debt_ns -= paid;
        s->repaid_ns += paid;
        s->period_start = start;
        s->remaining = runtime - paid;
        s->initialized = true;
        s->periods += intervals;
    }
}

static __always_inline void background_consume(struct background_server *s,
                                               u64 charge, bool protected)
{
    if (charge > s->remaining) {
        if (protected) {
            u64 excess = charge - s->remaining;
            s->excess_ns += excess;
            s->debt_ns += excess;
        }
        s->remaining = 0;
    } else {
        s->remaining -= charge;
    }
}

static __always_inline void background_charge(struct background_server *s,
                                              u64 start, u64 now, u64 cpu_ns,
                                              u64 runtime, u64 period, bool protected)
{
    s->cpu_ns += cpu_ns;
    if (protected)
        s->protected_cpu_ns += cpu_ns;
    else
        s->spare_cpu_ns += cpu_ns;
    u64 new_start = now - now % period;
    u64 charge = cpu_ns;
    if (s->initialized && start < new_start && s->period_start < new_start) {
        u64 current = now - new_start;
        if (current > cpu_ns)
            current = cpu_ns;
        /* Charge the old interval before replenishing. Otherwise its excess
         * would disappear at exactly the boundary we need to audit.
         */
        background_consume(s, cpu_ns - current, protected);
        charge = current;
    }
    background_refresh(s, now, runtime, period);
    /* If a scheduling boundary is late, charge the current interval for at
     * most its elapsed wall time. CPU time before it cannot consume the new
     * allocation. Interrupt placement inside the segment is unavailable;
     * this conservatively charges the latest interval first.
     */
    if (start < s->period_start && charge > now - s->period_start)
        charge = now - s->period_start;
    background_consume(s, charge, protected);
}

static __always_inline u64 background_slice(struct background_server *s,
                                           u64 slice, bool background)
{
    /* Caller refreshed the interval. A zero remainder means spare service,
     * not a zero-length dispatch. Always revisit policy at the next period.
     */
    if (background && s->remaining && slice > s->remaining)
        slice = s->remaining;
    return slice ? slice : 1;
}
#endif
