# Scheduler rules

Service is selected explicitly by class. Stage IDs identify application work
for diagnostics and do not affect routing.
Userspace owns job selection;
the scheduler routes the thread named by its hint.

## Routing at enqueue

Rules are applied in this order:

| Condition | Destination |
| --- | --- |
| Urgent class, wakeup enqueue | CPU-local DSQ with `SCX_ENQ_PREEMPT` |
| Urgent class, other enqueue | `DSQ_URGENT`, ordered by effective deadline |
| Deadline class, no budget overrun | `DSQ_DEADLINE`, ordered by effective deadline |
| Background class, unhinted task, or Deadline budget overrun | `DSQ_BACKGROUND` |

With the Background server disabled, `dispatch` moves at most one task to the
local DSQ, in this order:

```text
Urgent -> Deadline -> Background
```

Moving one task avoids queuing a batch of lower-priority tasks ahead of a later
arrival. Urgent retains its wakeup preemption. A Deadline wakeup requests a
reschedule only when the current task is an eligible Deadline owner with a
strictly later effective deadline. The arrival stays in the Deadline DSQ;
normal dispatch precedence still applies. Deadline wakeups also request
preemption of native or demoted Background service unless that worker is
executing under a still-funded protected Background grant. Urgent and foreign
scheduling classes are never targeted.

Both jobs must supply a deadline or a release-plus-freshness bound. Equal keys,
missing bounds, non-wakeup enqueues and a mismatched current job identity do not
trigger this request. This uses `scx_bpf_cpu_curr` under RCU; kernels without
that helper retain dispatch-only Deadline ordering. A remote CPU can change
owners between inspection and the kick, so the kick is a scheduling request,
not an atomic promise to displace a particular worker.

The focused loaded probe passed three trials: an earlier-deadline worker woke
3 ms into a 20 ms Deadline callback and started after 69, 74 and 68 microseconds,
before that callback completed. The server and BE cap were disabled. The loaded
Background-server regression also passes.

Application regression checks passed one 15-second measured run each with zero
and two Background hogs, using a 2 ms BE cap and a 2 ms / 10 ms Background
server. Both used source epoch `1403636579758555500` in the EuRoC synthetic
workload: all 3000 Urgent callbacks and all 300 callbacks per downstream stage
completed, with zero late callbacks, drops or unfinished work. With two hogs,
Urgent p99 start age was 1.72 ms, estimator p99 completion age was 15.77 ms,
and the hogs completed 11,936 iterations combined. These single runs showed no
application regression; they do not establish a latency improvement.

## Optional Background server

`--background-server-us Q/P` configures one pool per CPU. Q is the runtime
allocation in microseconds; P is the replenishment period in microseconds.
Require `0 < Q <= P`. Omitting the option disables the server and retains the
original routing, slices and fairness accounting. There is no default allocation.

With the server enabled, native Background, unhinted workers and budget-demoted
Deadline workers join the CPU's Background queue. Dispatch checks:

```text
Urgent -> Background with allocation remaining -> Deadline -> spare Background
```

All CPUs use fixed intervals aligned to monotonic time. At a new interval,
the grant is Q minus unpaid protected-service overrun; unused allocation does
not carry over. Overrun larger than Q can consume several future grants.
Skipped intervals retire debt without accumulating positive credit. Urgent
always takes precedence and never consumes this allocation. A server can use Q
near the end of one period and another Q immediately after replenishment.
`Q=P` can deny Deadline service while Background remains runnable.

Background execution is charged from the kernel's task CPU-runtime counter
before the `dispatch` decision, then checkpointed so `stopping` charges only
the remaining delta. The kernel can call dispatch before stopping. Charging
only in stopping would let the next worker consume an allocation that was
already spent. Spare-capacity execution is charged too. Once Q is exhausted, Background
is chosen only when Urgent and Deadline supply no runnable task. This is a
dispatch rule: Deadline wakeups can preempt unprotected Background service.
Server replenishment neither clears job overrun nor resets job CPU accounting.

At `running`, Background's slice is bounded by any remaining allocation.
Non-Urgent slices are also bounded by time to the next replenishment, so a long
Deadline slice does not deliberately span it. A per-CPU monotonic BPF timer
requests rescheduling at that bound; writing a slice alone does not guarantee
a scheduling event when the local scheduler tick is stopped. Retaining the
current worker rearms its timer without requiring a context switch. Stopping
disarms it, and Urgent execution never arms it. The timer does not select work
or charge CPU; dispatch still applies the same class and server rules.
Timer delivery and scheduling boundaries can occur late. Allocation
saturates at zero, but excess service ahead of waiting Deadline work becomes
debt against future grants. Otherwise a small overrun on every slice could
systematically exceed Q/P. Legitimate spare-capacity execution creates no debt.
This is accounting of CPU already supplied, not saved unused allocation, a
new job budget, or promotion to Deadline.

For execution crossing a boundary, the old interval is charged before
replenishment. The latest interval is charged up to its elapsed wall time;
unknown interrupt placement is handled conservatively. This can reduce
available service in that interval. Lifetime counters distinguish protected
and spare CPU time and report overshoot, repayment and remaining debt.
Protected-service classification checks the current Deadline worker or the
first CPU-eligible worker found in the shared Deadline DSQ. Work pinned to
other CPUs does not turn local spare service into protected-service debt.

The server establishes precedence against Deadline on that CPU inside
SCHED_EXT. Urgent work, foreign scheduling classes, interrupts and scheduling
granularity can prevent delivery of Q in an interval. It is not an admission
test or a hard real-time reservation.

Fairness counts only Background CPU time when enabled. A worker entering from
another service class starts at the pool's current virtual-time baseline, with
no Deadline credit or debt. Sleep/wakeup and native Background job changes do
not erase its accumulated service. Only waking sleepers are clamped to the
advancing baseline; continuously runnable competitors retain their service
deficit. Migration preserves positive debt relative to the destination pool.
Background queues are CPU-specific and are not work-stolen by other CPUs;
normal CPU selection still applies on wakeup. Pin workers for allocation tests.

The runnable previous task is not yet in a DSQ during dispatch. Deadline compares
its effective deadline with the first CPU-eligible queued Deadline job; the
earlier job wins and equal keys yield to the queued peer. Queued Urgent work
is considered before a previous Urgent worker. Both classes precede lower
service, except for funded Background allocation. A budget-exhausted previous Deadline worker yields so stopping
and enqueue can enforce demotion. This also corrects the disabled policy's
former rotation into Background when its only Deadline worker was current.
For Background, the current worker competes against the first ordered DSQ
entry using actual Background virtual time; being queued does not itself
give a worker precedence over a less-served current worker. Equal keys yield
to the queued peer. This comparison applies to protected and spare service.

## Age and effective deadlines

Expiry belongs to the application. An elapsed deadline or stale bound never
demotes a worker. There is no STALE queue, ownership exemption or deadline-grace
parameter. A late selected job retains its class unless CPU-budget enforcement
demotes it. Deadline lateness is still observed at `stopping`; application
completion metrics remain the authority for whether an output was timely.

Age observations use `max(now - release_ts_ns, 0)`, with zero for an unspecified
release. Future release times do not underflow.

Within Urgent and Deadline queues, the effective deadline is the earliest available
value among `deadline_ts_ns` and `release_ts_ns + stale_ns`. The latter is
used only when both fields are nonzero and the sum does not overflow. Only
Urgent may omit both bounds and use current time; invalid Deadline hints receive
Background service. This is deadline ordering, not newest-message selection.

## Execution budgets

BPF stores execution accounting per worker. A new `job_id` resets the job's
execution total and overrun state at enqueue. `running` also establishes job
identity because enrollment may run a task before its first enqueue; otherwise
that first enqueue could discard execution already charged to the job.
At `stopping`, the delta of `se.sum_exec_runtime` is added to `exec_ns_in_job`
and the legacy `vruntime`. Interrupt wall time is not charged as job execution.
Dispatch uses that same counter when checking a current worker's budget.
The enabled server uses separate Background-only CPU accounting.

When execution exceeds a nonzero budget, the scheduler marks the job overrun
and emits a budget-overrun event. A later enqueue sends overrun Deadline work to Background
and emits a budget-demotion event. The two events distinguish detection from
routing. Urgent accounting still records overruns, but its special route takes
precedence over budget demotion.

Budget enforcement occurs at scheduling boundaries; it is not a timer that
cancels compute at the exact budget. Background ordering uses accumulated
runtime. The hint's `weight` field is currently not applied to that accumulator.

## Insertion slices

The hint's `slice_ns=0` means use `SCX_SLICE_DFL` (20 ms on the tested kernel).
It is translated to an explicit slice before insertion. Passing a literal
zero to the kernel would retain the residual slice, or grant 1 ns if exhausted.

The optional loader argument `--be-slice-cap-us N` caps the resolved slice
for missing hints and non-urgent hints whose original class is Background.

| Setting | Effect |
| --- | --- |
| `0` (default) | No cap; existing requested/default slices apply. |
| Positive value | Eligible insertions use the smaller of the resolved slice and cap. |

Original Background-class and unhinted work are eligible. Urgent and Deadline hints are not, including a Deadline job
routed to Background after a budget overrun. The cap changes neither the global
default slice nor queue order, deadlines, admission, or preemption.
The server's runtime and period bounds apply later at `running`, including to
demoted Deadline work. They do not change eligibility for the insertion cap.

## Hint lifetime and observability

A worker's hint may remain visible after callback compute completes.
Retaining its class avoids a premature Background clear during the completion
tail. The hint is replaced
only after the executor establishes completion. See the
[executor contract](HINTS_API.md#executor-contract).

Deadline events are best-effort observations at scheduler boundaries. They
are not the workload's completion-lateness counters. Use application metrics
to evaluate whether outputs completed on time.

## Kernel compatibility and diagnostics

The BPF source uses weak kfunc declarations and `bpf_ksym_exists()` for renamed
sched_ext helpers. The loader can report embedded switch flags before attachment;
the default build uses partial-switch mode.

Historical trace and preemption probes remain opt-in and are not part of
the default policy. The loader help lists their command-line options.
