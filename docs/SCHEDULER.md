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

In `dispatch`, at most one task moves to the local DSQ, in this order:

```text
Urgent -> Deadline -> Background
```

Moving one task avoids queuing a batch of lower-priority tasks ahead of a later
arrival. Only the default Urgent wakeup path preempts. Deadline arrival does not shorten
a running Background slice.

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
used only when both fields are nonzero. With neither bound, the key is the
current time. This is deadline ordering, not newest-message selection.

## Execution budgets

BPF stores execution accounting per worker. A new `job_id` resets the job's
execution total and overrun state at enqueue.
At `stopping`, elapsed running time is added to `exec_ns_in_job` and
`vruntime`.

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
