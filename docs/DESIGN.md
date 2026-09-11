# Scheduler architecture

scx_fresh schedules enrolled Linux threads using metadata describing their
currently selected work. It does not select application messages or perform
application processing.

## Responsibility boundary

Responsibilities are divided as follows.

| Owner | Decisions |
| --- | --- |
| Architect | CPU allocation and affinity, service precedence and protection requirements, permitted adaptations, budget limits, and definitions of useful outcomes. |
| Application runtime | Dependency readiness, optional remaining-chain estimates, propagation of timing requirements, and work admission, dropping or cooperative cancellation. |
| BPF scheduler | CPU service for runnable workers, using selected-work metadata and enforcing configured service rules and resource limits. |

The runtime owns the work graph and work selection; the scheduler owns CPU
scheduling. A deadline miss does not authorize the scheduler to cancel
application work. Expiry and the decision to continue late work belong to the
application. Stage identity must not select service.

A runtime may supply a job deadline directly. Graph analysis and remaining-chain
estimates are optional ways to derive it, not requirements of the hint interface.
Dropping queued work does not imply permission to interrupt a running callback;
the runtime remains responsible for its message, resource and completion lifetimes.

## Service model

A service class describes configured CPU treatment, independent of application
function. It is a policy inside SCHED_EXT, not another Linux scheduling class.
Class precedence expresses the architect's priorities. Deadline wakeups request
preemption when their explicit
effective deadline is earlier than the running eligible Deadline job's, or when
the current worker is receiving unprotected Background service. Dispatch also
compares the current Deadline worker against queued Deadline work.

Ownership, job budgets and service classes are separate concepts. Ownership
protects the selected-work lifecycle; it does not grant unlimited CPU service.
A per-job execution budget is not a periodic CPU reservation. Its exhaustion
alone does not specify when the worker may receive service again.

An optional per-CPU Background server supplies service ahead of Deadline to a
shared pool of native Background and budget-demoted Deadline workers. Its Q/P
allocation is separate from per-job limits and remains subordinate to Urgent.
This consumes service that Deadline cannot also claim; it does not promote jobs
or restore their budgets. See the [server rules](SCHEDULER.md#optional-background-server).

Deadline service requires a usable time bound; invalid direct-map hints receive
Background service. Equal deadlines do not trigger wakeup preemption. The
implementation provides no admission-based timing guarantee.

## Current implementation

| Component | Responsibility |
| --- | --- |
| Application | Select work, derive timing requirements, reject obsolete work, and establish completion. |
| MIT hint interface | Describe one selected job per worker and publish it to the map. |
| GPL BPF scheduler | Route runnable threads, order queues, account CPU execution, and apply demotion. |
| GPL loader | Configure and attach the scheduler, pin maps, and read events. |

```mermaid
flowchart LR
    Select[Application selects work] --> Publish[Publish worker hint]
    Publish --> Wake[Wake worker]
    Publish --> Map[One map slot per worker]
    Map --> SCX[BPF scheduler]
    Wake --> SCX
    SCX --> CPU[CPU runs worker]
    CPU --> Complete[Application establishes completion]
    Complete --> Select
```

The map is metadata transport, not an application queue. A later arrival cannot
overwrite a running job's slot. The [hint contract](HINTS_API.md) specifies the
publication and ownership ordering.

## Scheduling scope

The default build uses partial-switch mode: only SCHED_EXT threads enter this
scheduler. CPU affinity constrains where a thread may execute; it does not
exclude unrelated work. Other scheduling classes and interrupt work remain
outside this policy's control.

The [current policy](SCHEDULER.md) has three explicit service classes: Urgent,
Deadline and Background. Application stage IDs are diagnostic only. Classes
are fixed policy choices; the optional Background allocation is shared per CPU.
Map write permissions
control who may publish hints; per-worker class authorization is not implemented.

## Limits

With the server disabled, strict priority can starve Background. Budget demotion does not cancel work,
but can delay the completion path. Removing age demotion does not establish
minimum service or a hard real-time guarantee. The scheduler does not control
accelerator execution, synchronize external clocks, or migrate an application job
between workers. Kernel fallback on scheduler failure is not a timing guarantee.

See [usage](USAGE.md) for build, attachment and tests.
