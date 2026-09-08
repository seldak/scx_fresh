# Scheduler architecture

scx_fresh schedules enrolled Linux threads using metadata describing their
currently selected work. It does not select application messages or perform
application processing.

## Responsibility boundary

The following contract guides the generic scheduler design. The current
implementation and remaining policy gaps are described below.

| Owner | Decisions |
| --- | --- |
| Architect | CPU allocation and affinity, service precedence and protection requirements, permitted adaptations, budget limits, and definitions of useful outcomes. |
| Application runtime | Dependency readiness, optional remaining-chain estimates, propagation of timing requirements, and work admission, dropping or cooperative cancellation. |
| BPF scheduler | CPU service for runnable workers, using selected-work metadata and enforcing configured service rules and resource limits. |

The runtime owns the work graph and work selection; the scheduler owns CPU
scheduling. A deadline miss does not authorize the scheduler to cancel
application work. Expiry and the decision to continue late work belong to the
application. Sensor or stage identity must not select service.

A runtime may supply a job deadline directly. Graph analysis and remaining-chain
estimates are optional ways to derive it, not requirements of the hint interface.
Dropping queued work does not imply permission to interrupt a running callback;
the runtime remains responsible for its message, resource and completion lifetimes.

## Service model and remaining gaps

A service class describes configured CPU treatment, independent of application
function. It is a policy inside SCHED_EXT, not another Linux scheduling class.
Class precedence expresses the architect's priorities. Within a deadline-ordered
class, an earlier-deadline job should preempt a later-deadline job when they
compete for the same CPU. Hints must not bypass configured class permissions or
resource limits. This same-class preemption is not implemented by the current Deadline
path.

Ownership, job budgets and service classes are separate concepts. Ownership
protects the selected-work lifecycle; it does not grant unlimited CPU service.
A per-job execution budget is not a periodic CPU reservation. Its exhaustion
alone does not specify when the worker may receive service again.

An optional per-CPU Background server supplies service ahead of Deadline to a
shared pool of native Background and budget-demoted Deadline workers. Its Q/P
allocation is separate from per-job limits and remains subordinate to Urgent.
This consumes service that Deadline cannot also claim; it does not promote jobs
or restore their budgets. See the [server rules](SCHEDULER.md#optional-background-server).

Treatment of missing deadlines and deadline ties also needs an explicit rule.
These choices must be settled before claiming predictable service; the current
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

| Current mechanism | Difference from the intended contract |
| --- | --- |
| Urgent class selects the dedicated queue and wakeup preemption | Implemented independently of stage identity. |
| Deadline effective-deadline ordering without wakeup preemption | Same-class earlier-deadline preemption needs implementation and validation. |
| Application-owned expiry, with no age demotion | Implemented for every class without an ownership flag. |
| Job-budget overrun demotes Deadline to Background; Urgent routing is exempt | Server service does not refill job budgets or restore Deadline standing. |
| Optional per-CPU Background server | Supplies precedence over Deadline while funded; delivery depends on interference and scheduling granularity. |

Generic class selection and application-owned expiry are implemented. Same-class
deadline preemption and class permissions remain future changes. The optional
Background server has passed the focused loaded allocation and progress probe;
those finite-window checks do not establish a hard reservation.
The hint and scheduler references describe the current ABI and routing rules.

## Limits

With the server disabled, strict priority can starve Background. Budget demotion does not cancel work,
but can delay the completion path. Removing age demotion does not establish
minimum service or a hard real-time guarantee. The scheduler does not control
GPU/ISP execution, synchronize measurements, or migrate an application job
between workers. Kernel fallback on scheduler failure is not a timing guarantee.

See [usage](USAGE.md) for build, attachment, and non-attaching tests. The
application integration and evaluation remain in
[scx-slam-fresh](https://github.com/seldak/scx-slam-fresh).
