# Userspace hints API

`libfreshqos` writes scheduling metadata to the pinned `task_hints` BPF map.
Each key is a worker identity, packed as `(tgid << 32) | tid`. Each value
describes one selected job.

> Userspace selects work. sched_ext consumes metadata about the work already
> selected for a worker.

## Functions

Declarations are in `src/freshqos.h`; the shared layout is
`struct fresh_task_hint` in `include/scx_fresh_shared.h`.

| Function | Use |
| --- | --- |
| `freshqos_pid_tgid_self()` | Return the current worker's packed identity. |
| `freshqos_open(q, pin_dir)` | Open the pinned hint map into a caller-owned handle. |
| `freshqos_close(q)` | Close the map descriptor. |
| `freshqos_publish_hint(q, hint)` | Replace the current thread's hint. |
| `freshqos_publish_hint_for(q, worker, hint)` | Replace an explicitly identified worker's hint. |
| `freshqos_publish_job(...)` / `freshqos_publish_job_for(...)` | Build and publish a hint from individual fields. |
| `freshqos_clear_hint(q)` | Write an unspecified-stage Background hint with job ID zero for the current thread. |

Use the full hint structure when setting flags such as
`FRESH_HINT_EXECUTOR_OWNED`. A clear is a map update, not an ownership or
cancellation operation; an executor must establish that clearing is safe.

## Fields

| Field | Meaning |
| --- | --- |
| `api_version` | Set to `FRESH_API_VERSION`. |
| `stage_id` | Application-defined diagnostic identity; never selects service. |
| `class_id` | `FRESH_CLASS_BACKGROUND`, `FRESH_CLASS_DEADLINE` or `FRESH_CLASS_URGENT`. |
| `flags` | Ownership flags; zero unless the client implements their contract. |
| `job_id` | Stable for one job; change it when selecting new work. |
| `release_ts_ns` | Monotonic release time. |
| `deadline_ts_ns` | Absolute monotonic deadline, or zero for none. |
| `stale_ns` | Maxurgentm useful age, or zero to disable the stale threshold. |
| `budget_ns` | Execution budget, or zero to disable budget enforcement. |
| `slice_ns` | Requested insertion slice; zero selects the scheduler default. |
| `weight` | Reserved fairness parameter; current BPF runtime accounting does not apply it. |

For nonzero deadlines, use a value at or after release. Scheduler timestamps
use `CLOCK_MONOTONIC`, corresponding to BPF `bpf_ktime_get_ns()`. External source timestamps may use another clock and must be translated before
being used as kernel deadlines.

## Executor contract

The single slot per worker makes publication ordering part of correctness.

### Assign, publish, wake

For a sleeping worker:

1. Select a job and bind it to that worker.
2. Publish its identity and scheduling fields into the worker's slot.
3. Wake the worker.

Publishing only after the worker starts running is too late to classify its
wakeup. A worker selecting another job without sleeping must publish after
selection and before compute.

### Ownership and eviction

A producer or eviction path must not overwrite an executing job's hint.
Only the worker may replace or clear it, unless the executor has independently
established completion.

Do not publish work evicted before assignment. If the selected head is removed
before a planned wake, publish the replacement first or do not wake the worker.
A pre-start thief publishes the stolen job onto its own slot before execution.

Once compute begins, the job stays with that worker until completion or
worker-controlled cancellation. Budget state is keyed by worker, so moving
a running job would reset accounting and could grant it a second Deadline budget.
Mid-job migration requires state keyed by at least stage and job identity.

### Retaining ownership through completion

`FRESH_HINT_EXECUTOR_OWNED` prevents age demotion for a selected non-urgent
owner. The client must reject expired work before execution and preserve
ownership through its completion path. Budget demotion still applies.
A completed hint may remain through parking until the dispatcher establishes
completion and replaces it with the next job. Clearing the slot into Background too
early can delay the completion tail under contention.

The scheduler's default deadline grace is 1 ms. A client may enforce a stricter
admission deadline without that grace. The flag does not cancel work, disable
budget accounting, or authorize kernel-side selection.

## Client boundary

The MIT helper library is optional. A client may access the documented map
layout directly, with the required map permissions and publication ordering.
The helper sets the ABI version when constructing a job, but does not negotiate
versions or validate application deadlines. Full-structure publication leaves
field initialization to the caller.

ABI version 2 replaces stage-based routing with explicit service classes.
Clients and scheduler must be rebuilt together. Version 1 hints and unknown
classes are treated as unhinted Background work; stage zero has no special
meaning. The client rejects incompatible versions and unknown classes before
updating the map. See the [scheduler rules](SCHEDULER.md) for service treatment.

Application-specific message lifetimes, sensor timestamps, and queue admission
belong in the consuming application's documentation.
