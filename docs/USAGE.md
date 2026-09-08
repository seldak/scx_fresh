# Build and operation

Run from the scheduler repository root. Requires a sched_ext-capable Linux
kernel, readable kernel BTF, clang with BPF support, bpftool, a C compiler,
libbpf/libelf/zlib development files, and Python 3 for tests. ROS is not needed.

```bash
make
make test
./build/scx_fresh --print-ops-flags
./build/scx_fresh --print-config
```

The default flags are `0x8` (partial switch). `make test` runs loader
configuration, slice, service-class and Background-server tests without attachment.
Generated kernel type declarations may produce compiler warnings on some kernels.

`make client` builds only the optional MIT client library. Its public header is
`src/freshqos.h`, with ABI definitions in `include/`. Applications can compile
`src/freshqos.c` directly instead of linking the archive. The client requires
libbpf but does not require generating or embedding a BPF skeleton.

## Attach

On a test machine, with no other sched_ext scheduler active:

```bash
sudo ./build/scx_fresh --pin /sys/fs/bpf/scx_fresh
```

The pin directory is supplied explicitly. It contains the hint map and events
ring buffer. Stop the foreground loader with Ctrl-C to detach it. Configure
application workers as SCHED_EXT and set CPU affinity separately; the loader
does not enroll an arbitrary application or reserve a CPU set for it.

The default policy uses wakeup-only preemption for its Urgent class and no
Background slice cap. Expiry is application-owned. These are implementation defaults,
not an application deadline guarantee.

| Loader option | Purpose |
| --- | --- |
| `--pin DIR` | Select map pin directory for attachment. |
| `--print-ops-flags` | Inspect embedded flags without attachment. |
| `--print-config` | Inspect selected configuration without attachment. |
| `--be-slice-cap-us N` | Cap eligible Background insertion slices; default 0 disables the cap. |
| `--background-server-us Q/P` | Per-CPU Background runtime and period in microseconds; omitted means disabled. |

For example, `--background-server-us 2000/10000` allows the Background pool
2 ms ahead of Deadline in each 10 ms interval. This is a test configuration,
not a recommended application default. See the [server rules](SCHEDULER.md#optional-background-server)
for replenishment, interference and fairness semantics.

The focused loaded test compares disabled service, that allocation, and the
same allocation with periodic Urgent work. It keeps Deadline runnable and
reports CPU time for native Background and budget-demoted Deadline workers in
a common three-second window. It needs root and no attached scheduler:

```bash
make all test build/background_workload
sudo python3 scripts/test_background_server.py --cpu 14 --housekeeping-cpu 1
```

Choose CPUs appropriate to the test machine. The test uses partial switch and
detaches between cells. The probe checks combined Background CPU against 20%
of the common window, native/demoted service balance, and maximum service gaps.
It allows two periods plus two observation chunks for allocation and balance,
and five periods for a Background gap. These finite-window tolerances do not
establish a hard reservation or a latency guarantee; inspect the reported CPU
shares and raw observation gaps.
Bag regressions with the server omitted remain a separate disabled-policy gate.
The loader also prints `background_server_lifetime` counters for CPUs that
served Background. These include warmup and shutdown time and must not be
compared directly with the workload's three-second window totals. They expose
protected/spare service, overshoot, repaid allocation debt and outstanding debt.

`--help` also lists preemption and trace probes. They are opt-in
diagnostics, not additional default policy. Event counts describe scheduler
observations; applications must measure actual completion lateness themselves.

Execution tracing requires `--trace-worker-name NAME` to identify a worker by
its thread name. `--trace-urgent` observes Urgent hints and can use that name to
observe missing or misclassified hints. `--trace-stage N` observes an arbitrary
application stage; it does not change that stage's service.

`--print-config` reports `expiry_policy=application`. The removed
`--deadline-grace-us` option is rejected rather than silently ignored.

## Deadline contention probe

Build and run the focused multi-worker check:

```bash
make build/deadline_contention
sudo python3 scripts/test_deadline_contention.py --cpu 14 --housekeeping-cpu 1
```

The first cell releases earlier, equal and later Deadline jobs during a 20 ms
owner. The second adds Urgent, Background and a budget-limited Deadline worker,
with the Background server set to 2 ms / 10 ms. Each worker publishes three
successive jobs. The probe records CPU time, start delay and completion order;
it checks complete work, earlier-deadline preemption in the first cell, Urgent
response and Background overlap in the second, and demotion of each budgeted
job. Equal deadlines have no asserted FIFO completion order. The budgeted
worker requests a 1 ms slice so its 6 ms job exercises re-enqueue demotion.
No scheduler policy changes are made by this test.

Loaded validation passed all three rounds in both cells on the isolated test
CPU. Deadline-only earlier arrivals started within 68–84 microseconds; mixed-cell
Urgent arrivals started within 60–63 microseconds. Every worker completed its
requested CPU work, native Background started before the Deadline owner finished,
and the budgeted worker emitted a demotion for each of its three jobs. Equal-deadline
completion order varied, as permitted. These finite tests do not establish a
schedulability guarantee or a bound on worst-case response time.

## Build configuration

The focused Deadline preemption probe uses a 20ms Deadline callback and wakes
an earlier-deadline worker after 3ms. Three repetitions must show an overlapping
owner and a start delay below 5ms. This is a test tolerance, not a guarantee.

```bash
make all test build/deadline_workload
sudo python3 scripts/test_deadline_preemption.py --cpu 14 --housekeeping-cpu 1
```

## Build variables

`BUILD_DIR` selects generated output. `CC`, `AR`, `BPF_CLANG`, and `BPF_CFLAGS`
select build tools and flags. Make does not track changes to command-line flags;
clean the selected build directory before changing them.

`FRESH_FULL_SWITCH=1` enables full-switch mode. It is outside the established
partial-switch evaluation configuration. Clean and rebuild when returning to
the default. Do not add `isolcpus=domain` for the previously tested kernel
7.0.0-31-generic: scheduler attachment was rejected with that setting.

The loader embeds its BPF object. Rebuild it after BPF changes. CPU placement,
interrupt placement, and workload admission remain deployment responsibilities.
