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
configuration, slice and service-class tests without attaching a scheduler.
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

`--help` also lists preemption and trace probes. They are opt-in
diagnostics, not additional default policy. Event counts describe scheduler
observations; applications must measure actual completion lateness themselves.

Execution tracing requires `--trace-worker-name NAME` to identify a worker by
its thread name. `--trace-urgent` observes Urgent hints and can use that name to
observe missing or misclassified hints. `--trace-stage N` observes an arbitrary
application stage; it does not change that stage's service.

`--print-config` reports `expiry_policy=application`. The removed
`--deadline-grace-us` option is rejected rather than silently ignored.

## Build configuration

`BUILD_DIR` selects generated output. `CC`, `AR`, `BPF_CLANG`, and `BPF_CFLAGS`
select build tools and flags. Make does not track changes to command-line flags;
clean the selected build directory before changing them.

`FRESH_FULL_SWITCH=1` enables full-switch mode. It is outside the established
partial-switch evaluation configuration. Clean and rebuild when returning to
the default. Do not add `isolcpus=domain` for the previously tested kernel
7.0.0-31-generic: scheduler attachment was rejected with that setting.

The loader embeds its BPF object. Rebuild it after BPF changes. CPU placement,
interrupt placement, and workload admission remain deployment responsibilities.
