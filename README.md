# scx_fresh

A sched_ext scheduler for application-selected jobs, with explicit service
classes and per-job timing hints.

Applications select Urgent, Deadline or Background service explicitly. Stage
identity is diagnostic and never selects a queue. The hint ABI is version 1;
use matching client headers and library. Unsupported versions receive Background service.

The application selects work and publishes one hint per worker before waking
it. The scheduler supplies CPU service; it does not own the work queue, decide
whether work is useful, or cancel jobs. A per-job budget can demote Deadline
work to Background. The optional Background server allocates service ahead of
Deadline while remaining subordinate to Urgent.

## Build and test

Requires Linux with sched_ext support, readable kernel BTF, clang with a BPF
backend, bpftool, a C compiler, and libbpf, libelf, and zlib development files.
Python 3 runs the tests.

```bash
make
make test
./build/scx_fresh --print-ops-flags
```

The default is partial-switch mode: only threads using SCHED_EXT are enrolled.
The tests inspect the embedded scheduler and exercise slice selection without
attaching it. The BE slice cap remains disabled by default.

The build produces the `scx_fresh` loader and an MIT-licensed `libfreshqos.a`
client library. Applications use `src/freshqos.h` and the headers in `include/`;
linking the client requires libbpf. The client does not embed the BPF program.

See the [architecture](docs/DESIGN.md), [hint contract](docs/HINTS_API.md),
[current policy](docs/SCHEDULER.md), and [operation guide](docs/USAGE.md).

The [PREEMPT_RT experiment](experiments/preempt-rt/README.md) contains local
kernel patches and their validation limits; it is not supported RT enablement.

## License

The BPF scheduler, loader, and tests compiling BPF helpers are GPL-2.0-only. The client library,
shared interface headers, build tooling, scheduler-mode test, and documentation
are MIT-licensed. File-level SPDX notices identify the boundary. See
[GPL-2.0-only](LICENSE) and [MIT](LICENSES/MIT.txt).

Generated skeletons embed the GPL BPF program. Dependencies retain their own
licenses, including libbpf's LGPL-2.1 or BSD-2-Clause alternatives.

## Provenance

Developed from the scheduler in
[scx-slam-fresh](https://github.com/seldak/scx-slam-fresh), which retains the
application integration and historical evaluation results. This repository
starts with the generic service-class implementation.
