# PREEMPT_RT timer experiment

These patches reproduce a local experiment, not supported RT timer enablement
or an upstream-ready patch series. Base: bpf-next commit
`af0b84a9215d951d16f26b7ee34353b970cf5d4e` (7.3.0-rc2).
Kernel patches and selftests retain GPL-2.0 licensing.

## Changes

1. `0001-reject-atomic-cancel.patch`: reject synchronous timer cancellation
   from atomic context on RT before modifying the callback reference.
2. `0002-enable-timers-experimental.patch`: remove the blanket RT verifier
   restriction. This is a diagnostic bypass, not proof that all timer paths
   are safe. Apply only together with the cancellation guard for this test.
3. `0003-cancellation-test.patch`: exercise cancellation while a callback runs
   on another CPU, including rejection and subsequent timer reuse.

Apply with `git apply` in that order to the pinned kernel source. Configure
`CONFIG_PREEMPT_RT`, `CONFIG_BPF_SYSCALL`, `CONFIG_SCHED_CLASS_EXT`,
`CONFIG_DEBUG_INFO_BTF`, `CONFIG_DEBUG_ATOMIC_SLEEP`, and `CONFIG_PROVE_LOCKING`.
Build and boot that kernel before running its matching BPF selftests.

```bash
sudo timeout --signal=TERM --kill-after=5s 30s \
  taskset -c 1,14 ./test_progs -t timer_cancel_rt -v
```

The two CPUs must be available and distinct. The callback wait is bounded;
the caller waits without sleeping to avoid missing the overlap. An overlap
failure is inconclusive, not a cancellation failure. Check kernel logs as well
as assertions: a successful return alone cannot detect sleeping in atomic context.

## Timer cancellation and scheduler progress

Ubuntu 7.0.0-31-realtime rejected the timer helper while the control program
loaded. Removing the restriction on the pinned kernel exposed
`bpf_timer_cancel -> hrtimer_cancel_wait_running -> rt_spin_lock` sleeping with
preemption disabled. The guard subsequently returned `-EOPNOTSUPP` for that
caller; preemptible cancellation waited for callback completion, and rejection
preserved the timer's callback for rearming and cancellation. Both overlapping
subtests passed. The auxiliary unsigned `bpf_testmod` was rejected by Secure
Boot; these subtests do not depend on it.

The scheduler then exposed a separate RT feedback loop: starting its timer on
every resume woke threaded `irq_work`, whose preemption caused another resume
and start. Reusing an outstanding earlier expiry in `scx_fresh` restored progress;
shorter deadlines still rearm it. This scheduler change is separate from the
kernel patches.

With a 2 ms / 10 ms Background server on CPU 14, a three-second test measured:

| Case | Deadline CPU | Native Background | Demoted Deadline | Urgent CPU |
| --- | ---: | ---: | ---: | ---: |
| Server disabled | 2970.842 ms | 0.110 ms | 0.101 ms | — |
| Server enabled | 2351.027 ms | 300.033 ms | 299.981 ms | — |
| Server plus Urgent | 2016.942 ms | 299.948 ms | 299.989 ms | 304.042 ms |

Allocation, fairness and progress gates passed. Maximum Background gaps were
28.093 ms and 18.104 ms in the enabled cases. Reproduce from the scheduler root:

```bash
make all test build/background_workload
sudo python3 scripts/test_background_server.py --cpu 14 --housekeeping-cpu 1
```

## Limits

Lockdep exhausted its chain-tracking capacity during boot and disabled itself.
Atomic-sleep diagnostics remained useful, but this was not a clean lockdep
validation. Concurrent teardown, map destruction and other timer contexts have
not been exhaustively tested. No claim of general RT safety, bounded latency,
or schedulability follows. The debug kernel is also unsuitable for attributing
performance differences solely to PREEMPT_RT.

Application comparisons and their negative overload result belong in
[scx-slam-fresh](https://github.com/seldak/scx-slam-fresh).
