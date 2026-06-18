# execsnoop

`execsnoop` is a native Rust eBPF watcher for successful Linux exec events. The
userspace library loads an embedded Aya BPF object, attaches it to
`sched:sched_process_exec`, and receives fixed-size binary records through a
per-CPU perf event array.

## Event ABI

The BPF program emits this `#[repr(C)]` record:

```rust
pub struct RawExecEvent {
    pub pid: u32,
    pub parent_pid: u32,
    pub flags: u32,
    pub filename_len: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}
```

`filename_len` is the copied byte count excluding a trailing NUL. `flags`
contains explicit bits for filename truncation, unavailable parent PID, and
unavailable filename. Userspace validates the record size and decodes with
`ptr::read_unaligned`; byte strings are converted with
`String::from_utf8_lossy` only at API boundaries.

The tracepoint field offsets are read from the running kernel's tracefs format
file before attach and written into a BPF config map. The loader fails rather
than assuming offsets when `pid` or `filename` cannot be verified. Parent PID is
read in eBPF from `current->real_parent->tgid`; userspace verifies the
`task_struct` member offsets from `/sys/kernel/btf/vmlinux` at startup and
passes those byte offsets through the same config map. If the bounded BPF-side
reads fail for an event, `parent_pid` is zero and the unavailable-parent flag is
set.

## Behavior

The watcher reports successful execs only. It currently exposes the executable
filename/path as `Process::cmd`; argv capture is intentionally omitted because
bounded syscall-entry argv walking would add more BPF work and would need
entry/return correlation to avoid failed execs. The scheduler only needs the new
PID, parent PID, task name, and executable identity.

## Requirements

Build time requires `rust-src`, the `bpfel-unknown-none` Rust target support,
`llc`, and `llvm-objcopy` to compile the embedded Rust eBPF object. Runtime
requires tracefs access, readable vmlinux BTF at `/sys/kernel/btf/vmlinux`,
perf event arrays, and eBPF permissions such as `CAP_BPF` plus `CAP_PERFMON` on
modern kernels, or equivalent root privileges.

If the watcher cannot read tracepoint metadata, load BPF, or attach the
tracepoint, `execsnoop::watch()` returns an error. The daemon logs a warning and
continues running with periodic process refreshes.

## Manual Verification

1. Build and run the daemon with `process_scheduler.execsnoop true`.
2. Execute simple commands such as `/usr/bin/true` and `sh -c 'sleep 0.1'`.
3. Execute paths or scripts containing spaces and arguments containing newline
   bytes; verify the daemon keeps running and logs structured events.
4. Optionally run `execsnoop-bpfcc` beside the daemon on a test system and
   compare PID, PPID, COMM, and executable path for successful execs.
5. Run `cargo test -p execsnoop`, `cargo build`, `cargo fmt --check`, and
   `cargo clippy --all-features -- -W clippy::pedantic`.
