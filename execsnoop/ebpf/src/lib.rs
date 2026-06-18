// Copyright 2026 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::task_struct,
    helpers::{
        bpf_get_current_comm, bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, gen,
    },
    macros::{map, tracepoint},
    maps::{Array, RingBuf},
    programs::TracePointContext,
    EbpfContext,
};
use core::panic::PanicInfo;

const TASK_COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;
const FLAG_FILENAME_TRUNCATED: u32 = 1 << 0;
const FLAG_PARENT_PID_MISSING: u32 = 1 << 1;
const FLAG_FILENAME_MISSING: u32 = 1 << 2;

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecStats {
    entered: u64,
    missing_config: u64,
    invalid_config: u64,
    pid_read_failed: u64,
    parent_pid_failed: u64,
    filename_loc_read_failed: u64,
    filename_missing: u64,
    filename_read_failed: u64,
    filename_truncated: u64,
    output_attempted: u64,
    output_failed: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TracepointConfig {
    pid_offset: u32,
    filename_offset: u32,
    task_real_parent_offset: u32,
    task_tgid_offset: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct ExecEvent {
    pid: u32,
    parent_pid: u32,
    flags: u32,
    filename_len: u32,
    comm: [u8; TASK_COMM_LEN],
    filename: [u8; FILENAME_LEN],
}

#[map(name = "CONFIG")]
static CONFIG: Array<TracepointConfig> = Array::with_max_entries(1, 0);

#[map(name = "STATS")]
static STATS: Array<ExecStats> = Array::with_max_entries(1, 0);

#[map(name = "EVENTS")]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[no_mangle]
#[link_section = "license"]
#[used]
pub static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[tracepoint(name = "sched_process_exec", category = "sched")]
pub fn sched_process_exec(ctx: TracePointContext) -> u32 {
    match unsafe { try_sched_process_exec(&ctx) } {
        Ok(()) | Err(()) => 0,
    }
}

unsafe fn try_sched_process_exec(ctx: &TracePointContext) -> Result<(), ()> {
    let stats = STATS.get_ptr_mut(0);
    inc_entered(stats);

    let Some(config) = CONFIG.get(0) else {
        inc_missing_config(stats);
        return Err(());
    };

    if config.pid_offset == 0 || config.filename_offset == 0 {
        inc_invalid_config(stats);
        return Err(());
    }

    let (parent_pid, parent_missing) = read_parent_pid(config)
        .map(|pid| (pid, false))
        .unwrap_or((0, true));
    if parent_missing {
        inc_parent_pid_failed(stats);
    }

    let pid = match ctx.read_at(config.pid_offset as usize) {
        Ok(pid) => pid,
        Err(_) => {
            inc_pid_read_failed(stats);
            return Err(());
        }
    };

    let mut event = ExecEvent {
        pid,
        parent_pid,
        flags: if parent_missing {
            FLAG_PARENT_PID_MISSING
        } else {
            0
        },
        filename_len: 0,
        comm: bpf_get_current_comm().unwrap_or([0; TASK_COMM_LEN]),
        filename: [0; FILENAME_LEN],
    };

    let data_loc: u32 = match ctx.read_at(config.filename_offset as usize) {
        Ok(data_loc) => data_loc,
        Err(_) => {
            inc_filename_loc_read_failed(stats);
            return Err(());
        }
    };
    let filename_offset = data_loc & 0xffff;
    let filename_len = data_loc >> 16;

    if filename_offset == 0 || filename_len == 0 {
        inc_filename_missing(stats);
        event.flags |= FLAG_FILENAME_MISSING;
        output_event(stats, &event);
        return Ok(());
    }

    let filename_ptr = ctx.as_ptr().cast::<u8>().add(filename_offset as usize);
    match bpf_probe_read_kernel_str_bytes(filename_ptr, &mut event.filename) {
        Ok(copied) => {
            event.filename_len = copied.len() as u32;

            if filename_len >= FILENAME_LEN as u32 || copied.len() == FILENAME_LEN - 1 {
                inc_filename_truncated(stats);
                event.flags |= FLAG_FILENAME_TRUNCATED;
            }
        }
        Err(_) => {
            inc_filename_read_failed(stats);
            event.flags |= FLAG_FILENAME_MISSING;
        }
    }

    output_event(stats, &event);
    Ok(())
}

fn output_event(stats: Option<*mut ExecStats>, event: &ExecEvent) {
    unsafe {
        inc_output_attempted(stats);
        if EVENTS.output(event, 0).is_err() {
            inc_output_failed(stats);
        }
    }
}

unsafe fn inc_entered(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).entered += 1;
    }
}

unsafe fn inc_missing_config(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).missing_config += 1;
    }
}

unsafe fn inc_invalid_config(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).invalid_config += 1;
    }
}

unsafe fn inc_pid_read_failed(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).pid_read_failed += 1;
    }
}

unsafe fn inc_parent_pid_failed(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).parent_pid_failed += 1;
    }
}

unsafe fn inc_filename_loc_read_failed(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).filename_loc_read_failed += 1;
    }
}

unsafe fn inc_filename_missing(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).filename_missing += 1;
    }
}

unsafe fn inc_filename_read_failed(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).filename_read_failed += 1;
    }
}

unsafe fn inc_filename_truncated(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).filename_truncated += 1;
    }
}

unsafe fn inc_output_attempted(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).output_attempted += 1;
    }
}

unsafe fn inc_output_failed(stats: Option<*mut ExecStats>) {
    if let Some(stats) = stats {
        (*stats).output_failed += 1;
    }
}

unsafe fn read_parent_pid(config: &TracepointConfig) -> Result<u32, ()> {
    if config.task_real_parent_offset == 0 || config.task_tgid_offset == 0 {
        return Err(());
    }

    // Aya's generated `task_struct` binding is intentionally opaque here, so
    // userspace verifies the vmlinux BTF layout and passes byte offsets through
    // CONFIG. The helper performs only two bounded kernel reads:
    // current->real_parent and real_parent->tgid.
    let task = gen::bpf_get_current_task_btf();
    if task.is_null() {
        return Err(());
    }

    let parent_ptr = (task.cast::<u8>())
        .add(config.task_real_parent_offset as usize)
        .cast::<*mut task_struct>();
    let parent: *mut task_struct = bpf_probe_read_kernel(parent_ptr).map_err(|_| ())?;
    if parent.is_null() {
        return Err(());
    }

    let tgid_ptr = (parent.cast::<u8>())
        .add(config.task_tgid_offset as usize)
        .cast::<i32>();
    let tgid: i32 = bpf_probe_read_kernel(tgid_ptr).map_err(|_| ())?;
    if tgid <= 0 {
        return Err(());
    }

    Ok(tgid as u32)
}

#[panic_handler]
fn panic(_info: &PanicInfo<'_>) -> ! {
    loop {}
}
