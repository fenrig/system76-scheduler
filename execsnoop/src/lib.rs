// Copyright 2022 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

#![deny(missing_docs)]

//! Native eBPF exec watcher for Linux.
//!
//! This crate attaches a small eBPF program to `sched:sched_process_exec` and
//! receives fixed-size binary events over a BPF ring buffer. It intentionally
//! avoids shell commands, Python, text column parsing, locale handling, and UTF-8
//! assumptions in the hot path.
//!
//! # Kernel and permission requirements
//!
//! Loading the watcher requires a kernel with tracepoints, BPF ring buffers, and
//! readable vmlinux BTF so userspace can verify `task_struct` offsets used for
//! the parent PID read. The process normally needs `CAP_BPF` and `CAP_PERFMON`
//! on modern kernels, or equivalent root privileges on older kernels. If
//! loading, format verification, or attaching fails, [`watch`] returns an error
//! so callers can log a warning and continue without realtime exec events.

use aya::{
    include_bytes_aligned,
    maps::{Array, MapData, RingBuf},
    programs::TracePoint,
    Ebpf, Pod,
};
use std::{
    borrow::Cow,
    collections::VecDeque,
    fs, io,
    mem::{align_of, size_of},
    path::Path,
    ptr, thread,
    time::{Duration, Instant},
};

const OBJECT: &[u8] = include_bytes_aligned!(concat!(env!("OUT_DIR"), "/execsnoop.bpf.o"));
const TASK_COMM_LEN: usize = 16;
const FILENAME_LEN: usize = 256;
const EVENTS_MAP: &str = "EVENTS";
const CONFIG_MAP: &str = "CONFIG";
const STATS_MAP: &str = "STATS";
const PROGRAM: &str = "sched_process_exec";
const FLAG_FILENAME_TRUNCATED: u32 = 1 << 0;
const FLAG_FILENAME_MISSING: u32 = 1 << 2;
const BTF_KIND_STRUCT: u32 = 4;
const STATS_LOG_INTERVAL: Duration = Duration::from_secs(5);

/// Fixed-size binary event emitted by the eBPF program.
///
/// The eBPF side writes this exact layout to the `EVENTS` ring buffer.
/// Userspace decodes it only after checking the byte length, then uses
/// `ptr::read_unaligned` so ring buffer item alignment does not matter.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RawExecEvent {
    /// Process ID, using userspace PID terminology (`task->tgid`).
    pub pid: u32,
    /// Parent process ID. Zero means unavailable.
    pub parent_pid: u32,
    /// Bitmask describing truncation or missing optional fields.
    pub flags: u32,
    /// Number of bytes copied into `filename`, excluding a trailing NUL.
    pub filename_len: u32,
    /// Current task command name.
    pub comm: [u8; TASK_COMM_LEN],
    /// Executable filename/path from the tracepoint.
    pub filename: [u8; FILENAME_LEN],
}

const _: [(); 288] = [(); size_of::<RawExecEvent>()];
const _: [(); 4] = [(); align_of::<RawExecEvent>()];

/// Diagnostic counters exported by the eBPF program.
///
/// These counters are intentionally approximate: the eBPF program increments a
/// single array entry from multiple CPUs without synchronization. They are used
/// only to diagnose whether the tracepoint is entered and where events are
/// dropped before userspace receives them.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ExecStats {
    /// Tracepoint program entries.
    pub entered: u64,
    /// The config map entry was unavailable.
    pub missing_config: u64,
    /// Config offsets were unset or invalid.
    pub invalid_config: u64,
    /// The tracepoint PID field could not be read.
    pub pid_read_failed: u64,
    /// Parent PID could not be read from `task_struct`.
    pub parent_pid_failed: u64,
    /// The tracepoint filename `__data_loc` field could not be read.
    pub filename_loc_read_failed: u64,
    /// The tracepoint reported an empty filename.
    pub filename_missing: u64,
    /// The filename string read failed.
    pub filename_read_failed: u64,
    /// The filename was truncated into the fixed event buffer.
    pub filename_truncated: u64,
    /// The eBPF program attempted to emit an event to the ring buffer.
    pub output_attempted: u64,
    /// The eBPF program failed to emit an event to the ring buffer.
    pub output_failed: u64,
}

const _: [(); 88] = [(); size_of::<ExecStats>()];
const _: [(); 8] = [(); align_of::<ExecStats>()];

// `ExecStats` is a plain fixed-size `repr(C)` record of integer counters shared
// with an eBPF array map.
unsafe impl Pod for ExecStats {}

/// Process info.
#[derive(Clone, Debug)]
pub struct Process<'a> {
    /// Process name.
    pub name: &'a [u8],
    /// Process command line. Native execsnoop currently provides the executable
    /// filename/path rather than argv, because `sched_process_exec` exposes the
    /// successful exec path without unbounded argument walking.
    pub cmd: &'a [u8],
    /// Process PID.
    pub pid: u32,
    /// Process parent PID.
    pub parent_pid: u32,
}

impl<'a> Process<'a> {
    /// Process command line/path converted lossily for API consumers that need
    /// Rust strings.
    #[must_use]
    pub fn cmd_lossy(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.cmd)
    }

    /// Process name converted lossily for API consumers that need Rust strings.
    #[must_use]
    pub fn name_lossy(&self) -> Cow<'a, str> {
        String::from_utf8_lossy(self.name)
    }
}

/// Process iterator.
pub struct ProcessIterator {
    bpf: Ebpf,
    events: RingBuf<MapData>,
    pending: VecDeque<OwnedProcess>,
    name_buffer: Vec<u8>,
    cmd_buffer: Vec<u8>,
    last_stats_log: Instant,
    last_stats: ExecStats,
    stats_logs: u64,
}

impl ProcessIterator {
    /// Get the next process from the iterator.
    #[allow(clippy::should_implement_trait)]
    pub fn next(&mut self) -> Option<Process<'_>> {
        let process = self.next_owned()?;

        self.name_buffer.clear();
        self.name_buffer.extend_from_slice(&process.name);
        self.cmd_buffer.clear();
        self.cmd_buffer.extend_from_slice(&process.cmd);

        Some(Process {
            name: &self.name_buffer,
            cmd: &self.cmd_buffer,
            pid: process.pid,
            parent_pid: process.parent_pid,
        })
    }

    fn next_owned(&mut self) -> Option<OwnedProcess> {
        loop {
            if let Some(process) = self.pending.pop_front() {
                return Some(process);
            }

            while let Some(bytes) = self.events.next() {
                if let Some(event) = decode_event(&bytes) {
                    if event.flags & FLAG_FILENAME_TRUNCATED != 0 {
                        tracing::debug!("exec filename truncated for pid {}", event.pid);
                    }

                    if let Ok(process) = OwnedProcess::try_from(event) {
                        self.pending.push_back(process);
                    }
                }
            }

            self.log_stats_if_due();
            thread::sleep(Duration::from_millis(10));
        }
    }

    fn log_stats_if_due(&mut self) {
        if !tracing::enabled!(tracing::Level::DEBUG) {
            return;
        }

        if self.last_stats_log.elapsed() < STATS_LOG_INTERVAL {
            return;
        }

        self.last_stats_log = Instant::now();
        let Ok(stats) = self.stats() else {
            return;
        };

        self.stats_logs += 1;
        let changed = stats != self.last_stats;
        if changed || self.stats_logs <= 3 {
            tracing::debug!(
                entered = stats.entered,
                missing_config = stats.missing_config,
                invalid_config = stats.invalid_config,
                pid_read_failed = stats.pid_read_failed,
                parent_pid_failed = stats.parent_pid_failed,
                filename_loc_read_failed = stats.filename_loc_read_failed,
                filename_missing = stats.filename_missing,
                filename_read_failed = stats.filename_read_failed,
                filename_truncated = stats.filename_truncated,
                output_attempted = stats.output_attempted,
                output_failed = stats.output_failed,
                "native execsnoop eBPF stats"
            );
            self.last_stats = stats;
        }
    }

    /// Read diagnostic counters from the eBPF program.
    ///
    /// These counters are approximate and intended only for runtime diagnosis.
    ///
    /// # Errors
    ///
    /// Returns an error if the `STATS` map is unavailable or cannot be read.
    pub fn stats(&self) -> io::Result<ExecStats> {
        let stats = Array::<_, ExecStats>::try_from(
            self.bpf
                .map(STATS_MAP)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing STATS map"))?,
        )
        .map_err(other)?;

        stats.get(&0, 0).map_err(other)
    }
}

#[derive(Clone, Debug)]
struct OwnedProcess {
    name: Vec<u8>,
    cmd: Vec<u8>,
    pid: u32,
    parent_pid: u32,
}

impl TryFrom<RawExecEvent> for OwnedProcess {
    type Error = ();

    fn try_from(event: RawExecEvent) -> Result<Self, Self::Error> {
        if event.flags & FLAG_FILENAME_MISSING != 0 {
            return Err(());
        }
        let filename_len = usize::try_from(event.filename_len).map_err(|_error| ())?;
        let filename_len = filename_len.min(event.filename.len());
        let name_len = nul_or_len(&event.comm);
        Ok(Self {
            name: event.comm[..name_len].to_vec(),
            cmd: event.filename[..filename_len].to_vec(),
            pid: event.pid,
            parent_pid: event.parent_pid,
        })
    }
}

/// Watches successful process exec events on Linux.
///
/// # Errors
///
/// Returns an error if the kernel tracepoint format cannot be verified, the BPF
/// object cannot be loaded, or the tracepoint/ring buffer cannot be attached.
pub fn watch() -> io::Result<ProcessIterator> {
    let format = TracepointFormat::load()?;
    let task_offsets = TaskStructOffsets::load()?;
    let mut bpf = Ebpf::load(OBJECT).map_err(other)?;
    configure_offsets(&mut bpf, TracepointConfig::new(format, task_offsets))?;

    let program: &mut TracePoint = bpf
        .program_mut(PROGRAM)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing BPF program"))?
        .try_into()
        .map_err(other)?;
    program.load().map_err(other)?;
    program
        .attach("sched", "sched_process_exec")
        .map_err(other)?;

    let events = RingBuf::try_from(
        bpf.take_map(EVENTS_MAP)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing EVENTS map"))?,
    )
    .map_err(other)?;

    Ok(ProcessIterator {
        bpf,
        events,
        pending: VecDeque::new(),
        name_buffer: Vec::with_capacity(TASK_COMM_LEN),
        cmd_buffer: Vec::with_capacity(FILENAME_LEN),
        last_stats_log: Instant::now(),
        last_stats: ExecStats::default(),
        stats_logs: 0,
    })
}

fn configure_offsets(bpf: &mut Ebpf, value: TracepointConfig) -> io::Result<()> {
    let mut config = aya::maps::Array::<_, TracepointConfig>::try_from(
        bpf.map_mut(CONFIG_MAP)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing CONFIG map"))?,
    )
    .map_err(other)?;

    config.set(0, value, 0).map_err(other)
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
#[allow(clippy::struct_field_names)]
struct TracepointConfig {
    pid_offset: u32,
    filename_offset: u32,
    task_real_parent_offset: u32,
    task_tgid_offset: u32,
}

// `TracepointConfig` is a plain `repr(C)` record of `u32`s shared with the BPF
// array map. It contains no padding-sensitive references or invalid bit
// patterns.
unsafe impl Pod for TracepointConfig {}

impl TracepointConfig {
    fn new(format: TracepointFormat, task_offsets: TaskStructOffsets) -> Self {
        Self {
            pid_offset: format.pid_offset,
            filename_offset: format.filename_offset,
            task_real_parent_offset: task_offsets.real_parent,
            task_tgid_offset: task_offsets.tgid,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct TracepointFormat {
    pid_offset: u32,
    filename_offset: u32,
}

impl TracepointFormat {
    fn load() -> io::Result<Self> {
        const PATHS: [&str; 2] = [
            "/sys/kernel/tracing/events/sched/sched_process_exec/format",
            "/sys/kernel/debug/tracing/events/sched/sched_process_exec/format",
        ];

        for path in PATHS {
            match fs::read_to_string(path) {
                Ok(format) => return Self::parse(&format),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("cannot read {path}: {error}"),
                    ));
                }
                Err(error) => return Err(error),
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "sched_process_exec tracepoint format not found",
        ))
    }

    fn parse(format: &str) -> io::Result<Self> {
        let pid_offset = field_offset(format, "pid")?;
        let filename_offset = field_offset(format, "filename")?;

        Ok(Self {
            pid_offset,
            filename_offset,
        })
    }
}

fn field_offset(format: &str, name: &str) -> io::Result<u32> {
    for line in format.lines().map(str::trim) {
        if !line.starts_with("field:") || !line.contains(&format!(" {name};")) {
            continue;
        }

        for part in line.split(';').map(str::trim) {
            let Some(offset) = part.strip_prefix("offset:") else {
                continue;
            };

            return offset.trim().parse::<u32>().map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid {name} offset in tracepoint format: {error}"),
                )
            });
        }
    }

    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("missing {name} field in sched_process_exec tracepoint"),
    ))
}

#[derive(Clone, Copy, Debug)]
struct TaskStructOffsets {
    real_parent: u32,
    tgid: u32,
}

impl TaskStructOffsets {
    fn load() -> io::Result<Self> {
        let btf = fs::read("/sys/kernel/btf/vmlinux").map_err(|error| {
            io::Error::new(error.kind(), format!("cannot read vmlinux BTF: {error}"))
        })?;
        Self::parse(&btf)
    }

    fn parse(btf: &[u8]) -> io::Result<Self> {
        let parsed = Btf::parse(btf)?;
        let task = parsed
            .find_struct("task_struct")?
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing task_struct BTF"))?;

        let real_parent = task.member_offset("real_parent")?;
        let tgid = task.member_offset("tgid")?;

        Ok(Self { real_parent, tgid })
    }
}

struct Btf<'a> {
    types: &'a [u8],
    strings: &'a [u8],
}

impl<'a> Btf<'a> {
    fn parse(bytes: &'a [u8]) -> io::Result<Self> {
        if bytes.len() < 24 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short BTF header",
            ));
        }

        let magic = u16::from_le_bytes([bytes[0], bytes[1]]);
        if magic != 0xeb9f {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported BTF endianness or magic",
            ));
        }

        let version = bytes[2];
        if version != 1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported BTF version {version}"),
            ));
        }

        let header_len = read_u32(bytes, 4)? as usize;
        let type_off = read_u32(bytes, 8)? as usize;
        let type_len = read_u32(bytes, 12)? as usize;
        let str_off = read_u32(bytes, 16)? as usize;
        let str_len = read_u32(bytes, 20)? as usize;

        let types_start = header_len.checked_add(type_off).ok_or_else(invalid_btf)?;
        let types_end = types_start.checked_add(type_len).ok_or_else(invalid_btf)?;
        let strings_start = header_len.checked_add(str_off).ok_or_else(invalid_btf)?;
        let strings_end = strings_start.checked_add(str_len).ok_or_else(invalid_btf)?;

        let types = bytes.get(types_start..types_end).ok_or_else(invalid_btf)?;
        let strings = bytes
            .get(strings_start..strings_end)
            .ok_or_else(invalid_btf)?;

        Ok(Self { types, strings })
    }

    fn find_struct<'btf>(&'btf self, name: &str) -> io::Result<Option<BtfStruct<'btf, 'a>>> {
        let mut offset = 0;

        while offset < self.types.len() {
            let type_start = offset;
            let name_offset = read_u32_at(self.types, &mut offset)?;
            let info = read_u32_at(self.types, &mut offset)?;
            let size_or_type = read_u32_at(self.types, &mut offset)?;
            let kind = (info >> 24) & 0x1f;
            let kind_flag = info >> 31 != 0;
            let vlen = (info & 0xffff) as usize;

            if kind == BTF_KIND_STRUCT && self.string(name_offset)? == Some(name) {
                let members_start = offset;
                let members_len = vlen.checked_mul(12).ok_or_else(invalid_btf)?;
                let members_end = members_start
                    .checked_add(members_len)
                    .ok_or_else(invalid_btf)?;
                let members = self
                    .types
                    .get(members_start..members_end)
                    .ok_or_else(invalid_btf)?;

                return Ok(Some(BtfStruct {
                    btf: self,
                    kind_flag,
                    members,
                    _size: size_or_type,
                }));
            }

            offset = type_start
                .checked_add(type_record_len(kind, vlen)?)
                .ok_or_else(invalid_btf)?;
        }

        Ok(None)
    }

    fn string(&self, offset: u32) -> io::Result<Option<&'a str>> {
        let offset = offset as usize;
        if offset == 0 {
            return Ok(None);
        }

        let rest = self.strings.get(offset..).ok_or_else(invalid_btf)?;
        let end = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "unterminated BTF string"))?;

        Ok(std::str::from_utf8(&rest[..end]).ok())
    }
}

struct BtfStruct<'btf, 'data> {
    btf: &'btf Btf<'data>,
    kind_flag: bool,
    members: &'btf [u8],
    _size: u32,
}

impl BtfStruct<'_, '_> {
    fn member_offset(&self, name: &str) -> io::Result<u32> {
        for member in self.members.chunks_exact(12) {
            let name_offset = read_u32(member, 0)?;
            let bit_offset = read_u32(member, 8)?;
            let field_name = self.btf.string(name_offset)?;

            if field_name != Some(name) {
                continue;
            }

            let bitfield_size = if self.kind_flag { bit_offset >> 24 } else { 0 };
            if bitfield_size != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("task_struct.{name} is unexpectedly a bitfield"),
                ));
            }

            let bit_offset = if self.kind_flag {
                bit_offset & 0x00ff_ffff
            } else {
                bit_offset
            };

            if bit_offset % 8 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("task_struct.{name} is not byte-aligned"),
                ));
            }

            return Ok(bit_offset / 8);
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("missing task_struct.{name} BTF member"),
        ))
    }
}

fn type_record_len(kind: u32, vlen: usize) -> io::Result<usize> {
    let extra = match kind {
        0 | 2 | 7..=12 | 16 | 18 => 0,
        1 | 14 | 17 => 4,
        3 => 12,
        4 | 5 | 15 | 19 => vlen.checked_mul(12).ok_or_else(invalid_btf)?,
        6 | 13 => vlen.checked_mul(8).ok_or_else(invalid_btf)?,
        unknown => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported BTF kind {unknown}"),
            ));
        }
    };

    12usize.checked_add(extra).ok_or_else(invalid_btf)
}

fn read_u32(bytes: &[u8], offset: usize) -> io::Result<u32> {
    let end = offset.checked_add(4).ok_or_else(invalid_btf)?;
    let bytes = bytes
        .get(offset..end)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short BTF record"))?;

    Ok(u32::from_le_bytes(
        bytes.try_into().expect("slice length checked above"),
    ))
}

fn read_u32_at(bytes: &[u8], offset: &mut usize) -> io::Result<u32> {
    let value = read_u32(bytes, *offset)?;
    *offset = offset.checked_add(4).ok_or_else(invalid_btf)?;
    Ok(value)
}

fn invalid_btf() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid BTF data")
}

fn decode_event(bytes: &[u8]) -> Option<RawExecEvent> {
    if bytes.len() != size_of::<RawExecEvent>() {
        tracing::debug!("dropping malformed exec event of {} bytes", bytes.len());
        return None;
    }

    // Ring buffer items do not guarantee alignment for our Rust type. The length is
    // checked above, and `RawExecEvent` is a plain fixed-size `repr(C)` record,
    // so an unaligned copy is the narrowest unsafe operation needed here.
    Some(unsafe { ptr::read_unaligned(bytes.as_ptr().cast::<RawExecEvent>()) })
}

fn nul_or_len(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len())
}

fn other(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::other(error)
}

#[allow(dead_code)]
fn _object_exists_for_docs(path: &Path) -> bool {
    path.exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(comm: &[u8], filename: &[u8], flags: u32) -> RawExecEvent {
        let mut event = RawExecEvent {
            pid: 42,
            parent_pid: 7,
            flags,
            filename_len: filename.len().min(FILENAME_LEN) as u32,
            comm: [0; TASK_COMM_LEN],
            filename: [0; FILENAME_LEN],
        };
        event.comm[..comm.len().min(TASK_COMM_LEN)]
            .copy_from_slice(&comm[..comm.len().min(TASK_COMM_LEN)]);
        event.filename[..filename.len().min(FILENAME_LEN)]
            .copy_from_slice(&filename[..filename.len().min(FILENAME_LEN)]);
        event
    }

    fn bytes(event: &RawExecEvent) -> &[u8] {
        // The test constructs an initialized `repr(C)` value and views exactly
        // its object bytes for decoder round-trips.
        unsafe {
            std::slice::from_raw_parts(ptr::from_ref(event).cast::<u8>(), size_of::<RawExecEvent>())
        }
    }

    #[test]
    fn decodes_binary_event_with_spaces() {
        let raw = event(b"my shell", b"/tmp/path with spaces/script", 0);
        let decoded = decode_event(bytes(&raw)).unwrap();
        let process = OwnedProcess::try_from(decoded).unwrap();
        assert_eq!(process.name, b"my shell");
        assert_eq!(process.cmd, b"/tmp/path with spaces/script");
    }

    #[test]
    fn preserves_newline_like_bytes() {
        let raw = event(b"runner", b"/tmp/script\narg", 0);
        let process = OwnedProcess::try_from(decode_event(bytes(&raw)).unwrap()).unwrap();
        assert_eq!(process.cmd, b"/tmp/script\narg");
    }

    #[test]
    fn lossy_conversion_handles_invalid_utf8() {
        let raw = event(b"bad\xffname", b"/tmp/\xff/bin", 0);
        let process = OwnedProcess::try_from(decode_event(bytes(&raw)).unwrap()).unwrap();
        let public = Process {
            name: &process.name,
            cmd: &process.cmd,
            pid: process.pid,
            parent_pid: process.parent_pid,
        };

        assert_eq!(public.name_lossy(), "bad\u{fffd}name");
        assert_eq!(public.cmd_lossy(), "/tmp/\u{fffd}/bin");
    }

    #[test]
    fn keeps_truncation_boundary() {
        let filename = [b'a'; FILENAME_LEN];
        let raw = event(b"boundary", &filename, FLAG_FILENAME_TRUNCATED);
        let process = OwnedProcess::try_from(decode_event(bytes(&raw)).unwrap()).unwrap();
        assert_eq!(process.cmd.len(), FILENAME_LEN);
        assert!(raw.flags & FLAG_FILENAME_TRUNCATED != 0);
    }

    #[test]
    fn missing_parent_pid_stays_zero() {
        let mut raw = event(b"runner", b"/bin/true", 1 << 1);
        raw.parent_pid = 0;
        let process = OwnedProcess::try_from(decode_event(bytes(&raw)).unwrap()).unwrap();
        assert_eq!(process.parent_pid, 0);
    }

    #[test]
    fn rejects_short_binary_event() {
        assert!(decode_event(&[0; 12]).is_none());
    }

    #[test]
    fn embedded_bpf_object_parses() {
        match Ebpf::load(OBJECT) {
            Ok(_bpf) => {}
            Err(aya::EbpfError::ParseError(error)) => {
                panic!("embedded BPF object should parse: {error}");
            }
            Err(_post_parse_error) => {}
        }
    }

    #[test]
    fn parses_tracepoint_format_offsets() {
        let format = "\
field:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;
field:pid_t pid;\toffset:24;\tsize:4;\tsigned:1;
field:__data_loc char[] filename;\toffset:32;\tsize:4;\tsigned:1;
";
        let parsed = TracepointFormat::parse(format).unwrap();
        assert_eq!(parsed.pid_offset, 24);
        assert_eq!(parsed.filename_offset, 32);
    }

    #[test]
    fn parses_task_struct_offsets_from_btf() {
        let strings = b"\0task_struct\0real_parent\0tgid\0";
        let task_struct_name = 1u32;
        let real_parent_name = 13u32;
        let tgid_name = 25u32;
        let mut btf = Vec::new();

        btf.extend_from_slice(&0xeb9fu16.to_le_bytes());
        btf.push(1);
        btf.push(0);
        btf.extend_from_slice(&24u32.to_le_bytes());
        btf.extend_from_slice(&0u32.to_le_bytes());
        btf.extend_from_slice(&36u32.to_le_bytes());
        btf.extend_from_slice(&36u32.to_le_bytes());
        btf.extend_from_slice(&(strings.len() as u32).to_le_bytes());

        btf.extend_from_slice(&task_struct_name.to_le_bytes());
        btf.extend_from_slice(&((BTF_KIND_STRUCT << 24) | 2).to_le_bytes());
        btf.extend_from_slice(&64u32.to_le_bytes());
        btf.extend_from_slice(&real_parent_name.to_le_bytes());
        btf.extend_from_slice(&1u32.to_le_bytes());
        btf.extend_from_slice(&(16u32 * 8).to_le_bytes());
        btf.extend_from_slice(&tgid_name.to_le_bytes());
        btf.extend_from_slice(&2u32.to_le_bytes());
        btf.extend_from_slice(&(32u32 * 8).to_le_bytes());
        btf.extend_from_slice(strings);

        let offsets = TaskStructOffsets::parse(&btf).unwrap();
        assert_eq!(offsets.real_parent, 16);
        assert_eq!(offsets.tgid, 32);
    }
}
