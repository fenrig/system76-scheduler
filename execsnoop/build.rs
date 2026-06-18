// Copyright 2026 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

fn main() {
    println!("cargo:rerun-if-changed=ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=ebpf/src/lib.rs");

    if let Err(error) = build_bpf() {
        panic!("failed to build execsnoop eBPF object: {error}");
    }
}

fn build_bpf() -> io::Result<()> {
    let cargo = env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets it"));
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").expect("cargo sets it"));
    let ebpf_target_dir = out_dir.join("ebpf-target");
    let bitcode = out_dir.join("execsnoop.bpf.bc");
    let raw_object = out_dir.join("execsnoop.bpf.raw.o");
    let patched_object = out_dir.join("execsnoop.bpf.patched.o");
    let object = out_dir.join("execsnoop.bpf.o");

    let status = Command::new(cargo)
        .args([
            "rustc",
            "--manifest-path",
            manifest_dir
                .join("ebpf/Cargo.toml")
                .to_str()
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "non-UTF-8 manifest path")
                })?,
            "--target",
            "bpfel-unknown-none",
            "--release",
            "-Z",
            "build-std=core",
            "--",
            "--emit=obj",
        ])
        .env("CARGO_TARGET_DIR", &ebpf_target_dir)
        .env("RUSTC_BOOTSTRAP", "1")
        .env("RUSTFLAGS", "-C debuginfo=2")
        .status()?;

    if !status.success() {
        return Err(io::Error::other("cargo returned a non-zero status"));
    }

    let deps = ebpf_target_dir
        .join("bpfel-unknown-none")
        .join("release")
        .join("deps");
    let built = fs::read_dir(&deps)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| is_ebpf_object(path))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "missing eBPF object"))?;

    fs::copy(&built, &bitcode)?;

    let status = Command::new("llc")
        .args(["-march=bpfel", "-filetype=obj"])
        .arg(&bitcode)
        .arg("-o")
        .arg(&raw_object)
        .status()?;

    if !status.success() {
        return Err(io::Error::other("llc returned a non-zero status"));
    }

    patch_helper_calls(&raw_object, &patched_object)?;

    fs::copy(&patched_object, &object)?;
    fs::metadata(object).map(|_| ())
}

fn is_ebpf_object(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.starts_with("execsnoop_ebpf-")
                && Path::new(name)
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("o"))
        })
}

fn patch_helper_calls(input: &Path, output: &Path) -> io::Result<()> {
    let mut elf = fs::read(input)?;
    let sections = sections(&elf)?;

    // This toolchain emits BPF target objects as LLVM bitcode, so the build
    // drives `llc` manually. That path leaves Aya helper shims as pseudo-call
    // relocations. Aya userspace only relocates real BPF-to-BPF calls, so patch
    // known helper call sites to the kernel helper ABI: src_reg = 0, imm = id.
    for relocation_section in sections.iter().filter(|section| section.kind == SHT_REL) {
        let Some(target_section) = sections.get(relocation_section.info as usize) else {
            return Err(invalid_elf("relocation target section out of range"));
        };
        let Some(symbol_section) = sections.get(relocation_section.link as usize) else {
            return Err(invalid_elf("relocation symbol section out of range"));
        };
        if symbol_section.kind != SHT_SYMTAB {
            continue;
        }
        let Some(string_section) = sections.get(symbol_section.link as usize) else {
            return Err(invalid_elf("symbol string section out of range"));
        };

        let relocations = relocation_section.size / relocation_section.entry_size;
        for index in 0..relocations {
            let relocation_offset = relocation_section
                .offset
                .checked_add(index * relocation_section.entry_size)
                .ok_or_else(|| invalid_elf("relocation offset overflow"))?;
            let instruction_offset = read_u64(&elf, relocation_offset)?;
            let info = read_u64(&elf, relocation_offset + 8)?;
            let symbol_index = info >> 32;
            let symbol_offset = symbol_section
                .offset
                .checked_add(symbol_index * symbol_section.entry_size)
                .ok_or_else(|| invalid_elf("symbol offset overflow"))?;
            let name_offset = read_u32(&elf, symbol_offset)?;
            let Some(name) = elf_string(&elf, string_section, name_offset)? else {
                continue;
            };
            let Some(helper_id) = helper_id(name) else {
                continue;
            };

            let instruction_offset = target_section
                .offset
                .checked_add(instruction_offset)
                .ok_or_else(|| invalid_elf("instruction offset overflow"))?;
            patch_call_instruction(&mut elf, instruction_offset, helper_id)?;
        }
    }

    fs::write(output, elf)
}

fn patch_call_instruction(elf: &mut [u8], offset: u64, helper_id: i32) -> io::Result<()> {
    let offset = usize::try_from(offset).map_err(|_error| invalid_elf("offset too large"))?;
    let instruction = elf
        .get_mut(offset..offset + 8)
        .ok_or_else(|| invalid_elf("short BPF instruction"))?;

    if instruction[0] != 0x85 {
        return Err(invalid_elf("helper relocation does not point to a call"));
    }

    instruction[1] &= 0x0f;
    instruction[4..8].copy_from_slice(&helper_id.to_le_bytes());
    Ok(())
}

fn helper_id(name: &str) -> Option<i32> {
    [
        ("bpf_map_lookup_elem", 1),
        ("bpf_probe_read", 4),
        ("bpf_get_current_comm", 16),
        ("bpf_perf_event_output", 25),
        ("bpf_probe_read_kernel", 113),
        ("bpf_probe_read_kernel_str", 115),
        ("bpf_ringbuf_output", 130),
        ("bpf_ringbuf_reserve", 131),
        ("bpf_ringbuf_submit", 132),
        ("bpf_ringbuf_discard", 133),
        ("bpf_get_current_task_btf", 158),
    ]
    .into_iter()
    .find_map(|(symbol, id)| name.ends_with(symbol).then_some(id))
}

#[derive(Clone, Copy, Debug)]
struct Section {
    kind: u32,
    offset: u64,
    size: u64,
    link: u32,
    info: u32,
    entry_size: u64,
}

const SHT_SYMTAB: u32 = 2;
const SHT_REL: u32 = 9;

fn sections(elf: &[u8]) -> io::Result<Vec<Section>> {
    if elf.len() < 64 || &elf[..4] != b"\x7fELF" || elf[4] != 2 || elf[5] != 1 {
        return Err(invalid_elf("unsupported ELF header"));
    }

    let section_header_offset = read_u64(elf, 40)?;
    let section_header_size = u64::from(read_u16(elf, 58)?);
    let section_count = u64::from(read_u16(elf, 60)?);

    if section_header_size < 64 {
        return Err(invalid_elf("short section header size"));
    }

    let mut sections = Vec::with_capacity(
        usize::try_from(section_count).map_err(|_error| invalid_elf("too many sections"))?,
    );
    for index in 0..section_count {
        let offset = section_header_offset
            .checked_add(index * section_header_size)
            .ok_or_else(|| invalid_elf("section header offset overflow"))?;
        sections.push(Section {
            kind: read_u32(elf, offset + 4)?,
            offset: read_u64(elf, offset + 24)?,
            size: read_u64(elf, offset + 32)?,
            link: read_u32(elf, offset + 40)?,
            info: read_u32(elf, offset + 44)?,
            entry_size: read_u64(elf, offset + 56)?,
        });
    }

    Ok(sections)
}

fn elf_string<'a>(elf: &'a [u8], section: &Section, offset: u32) -> io::Result<Option<&'a str>> {
    if offset == 0 {
        return Ok(None);
    }

    let start = section
        .offset
        .checked_add(u64::from(offset))
        .ok_or_else(|| invalid_elf("string offset overflow"))?;
    let start = usize::try_from(start).map_err(|_error| invalid_elf("string offset too large"))?;
    let end = elf[start..]
        .iter()
        .position(|byte| *byte == 0)
        .map(|end| start + end)
        .ok_or_else(|| invalid_elf("unterminated ELF string"))?;

    Ok(std::str::from_utf8(&elf[start..end]).ok())
}

fn read_u16(bytes: &[u8], offset: u64) -> io::Result<u16> {
    let bytes = read_bytes::<2>(bytes, offset)?;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(bytes: &[u8], offset: u64) -> io::Result<u32> {
    let bytes = read_bytes::<4>(bytes, offset)?;
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64(bytes: &[u8], offset: u64) -> io::Result<u64> {
    let bytes = read_bytes::<8>(bytes, offset)?;
    Ok(u64::from_le_bytes(bytes))
}

fn read_bytes<const N: usize>(bytes: &[u8], offset: u64) -> io::Result<[u8; N]> {
    let offset = usize::try_from(offset).map_err(|_error| invalid_elf("offset too large"))?;
    let bytes = bytes
        .get(offset..offset + N)
        .ok_or_else(|| invalid_elf("short ELF data"))?;
    Ok(bytes.try_into().expect("slice length checked above"))
}

fn invalid_elf(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
