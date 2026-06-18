// Copyright 2021 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

pub mod paths;

use crate::config::eevdf::Profile;
use paths::SchedPaths;
use std::fmt::Display;
use std::io::Write;
use std::{fs, io};

/// Apply an EEVDF scheduler profile.
pub fn tweak(paths: &SchedPaths, conf: &Profile) {
    write_value(paths.base_slice_ns, conf.base_slice_ns);

    if let Some(preempt_path) = paths.preempt {
        write_value(preempt_path, conf.preempt);
    }
}

/// Write a value that implements `Display` to a file.
fn write_value<V: Display>(path: &str, value: V) {
    let write_to_file = |path, value| -> io::Result<()> {
        let mut file = fs::File::create(path)?;
        write!(file, "{value}")?;

        Ok(())
    };

    if let Err(why) = write_to_file(path, value) {
        tracing::warn!("failed to set value in {path}: {why}");
    }
}
