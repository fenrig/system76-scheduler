// Copyright 2021-2022 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

use std::path::Path;

pub const BASE_SLICE_NS_PATH: &str = "/sys/kernel/debug/sched/base_slice_ns";
pub const PREEMPT_PATH: &str = "/sys/kernel/debug/sched/preempt";

#[derive(Debug, thiserror::Error)]
pub enum SchedPathsError {
    #[error("kernel does not support EEVDF scheduler tuning")]
    NotSupported,
}

#[allow(clippy::module_name_repetitions)]
pub struct SchedPaths {
    pub base_slice_ns: &'static str,
    pub preempt: Option<&'static str>,
}

impl SchedPaths {
    pub fn new() -> Result<Self, SchedPathsError> {
        if !Path::new(BASE_SLICE_NS_PATH).exists() {
            return Err(SchedPathsError::NotSupported);
        }

        Ok(Self {
            base_slice_ns: BASE_SLICE_NS_PATH,
            preempt: Path::new(PREEMPT_PATH).exists().then_some(PREEMPT_PATH),
        })
    }
}
