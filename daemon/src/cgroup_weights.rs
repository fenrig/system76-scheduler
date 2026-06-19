// Copyright 2026 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

use std::collections::BTreeMap;
use std::path::{Component, Path, PathBuf};

use system76_scheduler_config::scheduler::{CgroupWeight, CgroupWeights};

#[derive(Debug)]
struct AppliedWeight {
    previous: CgroupWeight,
    current: CgroupWeight,
}

#[derive(Debug, Default)]
pub(crate) struct State {
    applied: BTreeMap<String, AppliedWeight>,
}

impl State {
    pub(crate) fn reconcile(
        &mut self,
        config: Option<&CgroupWeights>,
        desired: BTreeMap<String, CgroupWeight>,
    ) {
        let Some(config) = config.filter(|config| config.enable) else {
            self.restore_all();
            return;
        };

        self.restore_stale(&desired);

        for (cgroup, weight) in desired {
            if let Some(applied) = self.applied.get_mut(&cgroup) {
                if applied.current == weight {
                    continue;
                }

                if write_weight(&cgroup, weight).is_ok() {
                    applied.current = weight;
                }

                continue;
            }

            let previous = read_weight(&cgroup).unwrap_or(config.default);

            if write_weight(&cgroup, weight).is_ok() {
                self.applied.insert(
                    cgroup,
                    AppliedWeight {
                        previous,
                        current: weight,
                    },
                );
            }
        }
    }

    fn restore_stale(&mut self, desired: &BTreeMap<String, CgroupWeight>) {
        let stale = self
            .applied
            .keys()
            .filter(|cgroup| !desired.contains_key(*cgroup))
            .cloned()
            .collect::<Vec<_>>();

        for cgroup in stale {
            self.restore(&cgroup);
        }
    }

    fn restore_all(&mut self) {
        for cgroup in self.applied.keys().cloned().collect::<Vec<_>>() {
            self.restore(&cgroup);
        }
    }

    fn restore(&mut self, cgroup: &str) {
        let Some(applied) = self.applied.remove(cgroup) else {
            return;
        };

        let _res = write_weight(cgroup, applied.previous);
    }
}

fn read_weight(cgroup: &str) -> Option<CgroupWeight> {
    let cpu = std::fs::read_to_string(cgroup_file(cgroup, "cpu.weight")?)
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let io = std::fs::read_to_string(cgroup_file(cgroup, "io.weight")?)
        .ok()?
        .trim()
        .parse()
        .ok()?;

    Some(CgroupWeight::new(cpu, io))
}

fn write_weight(cgroup: &str, weight: CgroupWeight) -> std::io::Result<()> {
    let Some(cpu_path) = cgroup_file(cgroup, "cpu.weight") else {
        tracing::debug!(cgroup, "ignoring invalid cgroup path");
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    };
    let Some(io_path) = cgroup_file(cgroup, "io.weight") else {
        tracing::debug!(cgroup, "ignoring invalid cgroup path");
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    };

    let cpu = std::fs::write(cpu_path, weight.cpu.to_string());
    let io = std::fs::write(io_path, weight.io.to_string());

    match (cpu, io) {
        (Ok(()), Ok(())) => Ok(()),
        (Ok(()), Err(error)) | (Err(error), Ok(())) => {
            tracing::debug!(cgroup, error = %error, "partially applied cgroup weights");
            Ok(())
        }
        (Err(error), Err(_)) => Err(error),
    }
}

fn cgroup_file(cgroup: &str, file: &str) -> Option<PathBuf> {
    if !cgroup.starts_with('/') || cgroup.as_bytes().contains(&0) {
        return None;
    }

    let mut path = PathBuf::from("/sys/fs/cgroup");

    for component in Path::new(cgroup).components() {
        match component {
            Component::RootDir => (),
            Component::Normal(component) => path.push(component),
            _ => return None,
        }
    }

    path.push(file);
    Some(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cgroup_file_accepts_absolute_cgroup_paths() {
        assert_eq!(
            cgroup_file(
                "/user.slice/user-1000.slice/app.slice/app.scope",
                "cpu.weight"
            )
            .unwrap(),
            PathBuf::from(
                "/sys/fs/cgroup/user.slice/user-1000.slice/app.slice/app.scope/cpu.weight"
            )
        );
    }

    #[test]
    fn cgroup_file_rejects_relative_or_traversing_paths() {
        assert!(cgroup_file("user.slice/app.scope", "cpu.weight").is_none());
        assert!(cgroup_file("/user.slice/../system.slice", "cpu.weight").is_none());
        assert!(cgroup_file("/user.slice/\0/system.slice", "cpu.weight").is_none());
    }
}
