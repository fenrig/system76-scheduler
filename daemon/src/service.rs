// Copyright 2022 System76 <debug@system76.com>
// SPDX-License-Identifier: MPL-2.0

use crate::cgroup_weights;
use crate::config::scheduler::Profile;
use crate::eevdf::paths::SchedPaths;
use crate::process::{self, Process};
use crate::utils::Buffer;
use qcell::{LCell, LCellOwner};
use std::collections::BTreeMap;
use std::{os::unix::prelude::OsStrExt, sync::Arc};
use system76_scheduler_config::scheduler::Condition;
use system76_scheduler_pipewire::ProcessKind;

pub struct Service<'owner> {
    pub config: crate::config::Config,
    assign_scan: Vec<u32>,
    assign_scanned: Vec<u32>,
    assign_tasks: Vec<u32>,
    cgroup_weights: cgroup_weights::State,
    eevdf_paths: Option<SchedPaths>,
    foreground_processes: Vec<u32>,
    foreground: Option<ForegroundTarget>,
    gc_counter: usize,
    owner: LCellOwner<'owner>,
    pipewire_capture_processes: Vec<u32>,
    pipewire_playback_processes: Vec<u32>,
    process_map: process::Map<'owner>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ForegroundTarget {
    Process(u32),
    Cgroup(String),
}

impl<'owner> Service<'owner> {
    pub fn new(owner: LCellOwner<'owner>) -> Self {
        Self {
            assign_scan: Vec::with_capacity(16),
            assign_scanned: Vec::with_capacity(16),
            assign_tasks: Vec::with_capacity(16),
            cgroup_weights: cgroup_weights::State::default(),
            eevdf_paths: SchedPaths::new().ok(),
            config: crate::config::Config::default(),
            foreground_processes: Vec::with_capacity(256),
            foreground: None,
            gc_counter: 0,
            owner,
            pipewire_capture_processes: Vec::with_capacity(4),
            pipewire_playback_processes: Vec::with_capacity(4),
            process_map: process::Map::default(),
        }
    }

    pub fn assign_process_priority(&mut self, process: &LCell<'owner, Process<'owner>>) {
        if OwnedPriority::NotAssignable != process.ro(&self.owner).assigned_priority {
            return;
        }

        let priority = (|| {
            let process = process.ro(&self.owner);

            if self.process_is_exception(process) {
                return OwnedPriority::Exception;
            }

            if let Some(profile) = self
                .config
                .process_scheduler
                .assignments
                .get_by_cmdline(&process.cmdline)
            {
                return OwnedPriority::Config(profile.clone());
            }

            if let Some(profile) = self
                .config
                .process_scheduler
                .assignments
                .get_by_name(&process.name)
            {
                return OwnedPriority::Config(profile.clone());
            }

            if process.cgroup.is_empty() {
                return OwnedPriority::NotAssignable;
            }

            // True when all conditions for a profile are met by a process.
            let condition_met = |condition: &Condition| {
                if let Some(ref cgroup) = condition.cgroup {
                    if !cgroup.matches(&process.cgroup) {
                        return false;
                    }
                }

                if let Some(ref name) = condition.name {
                    if !name.matches(&process.name) {
                        return false;
                    }
                }

                if !condition.parent.is_empty() {
                    let mut has_parent = false;

                    if let Some(parent) = process.parent() {
                        let parent = parent.ro(&self.owner);
                        has_parent = condition
                            .parent
                            .iter()
                            .any(|condition| condition.matches(&parent.name));
                    }

                    if !has_parent {
                        return false;
                    }
                }

                if let Some(ref descends_condition) = condition.descends {
                    let is_ancestor = process.ancestors(&self.owner).any(|parent| {
                        let parent = parent.ro(&self.owner);
                        descends_condition.matches(&parent.name)
                    });

                    if !is_ancestor {
                        return false;
                    }
                }

                true
            };

            'outer: for (profile, conditions) in self
                .config
                .process_scheduler
                .assignments
                .conditions
                .values()
            {
                let mut assigned_profile = None;

                for (condition, include) in conditions {
                    match (condition_met(condition), *include) {
                        // Condition met for an include rule
                        (true, true) => assigned_profile = Some(profile),
                        // Condition met for an exclude rule
                        (true, false) => continue 'outer,
                        _ => (),
                    }
                }

                if let Some(profile) = assigned_profile.take() {
                    return OwnedPriority::Config(profile.clone());
                }
            }

            OwnedPriority::Assignable
        })();

        process.rw(&mut self.owner).assigned_priority = priority;
    }

    /// Assigns children of a process in case they've not been assigned.
    pub fn assign_children(&mut self, buffer: &mut Buffer, pid: u32) {
        let mut tasks = Vec::new();
        let mut scan = Vec::new();
        let mut scanned = Vec::new();

        std::mem::swap(&mut tasks, &mut self.assign_tasks);
        std::mem::swap(&mut scan, &mut self.assign_scan);
        std::mem::swap(&mut scanned, &mut self.assign_scanned);

        scanned.clear();
        scan.push(pid);

        while let Some(process) = scan.pop() {
            scanned.push(process);

            for pid in process::children(buffer, process) {
                if !(scan.contains(&pid) || scanned.contains(&pid)) {
                    scan.push(pid);
                }
            }

            tasks.push(process);
        }

        for pid in tasks.drain(..) {
            if self.process_map.get_pid(pid).is_none() {
                let Some(parent_pid) = process::parent_id(buffer, pid) else {
                    continue;
                };

                let Some(cmdline) = process::cmdline(buffer, pid) else {
                    continue;
                };

                let name = process::name(&cmdline).to_owned();

                self.assign_new_process(buffer, pid, parent_pid, name, cmdline);
            }
        }

        std::mem::swap(&mut tasks, &mut self.assign_tasks);
        std::mem::swap(&mut scan, &mut self.assign_scan);
        std::mem::swap(&mut scanned, &mut self.assign_scanned);
    }

    /// Assign a priority to a newly-created process, and record that process in the map.
    pub fn assign_new_process(
        &mut self,
        buffer: &mut Buffer,
        pid: u32,
        parent_pid: u32,
        name: String,
        mut cmdline: String,
    ) {
        let parent = self.process_map.get_pid(parent_pid).cloned();

        let mut cgroup = String::new();

        if process::exists(buffer, pid) {
            if cmdline.is_empty() {
                cmdline = process::cmdline(buffer, pid).unwrap_or_default();
            }

            cgroup = process::cgroup(buffer, pid)
                .map(String::from)
                .unwrap_or_default();
        }

        // Add the process to the map, if it does not already exist.
        let process = self.process_map.insert(
            &mut self.owner,
            Process {
                id: pid,
                parent_id: parent_pid,
                cgroup,
                cmdline,
                name,
                parent: parent.as_ref().map(Arc::downgrade),
                ..Process::default()
            },
        );

        let mut pipewire_ancestor = None;

        'outer: for process in process.ro(&self.owner).ancestors(&self.owner) {
            let process = process.ro(&self.owner);
            for &ancestor in &self.pipewire_capture_processes {
                if process.id == ancestor || process.parent_id == ancestor {
                    pipewire_ancestor = Some(ancestor);
                    break 'outer;
                }
            }

            for &ancestor in &self.pipewire_playback_processes {
                if process.id == ancestor || process.parent_id == ancestor {
                    pipewire_ancestor = Some(ancestor);
                    break 'outer;
                }
            }
        }

        if pipewire_ancestor.is_some() {
            process.rw(&mut self.owner).pipewire_ancestor = pipewire_ancestor;
        }

        self.assign_process_priority(&process);
        self.apply_process_priority(buffer, process.ro(&self.owner));
        self.reconcile_cgroup_weights(buffer);
    }

    pub fn apply_process_priority(&self, buffer: &mut Buffer, process: &Process<'owner>) {
        let profile_default;

        let profile = match process.assigned_priority.as_ref() {
            Priority::Assignable => {
                if let Some(kind) = self.process_is_pipewire_kind(process) {
                    if kind == ProcessKind::Capture {
                        if let Some(profile) = self.config.process_scheduler.pipewire.as_ref() {
                            crate::priority::set(buffer, process.id, profile);
                            return;
                        }
                    }
                }

                if let Some(assignments) = &self.config.process_scheduler.foreground {
                    if self.process_is_foreground(process) {
                        &assignments.foreground
                    } else if let Some(kind) = self.process_is_pipewire_kind(process) {
                        if kind == ProcessKind::Playback {
                            if let Some(profile) =
                                self.config.process_scheduler.pipewire_playback.as_ref()
                            {
                                crate::priority::set(buffer, process.id, profile);
                                return;
                            }
                        }

                        &assignments.background
                    } else {
                        &assignments.background
                    }
                } else if let Some(kind) = self.process_is_pipewire_kind(process) {
                    if kind == ProcessKind::Playback {
                        if let Some(profile) =
                            self.config.process_scheduler.pipewire_playback.as_ref()
                        {
                            crate::priority::set(buffer, process.id, profile);
                            return;
                        }
                    }

                    profile_default = Profile::new(Arc::from("default"));
                    &profile_default
                } else {
                    profile_default = Profile::new(Arc::from("default"));
                    &profile_default
                }
            }

            Priority::Config(profile) => profile,

            _ => return,
        };

        crate::priority::set(buffer, process.id, profile);
    }

    pub fn eevdf_apply(&self, config: &crate::config::eevdf::Profile) {
        let Some(paths) = &self.eevdf_paths else {
            return;
        };

        if !self.config.eevdf_profiles.enable {
            return;
        }

        crate::eevdf::tweak(paths, config);
    }

    pub fn eevdf_on_battery(&self, on_battery: bool) {
        self.eevdf_apply(if on_battery {
            self.eevdf_default_config()
        } else {
            self.eevdf_responsive_config()
        });
    }

    pub fn eevdf_config(&self, name: &str) -> Option<&crate::config::eevdf::Profile> {
        self.config.eevdf_profiles.profiles.get(name)
    }

    pub fn eevdf_default_config(&self) -> &crate::config::eevdf::Profile {
        self.eevdf_config("default")
            .unwrap_or(&crate::config::eevdf::PROFILE_DEFAULT)
    }

    pub fn eevdf_responsive_config(&self) -> &crate::config::eevdf::Profile {
        self.eevdf_config("responsive")
            .unwrap_or(&crate::config::eevdf::PROFILE_RESPONSIVE)
    }

    /// Periodically shrinks buffers and removes dead processes to keep total memory consumption low.
    pub fn garbage_clean(&mut self, buffer: &mut Buffer) {
        if self.gc_counter < 2048 {
            self.gc_counter += 1;
            return;
        }

        self.gc_counter = 0;

        buffer.shrink();

        let Ok(procfs) = std::fs::read_dir("/proc/") else {
            tracing::error!("failed to read /proc directory: process monitoring stopped");
            return;
        };

        self.process_map.drain_filter_prepare();

        for proc_entry in procfs.filter_map(Result::ok) {
            let file_name = proc_entry.file_name();

            let mut process = Process::default();

            match atoi::atoi::<u32>(file_name.as_bytes()) {
                Some(pid) => process.id = pid,
                None => continue,
            }

            // Processes without a command line path are kernel threads
            if process::cmdline(buffer, process.id).is_none() {
                continue;
            }

            if let Some(ppid) = process::parent_id(buffer, process.id) {
                process.parent_id = ppid;
            }

            self.process_map.retain_process_tree(&self.owner, &process);
            self.process_map_insert(process);
        }

        self.process_map.drain_filter(&self.owner);
    }

    /// Gets the config-assigned priority of a process.
    #[must_use]
    pub fn process_assignment(&self, pid: u32) -> Priority {
        let Some(process) = self.process_map.get_pid(pid) else {
            return Priority::NotAssignable;
        };

        process.ro(&self.owner).assigned_priority.as_ref()
    }

    // Check if the `process` has descended from the `ancestor`
    pub fn process_descended_from(&self, process: &Process<'owner>, ancestor: u32) -> bool {
        if process.parent_id == ancestor {
            return true;
        }

        process.ancestors(&self.owner).any(|process| {
            let process = process.ro(&self.owner);
            process.id == ancestor || process.parent_id == ancestor
        })
    }

    // Check if the `process` is excepted from process priority changes
    pub fn process_is_exception(&self, process: &Process<'owner>) -> bool {
        // Return if listed as an exception by its cmdline path
        if self
            .config
            .process_scheduler
            .assignments
            .is_exception_by_cmdline(&process.cmdline)
        {
            return true;
        }

        // Return if listed as an exception by process name
        if self
            .config
            .process_scheduler
            .assignments
            .is_exception_by_name(&process.name)
        {
            return true;
        }

        // Condition-based exceptions
        for condition in &self
            .config
            .process_scheduler
            .assignments
            .exceptions_conditions
        {
            // Checks if the process descends from an excepted parent process.
            if let Some(condition) = &condition.descends {
                if !condition.matches(&process.forked_name) {
                    let ancestry_match = process.ancestors(&self.owner).any(|parent| {
                        let parent = parent.ro(&self.owner);
                        condition.matches(&parent.name) || condition.matches(&parent.forked_name)
                    });

                    if !ancestry_match {
                        continue;
                    }
                }
            }

            // Checks if a process has a direct parent of the same name.
            if !condition.parent.is_empty() {
                let parent_match = condition.parent.iter().any(|condition| {
                    process.parent().map_or(false, |parent| {
                        let parent = parent.ro(&self.owner);
                        condition.matches(&parent.name) || condition.matches(&parent.forked_name)
                    })
                });

                if !parent_match {
                    continue;
                }
            }

            return true;
        }

        false
    }

    pub fn process_is_pipewire_kind(&self, process: &Process<'owner>) -> Option<ProcessKind> {
        let root = process.pipewire_ancestor.unwrap_or(process.id);

        if self.pipewire_capture_processes.contains(&root) {
            Some(ProcessKind::Capture)
        } else if self.pipewire_playback_processes.contains(&root) {
            Some(ProcessKind::Playback)
        } else {
            None
        }
    }

    pub fn process_is_foreground(&self, process: &Process<'owner>) -> bool {
        let Some(foreground) = &self.foreground else {
            return false;
        };

        match foreground {
            ForegroundTarget::Process(pid) => {
                process.id == *pid
                    || self.foreground_processes.contains(&process.id)
                    || self.process_descended_from(process, *pid)
            }
            ForegroundTarget::Cgroup(cgroup) => process_cgroup_matches(&process.cgroup, cgroup),
        }
    }

    /// Adds a new process to the process map
    pub fn process_map_insert(
        &mut self,
        process: Process<'owner>,
    ) -> Arc<LCell<'owner, Process<'owner>>> {
        self.process_map.insert(&mut self.owner, process)
    }

    /// Refreshes the process map
    pub fn process_map_refresh(&mut self, buffer: &mut Buffer) {
        self.process_map.drain_filter_prepare();

        let mut parents = BTreeMap::new();
        let Ok(procfs) = std::fs::read_dir("/proc/") else {
            tracing::error!("failed to read /proc directory: process monitoring stopped");
            return;
        };

        for proc_entry in procfs.filter_map(Result::ok) {
            let file_name = proc_entry.file_name();

            let mut process = Process::default();

            match atoi::atoi::<u32>(file_name.as_bytes()) {
                Some(pid) => process.id = pid,
                None => continue,
            }

            // Processes without a command line path are kernel threads
            match process::cmdline(buffer, process.id) {
                Some(cmdline) => process.cmdline = cmdline,
                None => continue,
            }

            process.name = process::name(&process.cmdline).to_owned();

            if let Some(cgroup) = process::cgroup(buffer, process.id) {
                process.cgroup = cgroup.to_owned();
            }

            if let Some(ppid) = process::parent_id(buffer, process.id) {
                parents.insert(process.id, ppid);
                process.parent_id = ppid;
            }

            self.process_map.retain_process_tree(&self.owner, &process);
            self.process_map_insert(process);
        }

        for (pid, ppid) in parents {
            if let Some(process) = self.process_map.get_pid(pid) {
                if let Some(parent) = self.process_map.get_pid(ppid) {
                    process.rw(&mut self.owner).parent = Some(Arc::downgrade(parent));
                }
            }
        }

        self.process_map.drain_filter(&self.owner);

        // Refresh priority assignments
        let mut process_map = process::Map::default();
        std::mem::swap(&mut process_map, &mut self.process_map);

        for process in process_map.map.values() {
            self.assign_process_priority(process);
            self.apply_process_priority(buffer, process.ro(&self.owner));
        }

        std::mem::swap(&mut process_map, &mut self.process_map);

        // Reassign foreground processes in case they were overridden.
        self.reapply_foreground(buffer);
        self.reconcile_cgroup_weights(buffer);
    }

    /// Reloads the configuration files.
    pub fn reload_configuration(&mut self, buffer: &mut Buffer) {
        self.config = crate::config::config();
        self.reconcile_cgroup_weights(buffer);
    }

    /// Sets a process as the foreground.
    pub fn set_foreground_process(&mut self, buffer: &mut Buffer, pid: u32) {
        self.assign_children(buffer, pid);

        if self.config.process_scheduler.foreground.is_some() {
            self.foreground = Some(ForegroundTarget::Process(pid));
            self.foreground_processes.clear();
            self.foreground_processes.push(pid);

            for process in self.process_map.map.values() {
                let process = process.ro(&self.owner);

                if let Priority::Assignable = self.process_assignment(process.id) {
                    if process.id == pid || self.process_descended_from(process, pid) {
                        self.foreground_processes.push(process.id);
                    }

                    self.apply_process_priority(buffer, process);
                }
            }
        }

        self.reconcile_cgroup_weights(buffer);
    }

    /// Sets a cgroup subtree as the foreground.
    pub fn set_foreground_cgroup(&mut self, buffer: &mut Buffer, cgroup: &str) {
        let cgroup = normalize_foreground_cgroup(cgroup);

        if cgroup.is_empty() {
            self.clear_foreground(buffer);
            return;
        }

        if self.config.process_scheduler.foreground.is_none() {
            return;
        }

        self.foreground = Some(ForegroundTarget::Cgroup(cgroup));
        self.foreground_processes.clear();
        self.reapply_foreground(buffer);
        self.reconcile_cgroup_weights(buffer);
    }

    /// Clears the active foreground process or cgroup target.
    pub fn clear_foreground(&mut self, buffer: &mut Buffer) {
        if self.foreground.take().is_none() {
            return;
        }

        self.foreground_processes.clear();
        self.reapply_foreground(buffer);
        self.reconcile_cgroup_weights(buffer);
    }

    fn reapply_foreground(&mut self, buffer: &mut Buffer) {
        if self.config.process_scheduler.foreground.is_none() {
            return;
        }

        let foreground = self.foreground.clone();
        self.foreground_processes.clear();

        for process_cell in self.process_map.map.values() {
            let process = process_cell.ro(&self.owner);

            if let Priority::Assignable = self.process_assignment(process.id) {
                if self.process_is_foreground(process) {
                    self.foreground_processes.push(process.id);
                }

                self.apply_process_priority(buffer, process);
            }
        }

        self.foreground = foreground;
    }

    /// Assigns a process to the pipewire profile if it does not already have an assignment.
    pub fn set_pipewire_process(&mut self, buffer: &mut Buffer, kind: ProcessKind, process: u32) {
        self.assign_children(buffer, process);

        let managed = match kind {
            ProcessKind::Capture => &mut self.pipewire_capture_processes,
            ProcessKind::Playback => &mut self.pipewire_playback_processes,
        };

        let mut assignable = true;

        if !managed.contains(&process) {
            if let Some(process) = self.process_map.get_pid(process) {
                let process = process.ro(&self.owner);
                if OwnedPriority::Assignable != process.assigned_priority {
                    assignable = false;
                }
            }

            managed.push(process);
        }

        if !assignable {
            self.reconcile_cgroup_weights(buffer);
            return;
        }

        for current_cell in self.process_map.map.values() {
            let (pid, descended) = {
                let current = current_cell.ro(&self.owner);
                (current.id, self.process_descended_from(current, process))
            };
            let ascended = if kind == ProcessKind::Capture {
                if let Some(root_cell) = self.process_map.get_pid(process) {
                    let root = root_cell.ro(&self.owner);
                    self.process_descended_from(root, pid)
                } else {
                    false
                }
            } else {
                false
            };

            if let Priority::Assignable = self.process_assignment(pid) {
                if pid == process {
                    let current = current_cell.ro(&self.owner);
                    self.apply_process_priority(buffer, current);
                } else if (descended && kind == ProcessKind::Capture) || ascended {
                    current_cell.rw(&mut self.owner).pipewire_ancestor = Some(process);
                    let current = current_cell.ro(&self.owner);
                    self.apply_process_priority(buffer, current);
                }
            }
        }

        self.reconcile_cgroup_weights(buffer);
    }

    /// Removes a process from the pipewire profile.
    ///
    /// Assigns the background or foreground process priority, if that feature is enabled.
    pub fn remove_pipewire_process(
        &mut self,
        buffer: &mut Buffer,
        kind: ProcessKind,
        process_id: u32,
    ) {
        let managed = match kind {
            ProcessKind::Capture => &mut self.pipewire_capture_processes,
            ProcessKind::Playback => &mut self.pipewire_playback_processes,
        };

        let Some(index) = managed.iter().position(|pid| *pid == process_id) else {
            return;
        };

        managed.remove(index);

        for process_cell in self.process_map.map.values() {
            let process = process_cell.rw(&mut self.owner);

            if process.id == process_id
                || (kind == ProcessKind::Capture && process.pipewire_ancestor == Some(process_id))
            {
                process.pipewire_ancestor = None;
                let process = process_cell.ro(&self.owner);

                if let Priority::Assignable = self.process_assignment(process.id) {
                    self.apply_process_priority(buffer, process);
                }
            }
        }

        self.reconcile_cgroup_weights(buffer);
    }

    fn reconcile_cgroup_weights(&mut self, buffer: &mut Buffer) {
        let config = self.config.process_scheduler.cgroup_weights.clone();
        let desired = config
            .as_ref()
            .filter(|config| config.enable)
            .map(|config| self.desired_cgroup_weights(buffer, config))
            .unwrap_or_default();

        self.cgroup_weights.reconcile(config.as_ref(), desired);
    }

    fn desired_cgroup_weights(
        &self,
        buffer: &mut Buffer,
        config: &crate::config::scheduler::CgroupWeights,
    ) -> BTreeMap<String, crate::config::scheduler::CgroupWeight> {
        let mut desired = BTreeMap::new();

        for pid in self.pipewire_playback_processes.clone() {
            if let Some(cgroup) = self.cgroup_for_pid(buffer, pid) {
                desired.insert(app_scope_cgroup(&cgroup), config.pipewire_playback);
            }
        }

        for pid in self.pipewire_capture_processes.clone() {
            if let Some(cgroup) = self.cgroup_for_pid(buffer, pid) {
                desired.insert(app_scope_cgroup(&cgroup), config.pipewire_capture);
            }
        }

        if let Some(cgroup) = self.foreground_cgroup(buffer) {
            desired.insert(app_scope_cgroup(&cgroup), config.foreground);
        }

        desired
    }

    fn foreground_cgroup(&self, buffer: &mut Buffer) -> Option<String> {
        match self.foreground.as_ref()? {
            ForegroundTarget::Cgroup(cgroup) => Some(cgroup.clone()),
            ForegroundTarget::Process(pid) => self.cgroup_for_pid(buffer, *pid),
        }
    }

    fn cgroup_for_pid(&self, buffer: &mut Buffer, pid: u32) -> Option<String> {
        if let Some(process) = self.process_map.get_pid(pid) {
            let process = process.ro(&self.owner);
            if !process.cgroup.is_empty() {
                return Some(process.cgroup.clone());
            }
        }

        process::cgroup(buffer, pid).map(ToOwned::to_owned)
    }
}

fn normalize_foreground_cgroup(cgroup: &str) -> String {
    let cgroup = cgroup.trim();

    if cgroup == "/" {
        return String::from("/");
    }

    cgroup.trim_end_matches('/').to_owned()
}

fn process_cgroup_matches(process: &str, foreground: &str) -> bool {
    if process.is_empty() || foreground.is_empty() {
        return false;
    }

    if foreground == "/" {
        return process.starts_with('/');
    }

    process == foreground
        || process
            .strip_prefix(foreground)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn app_scope_cgroup(cgroup: &str) -> String {
    let Some((prefix, rest)) = cgroup.split_once("/app.slice/") else {
        return cgroup.to_owned();
    };

    let Some(app_scope) = rest.split('/').next().filter(|scope| !scope.is_empty()) else {
        return cgroup.to_owned();
    };

    format!("{prefix}/app.slice/{app_scope}")
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Priority<'a> {
    Assignable,
    Config(&'a Profile),
    Exception,
    NotAssignable,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum OwnedPriority {
    Assignable,
    Config(Profile),
    Exception,
    #[default]
    NotAssignable,
}

impl OwnedPriority {
    fn as_ref(&self) -> Priority {
        match self {
            Self::Assignable => Priority::Assignable,
            Self::Config(profile) => Priority::Config(profile),
            Self::Exception => Priority::Exception,
            Self::NotAssignable => Priority::NotAssignable,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{app_scope_cgroup, normalize_foreground_cgroup, process_cgroup_matches};

    #[test]
    fn foreground_cgroup_matches_exact_scope() {
        assert!(process_cgroup_matches(
            "/user.slice/user-1000.slice/app.slice/app-org.test.scope",
            "/user.slice/user-1000.slice/app.slice/app-org.test.scope"
        ));
    }

    #[test]
    fn foreground_cgroup_matches_child_scope() {
        assert!(process_cgroup_matches(
            "/user.slice/user-1000.slice/app.slice/app-org.test.scope/session",
            "/user.slice/user-1000.slice/app.slice/app-org.test.scope"
        ));
    }

    #[test]
    fn foreground_cgroup_does_not_match_prefix_sibling() {
        assert!(!process_cgroup_matches(
            "/user.slice/user-1000.slice/app.slice/app-org.test.scope-extra",
            "/user.slice/user-1000.slice/app.slice/app-org.test.scope"
        ));
    }

    #[test]
    fn foreground_cgroup_normalization_trims_trailing_slashes() {
        assert_eq!(
            normalize_foreground_cgroup(" /user.slice/app.scope/// "),
            "/user.slice/app.scope"
        );
        assert_eq!(normalize_foreground_cgroup("/"), "/");
    }

    #[test]
    fn cgroup_weights_target_app_scope() {
        assert_eq!(
            app_scope_cgroup(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.test.scope/main.scope"
            ),
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.test.scope"
        );
        assert_eq!(
            app_scope_cgroup(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox@abc.service"
            ),
            "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox@abc.service"
        );
        assert_eq!(
            app_scope_cgroup("/system.slice/dbus-broker.service"),
            "/system.slice/dbus-broker.service"
        );
    }
}
