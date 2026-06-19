mod eevdf;
mod scheduler;

use std::path::Path;

use crate::kdl::NodeExt;
use crate::scheduler::ForegroundAssignments;
use crate::{configuration_files, Config, DISTRIBUTION_PATH, SYSTEM_CONF_PATH};
use ::kdl::KdlDocument;
use const_format::concatcp;

pub fn read_config() -> Config {
    let buffer = &mut String::with_capacity(4096);

    let mut config = read_assignments(read_main(buffer), buffer);

    let background = config
        .process_scheduler
        .assignments
        .profiles
        .remove("background");

    let foreground = config
        .process_scheduler
        .assignments
        .profiles
        .remove("foreground");

    if let (Some(background), Some(foreground)) = (background, foreground) {
        config.process_scheduler.foreground = Some(ForegroundAssignments {
            background,
            foreground,
        });
    }

    config.process_scheduler.pipewire = config
        .process_scheduler
        .assignments
        .profiles
        .remove("pipewire");

    config.process_scheduler.pipewire_playback = config
        .process_scheduler
        .assignments
        .profiles
        .remove("pipewire-playback");

    config
}

fn read_main(buffer: &mut String) -> Config {
    const DIST_CONF: &str = concatcp!(DISTRIBUTION_PATH, "config.kdl");
    const SYSTEM_CONF: &str = concatcp!(SYSTEM_CONF_PATH, "config.kdl");

    let mut config = Config::default();

    let path = if Path::new(SYSTEM_CONF).exists() {
        SYSTEM_CONF
    } else if Path::new(DIST_CONF).exists() {
        DIST_CONF
    } else {
        return config;
    };

    let span = tracing::warn_span!("parser::read_main", path);
    let _entered = span.enter();

    let Ok(buffer) = crate::read_into_string(buffer, path) else {
        tracing::error!("failed to read file");
        return config;
    };

    let document = match buffer.parse::<KdlDocument>() {
        Ok(document) => document,
        Err(why) => {
            let offset = why.span.offset();

            let mut line_number = 1;

            let mut buffer = &buffer.as_bytes()[..offset];

            while let Some(pos) = memchr::memchr(b'\n', buffer) {
                line_number += 1;
                buffer = &buffer[pos + 1..];
            }

            tracing::error!("parsing error on line {}: {}", line_number, why);
            return config;
        }
    };

    for node in document.nodes() {
        match node.name().value() {
            "autogroup-enabled" => {
                config.autogroup_enabled = node.get_bool(0).unwrap_or(false);
            }
            "eevdf-profiles" => config.eevdf_profiles.read(node),
            "process-scheduler" => config.process_scheduler.read(node),
            "version" => (),
            other => {
                tracing::warn!("unknown element: {}", other);
            }
        }
    }

    config
}

fn read_assignments(mut config: Config, buffer: &mut String) -> Config {
    const PATHS: [&str; 2] = [
        concatcp!(DISTRIBUTION_PATH, "process-scheduler/"),
        concatcp!(SYSTEM_CONF_PATH, "process-scheduler/"),
    ];

    for path in configuration_files(&PATHS, ".kdl") {
        if !Path::new(&path).exists() {
            continue;
        }
        let span = tracing::warn_span!("parser::read_assignments", path);
        let _entered = span.enter();

        let Ok(buffer) = crate::read_into_string(buffer, &path) else {
            continue;
        };

        let document = match buffer.parse::<KdlDocument>() {
            Ok(document) => document,
            Err(why) => {
                tracing::error!("parsing error: {}", why);
                continue;
            }
        };

        for node in document.nodes() {
            match node.name().value() {
                "assignments" => {
                    config.process_scheduler.assignments.parse(node);
                }

                "exceptions" => {
                    config.process_scheduler.assignments.parse_exceptions(node);
                }

                other => {
                    tracing::warn!("unknown field: {}", other);
                }
            }
        }
    }

    config
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler::SchedPolicy;

    fn read_document_into_config(config: &mut Config, source: &str) {
        let document = source.parse::<KdlDocument>().unwrap();

        for node in document.nodes() {
            match node.name().value() {
                "autogroup-enabled" => {
                    config.autogroup_enabled = node.get_bool(0).unwrap_or(false);
                }
                "eevdf-profiles" => config.eevdf_profiles.read(node),
                "process-scheduler" => config.process_scheduler.read(node),
                "version" => (),
                _ => (),
            }
        }
    }

    fn read_assignments_into_config(config: &mut Config, source: &str) {
        let document = source.parse::<KdlDocument>().unwrap();

        for node in document.nodes() {
            match node.name().value() {
                "assignments" => {
                    config.process_scheduler.assignments.parse(node);
                }
                "exceptions" => {
                    config.process_scheduler.assignments.parse_exceptions(node);
                }
                _ => (),
            }
        }
    }

    #[test]
    fn shipped_profile_fragments_parse() {
        let mut config = Config::default();

        read_document_into_config(&mut config, include_str!("../../../data/config.kdl"));
        read_assignments_into_config(&mut config, include_str!("../../../data/arch_linux.kdl"));
        read_assignments_into_config(&mut config, include_str!("../../../data/core-services.kdl"));
        read_assignments_into_config(&mut config, include_str!("../../../data/default-apps.kdl"));
        read_assignments_into_config(&mut config, include_str!("../../../data/pop_os.kdl"));
        read_assignments_into_config(&mut config, include_str!("../../../data/kde_plasma.kdl"));
        read_assignments_into_config(
            &mut config,
            include_str!("../../../data/user-overrides.kdl"),
        );

        let games = config
            .process_scheduler
            .assignments
            .profile("games")
            .unwrap();

        assert_eq!(games.nice.unwrap().get(), 2);

        let recording = config
            .process_scheduler
            .assignments
            .profile("recording")
            .unwrap();

        assert_eq!(recording.nice.unwrap().get(), -9);
        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("mumble")
            .is_some());

        let pipewire = config
            .process_scheduler
            .assignments
            .profile("pipewire")
            .unwrap();
        assert_eq!(pipewire.nice.unwrap().get(), -6);

        let pipewire_playback = config
            .process_scheduler
            .assignments
            .profile("pipewire-playback")
            .unwrap();
        assert_eq!(pipewire_playback.nice.unwrap().get(), 3);

        let cgroup_weights = config.process_scheduler.cgroup_weights.as_ref().unwrap();
        assert!(cgroup_weights.enable);
        assert_eq!(cgroup_weights.default.cpu, 100);
        assert_eq!(cgroup_weights.default.io, 100);
        assert_eq!(cgroup_weights.pipewire_capture.cpu, 800);
        assert_eq!(cgroup_weights.pipewire_capture.io, 800);
        assert_eq!(cgroup_weights.pipewire_playback.cpu, 400);
        assert_eq!(cgroup_weights.pipewire_playback.io, 400);
        assert_eq!(cgroup_weights.foreground.cpu, 800);
        assert_eq!(cgroup_weights.foreground.io, 800);

        let game_services = config
            .process_scheduler
            .assignments
            .profile("game-services")
            .unwrap();

        assert_eq!(game_services.nice.unwrap().get(), 0);
        let game_services_rules = config
            .process_scheduler
            .assignments
            .conditions
            .get("game-services")
            .unwrap();
        assert!(game_services_rules
            .1
            .iter()
            .any(|(condition, include)| *include
                && condition
                    .name
                    .as_ref()
                    .is_some_and(|name| name.matches("wineserver"))));
        assert!(!game_services_rules
            .1
            .iter()
            .any(|(condition, include)| *include
                && condition
                    .name
                    .as_ref()
                    .is_some_and(|name| name.matches("wine64-preloader"))));
        assert!(!game_services_rules
            .1
            .iter()
            .any(|(condition, include)| *include
                && condition
                    .name
                    .as_ref()
                    .is_some_and(|name| name.matches("proton-cachyos-slr"))));
        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("mixxx")
            .is_some());
        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("teams")
            .is_none());
        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("jitsi")
            .is_none());
        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("zoom")
            .is_none());
        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("mumble")
            .is_some());
        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("obs")
            .is_none());

        let cosmic = config
            .process_scheduler
            .assignments
            .get_by_name("cosmic-comp")
            .unwrap();

        assert_eq!(cosmic.nice.unwrap().get(), -3);

        let plasma = config
            .process_scheduler
            .assignments
            .get_by_name("plasmashell")
            .unwrap();

        assert_eq!(plasma.nice.unwrap().get(), -4);
        assert_eq!(plasma.sched_policy, SchedPolicy::Other);

        let sddm = config
            .process_scheduler
            .assignments
            .get_by_name("sddm")
            .unwrap();

        assert_eq!(sddm.nice.unwrap().get(), -4);

        let locker = config
            .process_scheduler
            .assignments
            .get_by_name("kscreenlocker")
            .unwrap();

        assert_eq!(locker.nice.unwrap().get(), -4);

        let baloo = config
            .process_scheduler
            .assignments
            .get_by_name("baloo_file")
            .unwrap();

        assert_eq!(baloo.nice.unwrap().get(), 19);
        assert_eq!(baloo.sched_policy, SchedPolicy::Idle);

        let yay = config
            .process_scheduler
            .assignments
            .get_by_name("yay")
            .unwrap();

        assert_eq!(yay.nice.unwrap().get(), 15);
        assert_eq!(yay.sched_policy, SchedPolicy::Batch);

        let git = config
            .process_scheduler
            .assignments
            .get_by_name("git")
            .unwrap();

        assert_eq!(git.nice.unwrap().get(), 19);
        assert_eq!(git.sched_policy, SchedPolicy::Idle);

        let freshclam = config
            .process_scheduler
            .assignments
            .get_by_name("freshclam")
            .unwrap();

        assert_eq!(freshclam.nice.unwrap().get(), 19);
        assert_eq!(freshclam.sched_policy, SchedPolicy::Idle);

        let timeshift = config
            .process_scheduler
            .assignments
            .get_by_name("timeshift")
            .unwrap();

        assert_eq!(timeshift.nice.unwrap().get(), 19);
        assert_eq!(timeshift.sched_policy, SchedPolicy::Idle);

        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("dbus-broker"));
        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("foreground_booster"));
        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("system76-scheduler"));
        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("systemd"));
        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("tuned"));
        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("tuned-ppd"));
        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("uresourced"));
        assert!(config
            .process_scheduler
            .assignments
            .is_exception_by_name("taskset"));
        assert!(!config
            .process_scheduler
            .assignments
            .exceptions_conditions
            .iter()
            .any(|condition| condition
                .descends
                .as_ref()
                .is_some_and(|descends| descends.matches("gamemoderun"))));

        let session_services = config
            .process_scheduler
            .assignments
            .conditions
            .get("session-services")
            .unwrap();

        let firefox_cgroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/app-firefox@dbf4749b12dd490cabc9fceedda97a7a.service";
        let firefox_included = session_services.1.iter().any(|(condition, include)| {
            *include
                && condition
                    .cgroup
                    .as_ref()
                    .is_some_and(|cgroup| cgroup.matches(firefox_cgroup))
        });
        let firefox_excluded = session_services.1.iter().any(|(condition, include)| {
            !*include
                && condition
                    .cgroup
                    .as_ref()
                    .is_some_and(|cgroup| cgroup.matches(firefox_cgroup))
        });

        assert!(firefox_included);
        assert!(firefox_excluded);

        assert!(config
            .process_scheduler
            .assignments
            .get_by_name("steam")
            .is_none());
    }
}
