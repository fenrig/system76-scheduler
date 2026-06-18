// Copyright 2023 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

use compact_str::CompactString;
use kdl::KdlNode;
use std::collections::BTreeMap;

/// EEVDF scheduler configurations.
pub struct Config {
    /// Enables EEVDF scheduler configuration.
    pub enable: bool,

    /// EEVDF profiles.
    pub profiles: BTreeMap<CompactString, Profile>,
}

impl Default for Config {
    fn default() -> Self {
        let mut config = Self {
            enable: false,
            profiles: BTreeMap::new(),
        };

        config
            .profiles
            .insert("default".into(), crate::eevdf::PROFILE_DEFAULT);
        config
            .profiles
            .insert("responsive".into(), crate::eevdf::PROFILE_RESPONSIVE);
        config
    }
}

/// Default EEVDF profile.
pub const PROFILE_DEFAULT: Profile = Profile {
    base_slice_ns: 3_000_000,
    preempt: "voluntary",
};

/// Responsive EEVDF profile.
pub const PROFILE_RESPONSIVE: Profile = Profile {
    base_slice_ns: 700_000,
    preempt: "full",
};

/// EEVDF profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Profile {
    /// Central EEVDF scheduling slice tunable in nanoseconds.
    pub base_slice_ns: u64,
    /// The kernel preemption mode to use, when supported by the kernel.
    pub preempt: &'static str,
}

/// Parses EEVDF profiles from a KDL node.
pub fn parse(nodes: &[KdlNode]) -> impl Iterator<Item = (&str, Profile)> {
    nodes.iter().map(|node| {
        let mut config = PROFILE_DEFAULT;

        for (name, entry) in crate::kdl::iter_properties(node) {
            match name {
                "base-slice-ns" => {
                    if let Some(value) = entry.value().as_i64() {
                        if let Ok(value) = u64::try_from(value) {
                            config.base_slice_ns = value;
                        } else {
                            tracing::warn!("base-slice-ns expected unsigned integer");
                        }
                    }
                }

                "preempt" => {
                    if let Some(value) = entry.value().as_string() {
                        match value {
                            "voluntary" => config.preempt = "voluntary",
                            "full" => config.preempt = "full",
                            _ => tracing::warn!("preempt expected one of: voluntary full"),
                        }
                    }
                }

                _ => (),
            }
        }

        (node.name().value(), config)
    })
}

#[cfg(test)]
mod tests {
    use super::{parse, PROFILE_DEFAULT};
    use kdl::KdlDocument;

    #[test]
    fn parses_eevdf_profiles() {
        let document = "default base-slice-ns=3000000 preempt=\"voluntary\"\nresponsive base-slice-ns=700000 preempt=\"full\""
            .parse::<KdlDocument>()
            .unwrap();

        let profiles = parse(document.nodes()).collect::<Vec<_>>();

        assert_eq!(profiles[0].0, "default");
        assert_eq!(profiles[0].1.base_slice_ns, 3_000_000);
        assert_eq!(profiles[0].1.preempt, "voluntary");
        assert_eq!(profiles[1].0, "responsive");
        assert_eq!(profiles[1].1.base_slice_ns, 700_000);
        assert_eq!(profiles[1].1.preempt, "full");
    }

    #[test]
    fn rejects_negative_base_slice() {
        let document = "default base-slice-ns=-1 preempt=\"full\""
            .parse::<KdlDocument>()
            .unwrap();

        let profile = parse(document.nodes()).next().unwrap().1;

        assert_eq!(profile.base_slice_ns, PROFILE_DEFAULT.base_slice_ns);
        assert_eq!(profile.preempt, "full");
    }

    #[test]
    fn ignores_removed_profile_fields() {
        let document = "default latency=4 nr-latency=10 wakeup-granularity=0.5 bandwidth-size=3"
            .parse::<KdlDocument>()
            .unwrap();

        let profile = parse(document.nodes()).next().unwrap().1;

        assert_eq!(profile, PROFILE_DEFAULT);
    }

    #[test]
    fn rejects_unknown_preempt_mode() {
        let document = "default base-slice-ns=700000 preempt=\"none\""
            .parse::<KdlDocument>()
            .unwrap();

        let profile = parse(document.nodes()).next().unwrap().1;

        assert_eq!(profile.base_slice_ns, 700_000);
        assert_eq!(profile.preempt, PROFILE_DEFAULT.preempt);
    }
}
