use crate::{eevdf::Config, kdl::NodeExt};
use kdl::KdlNode;

impl Config {
    /// Parses the EEVDF document node.
    pub fn read(&mut self, node: &KdlNode) {
        self.enable = node.enabled().unwrap_or(true);

        if !self.enable {
            return;
        }

        let Some(profiles) = node.children() else {
            return;
        };

        for (name, profile) in crate::eevdf::parse(profiles.nodes()) {
            self.profiles.insert(name.into(), profile);
        }
    }
}
