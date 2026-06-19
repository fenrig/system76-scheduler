// Copyright 2023 System76 <info@system76.com>
// SPDX-License-Identifier: MPL-2.0

#![deny(missing_docs)]

//! Pipewire integration for the System76 Scheduler

use bstr::BStr;
use pipewire as pw;
use pw::{
    node::{Node, NodeInfo},
    proxy::ProxyT,
    spa::ReadableDict,
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, HashMap},
    io,
    os::unix::prelude::{AsRawFd, OwnedFd},
    rc::Rc,
    time::Duration,
};

/// Node event
#[derive(Debug)]
pub enum NodeEvent<'a> {
    /// Node info
    Info(u32, &'a NodeInfo),
    /// Node removal
    Remove(u32),
}

/// Process event
#[derive(Debug)]
pub enum ProcessEvent {
    /// Process add
    Add(ProcessKind, u32),
    /// Process remove
    Remove(ProcessKind, u32),
}

/// PipeWire process kind
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ProcessKind {
    /// Audio, MIDI, or video capture.
    Capture,
    /// Audio or video playback.
    Playback,
}

impl ProcessKind {
    fn from_media_class(media_class: &str) -> Option<Self> {
        if should_boost_capture_media_class(media_class) {
            return Some(Self::Capture);
        }

        if should_boost_playback_media_class(media_class) {
            return Some(Self::Playback);
        }

        None
    }

    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::Capture => b"cap",
            Self::Playback => b"play",
        }
    }

    fn from_bytes(bytes: &[u8]) -> Option<Self> {
        match bytes {
            b"cap" => Some(Self::Capture),
            b"play" => Some(Self::Playback),
            _ => None,
        }
    }
}

impl ProcessEvent {
    /// Parse a process event from bytes
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut fields = BStr::new(bytes).split(|b| *b == b' ');

        let method = fields.next()?;
        let kind = ProcessKind::from_bytes(fields.next()?)?;
        let pid = atoi::atoi::<u32>(fields.next()?)?;

        match method {
            b"add" => Some(ProcessEvent::Add(kind, pid)),
            b"rem" => Some(ProcessEvent::Remove(kind, pid)),
            _ => None,
        }
    }

    /// # Errors
    ///
    /// - Failure to write bytes to writer
    pub fn to_bytes<W: std::io::Write>(&self, writer: &mut W) -> io::Result<()> {
        let (method, kind, pid) = match self {
            ProcessEvent::Add(kind, pid) => (b"add", *kind, *pid),
            ProcessEvent::Remove(kind, pid) => (b"rem", *kind, *pid),
        };

        writer.write_all(method)?;
        writer.write_all(b" ")?;
        writer.write_all(kind.as_bytes())?;
        writer.write_all(b" ")?;
        writer.write_all(itoa::Buffer::new().format(pid).as_bytes())
    }
}

/// Process information
#[must_use]
#[derive(Copy, Clone, Debug)]
pub struct Process {
    /// Process ID
    pub id: u32,
}

impl Process {
    /// Attains process info from a pipewire info node.
    #[must_use]
    pub fn from_node(info: &NodeInfo) -> Option<(ProcessKind, Self)> {
        let props = info.props()?;
        let media_class = props.get("media.class")?;
        let kind = ProcessKind::from_media_class(media_class)?;
        props.get("application.process.binary")?;

        Some((
            kind,
            Process {
                id: props.get("application.process.id")?.parse::<u32>().ok()?,
            },
        ))
    }
}

/// Returns true when a PipeWire node should receive the capture profile.
///
/// We only boost nodes that are doing capture or MIDI work. Output-only clients
/// such as browsers and games are left alone.
#[must_use]
pub fn should_boost_capture_media_class(media_class: &str) -> bool {
    matches!(
        media_class,
        "Audio/Source"
            | "Audio/Source/Virtual"
            | "Midi/Source"
            | "Midi/Source/Virtual"
            | "Video/Source"
            | "Video/Source/Virtual"
    ) || media_class.starts_with("Stream/Input/Audio")
        || media_class.starts_with("Stream/Input/Midi")
        || media_class.starts_with("Stream/Input/Video")
}

/// Returns true when a PipeWire node should receive the playback profile.
#[must_use]
pub fn should_boost_playback_media_class(media_class: &str) -> bool {
    matches!(
        media_class,
        "Audio/Sink" | "Audio/Sink/Virtual" | "Video/Sink" | "Video/Sink/Virtual"
    ) || media_class.starts_with("Stream/Output/Audio")
        || media_class.starts_with("Stream/Output/Video")
}

/// Monitors the processes from a given ``PipeWire`` socket.
///
/// ``PipeWire`` sockets are found in `/run/user/{{UID}}/pipewire-0`.
pub fn processes_from_socket(socket: &OwnedFd, mut func: impl FnMut(ProcessEvent) + 'static) {
    let mut managed = BTreeMap::new();

    let _res = nodes_from_socket(socket, move |event| match event {
        NodeEvent::Info(pw_id, info) => {
            if let Some((kind, process)) = Process::from_node(info) {
                if managed.insert(pw_id, (kind, process)).is_none() {
                    func(ProcessEvent::Add(kind, process.id));
                }
            }
        }

        NodeEvent::Remove(pw_id) => {
            if let Some((kind, process)) = managed.remove(&pw_id) {
                func(ProcessEvent::Remove(kind, process.id));
            }
        }
    });
}

/// Listens to information about nodes, passing that info into a callback.
///
/// # Errors
///
/// Errors if the pipewire connection fails
pub fn nodes_from_socket(
    socket: &OwnedFd,
    func: impl FnMut(NodeEvent) + 'static,
) -> Result<(), Box<dyn std::error::Error>> {
    let main_loop = pw::MainLoop::new()?;
    let context = pw::Context::new(&main_loop)?;
    let core = context.connect_fd(socket.as_raw_fd(), None)?;

    let registry = Rc::new(core.get_registry()?);
    let registry_weak = Rc::downgrade(&registry);

    let nodes = Rc::new(RefCell::new(HashMap::new()));
    let func = Rc::new(RefCell::new(func));

    let remove_ids = Rc::new(RefCell::new(Vec::new()));

    let garbage_collector = main_loop.add_timer({
        let nodes = Rc::downgrade(&nodes);
        let remove_ids = Rc::downgrade(&remove_ids);
        move |_| {
            if let Some(nodes) = nodes.upgrade() {
                if let Some(remove_ids) = remove_ids.upgrade() {
                    for id in remove_ids.borrow_mut().drain(..) {
                        nodes.borrow_mut().remove(&id);
                    }
                }
            }
        }
    });

    let _res = garbage_collector
        .update_timer(Some(Duration::from_secs(60)), Some(Duration::from_secs(60)))
        .into_result();

    let _registry_listener = registry
        .add_listener_local()
        .global(move |obj| {
            let Some(registry) = registry_weak.upgrade() else {
                return;
            };

            if pw::types::ObjectType::Node == obj.type_ {
                let Ok(node): Result<Node, _> = registry.bind(obj) else {
                    return;
                };

                let proxy = node.upcast_ref();
                let id = proxy.id();

                let func_weak = Rc::downgrade(&func);

                let info_listener = node
                    .add_listener_local()
                    .info(move |info| {
                        if let Some(func) = func_weak.upgrade() {
                            func.borrow_mut()(NodeEvent::Info(id, info));
                        }
                    })
                    .register();

                let func = Rc::downgrade(&func);
                let remove_ids = Rc::downgrade(&remove_ids);

                let remove_listener = proxy
                    .add_listener_local()
                    .removed(move || {
                        if let Some(remove_ids) = remove_ids.upgrade() {
                            remove_ids.borrow_mut().push(id);
                        }

                        if let Some(func) = func.upgrade() {
                            func.borrow_mut()(NodeEvent::Remove(id));
                        }
                    })
                    .register();

                nodes
                    .borrow_mut()
                    .insert(id, (node, info_listener, remove_listener));
            }
        })
        .register();

    main_loop.run();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        should_boost_capture_media_class, should_boost_playback_media_class, ProcessEvent,
    };

    #[test]
    fn parses_process_event_bytes() {
        assert!(matches!(
            ProcessEvent::from_bytes(b"add cap 123"),
            Some(ProcessEvent::Add(_, 123))
        ));
        assert!(matches!(
            ProcessEvent::from_bytes(b"rem play 456"),
            Some(ProcessEvent::Remove(_, 456))
        ));
    }

    #[test]
    fn boosts_capture_audio_midi_and_playback_separately() {
        assert!(should_boost_capture_media_class("Audio/Source"));
        assert!(should_boost_capture_media_class("Audio/Source/Virtual"));
        assert!(should_boost_capture_media_class("Stream/Input/Audio"));
        assert!(should_boost_capture_media_class("Stream/Input/Audio/Monitor"));
        assert!(should_boost_capture_media_class("Midi/Source"));
        assert!(should_boost_capture_media_class("Stream/Input/Midi"));
        assert!(should_boost_capture_media_class("Video/Source"));
        assert!(should_boost_capture_media_class("Stream/Input/Video"));

        assert!(should_boost_playback_media_class("Audio/Sink"));
        assert!(should_boost_playback_media_class("Audio/Sink/Virtual"));
        assert!(should_boost_playback_media_class("Stream/Output/Audio"));
        assert!(should_boost_playback_media_class("Video/Sink"));
        assert!(should_boost_playback_media_class("Stream/Output/Video"));

        assert!(!should_boost_capture_media_class("Audio/Sink"));
        assert!(!should_boost_capture_media_class("Stream/Output/Audio"));
        assert!(!should_boost_playback_media_class("Audio/Source"));
        assert!(!should_boost_playback_media_class("Stream/Input/Audio"));
        assert!(!should_boost_capture_media_class("Music"));
        assert!(!should_boost_playback_media_class("Music"));
    }
}
