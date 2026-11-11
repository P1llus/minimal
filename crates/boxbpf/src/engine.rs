//! Loading the programs and attaching them at a `boxes/` cgroup.

use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use aya::{
    Ebpf, EbpfLoader,
    maps::{Map, MapData},
    programs::{CgroupSkb, CgroupSock, CgroupSockAddr, ProgramError},
};

use crate::{Error, Handles, sys};

static OBJECT: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/boxbpf.bpf.o"));

/// Names the programs this build carries: the SHA-256 of the object. A
/// daemon and a loader with the same value load the same programs.
#[must_use]
pub const fn object_id() -> &'static str {
    env!("BOXBPF_OBJECT_ID")
}

#[derive(Clone, Copy)]
enum Kind {
    Sock,
    SockAddr,
    Skb,
}

struct Program {
    name: &'static str,
    kind: Kind,
    /// `enum bpf_attach_type`.
    attach_type: u32,
}

/// Every program of the object. One that is missing, fails the verifier or
/// does not attach fails the whole engine.
const PROGRAMS: [Program; 14] = [
    Program {
        name: "bp_sock_create",
        kind: Kind::Sock,
        attach_type: 2,
    },
    Program {
        name: "bp_sock_release",
        kind: Kind::Sock,
        attach_type: 34,
    },
    Program {
        name: "bp_bind4",
        kind: Kind::SockAddr,
        attach_type: 8,
    },
    Program {
        name: "bp_bind6",
        kind: Kind::SockAddr,
        attach_type: 9,
    },
    Program {
        name: "bp_connect4",
        kind: Kind::SockAddr,
        attach_type: 10,
    },
    Program {
        name: "bp_connect6",
        kind: Kind::SockAddr,
        attach_type: 11,
    },
    Program {
        name: "bp_sendmsg4",
        kind: Kind::SockAddr,
        attach_type: 14,
    },
    Program {
        name: "bp_sendmsg6",
        kind: Kind::SockAddr,
        attach_type: 15,
    },
    Program {
        name: "bp_recvmsg4",
        kind: Kind::SockAddr,
        attach_type: 19,
    },
    Program {
        name: "bp_recvmsg6",
        kind: Kind::SockAddr,
        attach_type: 20,
    },
    Program {
        name: "bp_getpeername4",
        kind: Kind::SockAddr,
        attach_type: 29,
    },
    Program {
        name: "bp_getpeername6",
        kind: Kind::SockAddr,
        attach_type: 30,
    },
    Program {
        name: "bp_ingress",
        kind: Kind::Skb,
        attach_type: 0,
    },
    Program {
        name: "bp_egress",
        kind: Kind::Skb,
        attach_type: 1,
    },
];

/// The maps a daemon gets, in the order they are handed over.
pub(crate) const MAPS: [&str; 9] = [
    "box_cfg",
    "rules4",
    "rules6",
    "pins",
    "set_rules",
    "endpoints",
    "stats",
    "flows",
    "events",
];

/// How many entries each map holds. Most of the hash maps are allocated in
/// full at load, so these bound the engine's memory as well as its
/// capacity. What one box may take of them is in [`crate::Limits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapSizes {
    pub boxes: u32,
    /// Prefix entries per address family, over all boxes.
    pub rule_entries: u32,
    pub pins: u32,
    pub name_sets: u32,
    pub endpoints: u32,
    /// Redirected flows whose original destination is remembered.
    pub flows: u32,
    /// Bytes of the event ring buffer: a power of two, at least a page.
    pub event_bytes: u32,
}

impl Default for MapSizes {
    fn default() -> Self {
        Self {
            boxes: 1024,
            rule_entries: 16384,
            pins: 16384,
            name_sets: 16384,
            endpoints: 4096,
            flows: 65536,
            event_bytes: 1 << 18,
        }
    }
}

/// The loaded programs. Holding it keeps nothing attached: attachments
/// belong to the cgroup and stay until the cgroup is removed.
pub struct Engine {
    ebpf: Ebpf,
}

fn program_error(name: &'static str) -> impl FnOnce(ProgramError) -> Error {
    move |source| Error::Program {
        name,
        source: Box::new(source),
    }
}

fn map_data(map: &Map) -> Option<&MapData> {
    match map {
        Map::HashMap(d)
        | Map::LruHashMap(d)
        | Map::LpmTrie(d)
        | Map::PerCpuHashMap(d)
        | Map::RingBuf(d) => Some(d),
        _ => None,
    }
}

impl Engine {
    /// Loads the programs for the attach point `boxes`. Needs `CAP_BPF` and
    /// `CAP_NET_ADMIN`.
    pub fn load(boxes: BorrowedFd<'_>, sizes: &MapSizes) -> Result<Self, Error> {
        let boxes_id =
            sys::cgroup_id(boxes).map_err(Error::sys("read the id of the boxes cgroup"))?;
        let mut ebpf = EbpfLoader::new()
            .override_global("boxes_id", &boxes_id, true)
            .map_max_entries("box_cfg", sizes.boxes)
            .map_max_entries("stats", sizes.boxes)
            .map_max_entries("rules4", sizes.rule_entries)
            .map_max_entries("rules6", sizes.rule_entries)
            .map_max_entries("pins", sizes.pins)
            .map_max_entries("set_rules", sizes.name_sets)
            .map_max_entries("endpoints", sizes.endpoints)
            .map_max_entries("flows", sizes.flows)
            .map_max_entries("ev_buckets", sizes.boxes)
            .map_max_entries("events", sizes.event_bytes)
            .load(OBJECT)
            .map_err(|e| Error::Load(Box::new(e)))?;
        for p in &PROGRAMS {
            let prog = ebpf.program_mut(p.name).ok_or(Error::Missing {
                kind: "program",
                name: p.name,
            })?;
            match p.kind {
                Kind::Sock => <&mut CgroupSock>::try_from(prog).and_then(CgroupSock::load),
                Kind::SockAddr => {
                    <&mut CgroupSockAddr>::try_from(prog).and_then(CgroupSockAddr::load)
                }
                Kind::Skb => <&mut CgroupSkb>::try_from(prog).and_then(CgroupSkb::load),
            }
            .map_err(program_error(p.name))?;
        }
        Ok(Self { ebpf })
    }

    fn program_fd(&mut self, p: &Program) -> Result<OwnedFd, Error> {
        let prog = self.ebpf.program_mut(p.name).ok_or(Error::Missing {
            kind: "program",
            name: p.name,
        })?;
        let fd = match p.kind {
            Kind::Sock => <&mut CgroupSock>::try_from(prog).and_then(|p| p.fd()),
            Kind::SockAddr => <&mut CgroupSockAddr>::try_from(prog).and_then(|p| p.fd()),
            Kind::Skb => <&mut CgroupSkb>::try_from(prog).and_then(|p| p.fd()),
        }
        .map_err(program_error(p.name))?;
        fd.as_fd()
            .try_clone_to_owned()
            .map_err(Error::sys("duplicate a program descriptor"))
    }

    /// Attaches every program at `boxes`, or none: when one does not
    /// attach, those before it are detached again. A cgroup with some of
    /// the hooks guarded and no way to tell would be worse than none.
    pub fn attach(&mut self, boxes: BorrowedFd<'_>) -> Result<(), Error> {
        for (done, p) in PROGRAMS.iter().enumerate() {
            let attached = self.program_fd(p).and_then(|fd| {
                sys::prog_attach(fd.as_fd(), boxes, p.attach_type)
                    .map_err(|e| program_error(p.name)(ProgramError::IOError(e)))
            });
            if let Err(error) = attached {
                self.detach_some(boxes, done);
                return Err(error);
            }
        }
        Ok(())
    }

    /// Detaches the first `count` programs. A program that is not attached
    /// is skipped, and so is one that does not detach: there is nothing
    /// more to do about it here, and the caller already has an error.
    fn detach_some(&mut self, boxes: BorrowedFd<'_>, count: usize) {
        for p in PROGRAMS.iter().take(count) {
            if let Ok(fd) = self.program_fd(p) {
                let _gone = sys::prog_detach(fd.as_fd(), boxes, p.attach_type);
            }
        }
    }

    /// Takes every program off `boxes` again: for an engine that was
    /// attached and then could not be handed to its daemon.
    pub fn detach(&mut self, boxes: BorrowedFd<'_>) {
        self.detach_some(boxes, PROGRAMS.len());
    }

    /// A descriptor of each map a daemon needs, in hand-over order.
    pub(crate) fn map_fds(&self) -> Result<Vec<OwnedFd>, Error> {
        MAPS.iter()
            .map(|name| {
                let data = self
                    .ebpf
                    .map(name)
                    .and_then(map_data)
                    .ok_or(Error::Missing { kind: "map", name })?;
                data.fd()
                    .as_fd()
                    .try_clone_to_owned()
                    .map_err(Error::sys("duplicate a map descriptor"))
            })
            .collect()
    }

    /// The typed maps of this engine.
    pub fn handles(&self) -> Result<Handles, Error> {
        Handles::from_fds(self.map_fds()?)
    }

    /// Loads and attaches in one step and returns the handles: what a
    /// daemon with root does for itself, as in the VM guest.
    ///
    /// The cgroup must carry no program of these kinds. An engine left
    /// from an earlier daemon would judge every flow as well, from maps
    /// nobody writes, and refuse it. A daemon makes its `boxes` cgroup
    /// anew at start, so it never meets one.
    ///
    /// On any error nothing stays attached.
    pub fn start(boxes: BorrowedFd<'_>, sizes: &MapSizes) -> Result<Handles, Error> {
        if has_programs(boxes)? {
            return Err(Error::InUse);
        }
        let mut engine = Self::load(boxes, sizes)?;
        engine.attach(boxes)?;
        engine.handles().inspect_err(|_| engine.detach(boxes))
    }
}

/// Whether any program of the kinds the engine attaches is attached at
/// `cgroup` itself. Programs on the cgroups above do not count: systemd
/// puts its own there.
pub(crate) fn has_programs(cgroup: BorrowedFd<'_>) -> Result<bool, Error> {
    for p in &PROGRAMS {
        let attached = sys::prog_query(cgroup, p.attach_type)
            .map_err(Error::sys("query attached programs"))?;
        if !attached.is_empty() {
            return Ok(true);
        }
    }
    Ok(false)
}
