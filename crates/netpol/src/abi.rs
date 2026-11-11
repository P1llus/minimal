//! Layouts and constants shared with the kernel programs.
//!
//! `bpf/abi.h` in the `boxbpf` crate declares the same structs in C. Its
//! build compiles the assertions [`c_static_asserts`] generates, so a
//! mismatch between the two sides fails the build. Change [`VERSION`] with
//! any layout or meaning change: loader and daemon compare it.
//!
//! Byte order: addresses are stored as they sit in a packet. An IPv4
//! address in a 16-byte field takes the first four bytes, the rest is zero.
//! Ports are host order. Box ids in LPM keys are native-endian bytes.

use std::{
    mem::{offset_of, size_of},
    net::IpAddr,
};

use serde::{Deserialize, Serialize};

use crate::{
    compile::{Compiled, Slot},
    model::{Action, Direction, Protocols, SetId, Verdict},
};

pub const VERSION: u32 = 3;

/// Endpoint indexes of a box are below this.
pub const ENDPOINTS_MAX: u8 = 4;

/// Rules per prefix or name set after covering rules are copied in.
pub const RULES_MAX: usize = 32;
/// `prio` of "no rule": what an event carries when a default decided.
pub const NO_RULE: u16 = 0xffff;
/// Bits of an LPM key before the address: box id, generation, direction.
pub const RULE_KEY_BASE: u32 = 128;

pub const FLAG_CHECK_SRC: u32 = 1 << 0;
pub const FLAG_LOG_FLOWS: u32 = 1 << 1;
pub const FLAG_HAS_SETS: u32 = 1 << 2;

pub const ACTION_DENY: u8 = 0;
pub const ACTION_ALLOW: u8 = 1;
pub const ACTION_REDIRECT: u8 = 2;

pub const EVENT_NET: u16 = 1;

/// A struct that is plain bytes: `repr(C)`, no padding, every bit pattern
/// valid.
///
/// # Safety
///
/// The implementor guarantees the above. Map access reads and writes these
/// as raw memory.
pub unsafe trait Plain: Copy + 'static {}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct BoxCfg {
    pub flags: u32,
    /// Part of the key of every rule, set and endpoint entry of the box:
    /// writing a config with another generation switches the whole policy
    /// at once. It also ends the verdicts sockets have cached.
    pub generation: u32,
    /// Indexed by [`Direction::code`].
    pub default_action: [u8; 3],
    pub _pad: u8,
    pub refuse_errno: u16,
    pub _pad2: u16,
    pub addr4: [u8; 4],
    pub addr6: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Rule {
    pub prio: u16,
    pub proto_mask: u8,
    pub action: u8,
    pub port_lo: u16,
    pub port_hi: u16,
    pub endpoint: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Rules {
    /// Rules in use, from the front of `r`.
    pub count: u16,
    pub _pad: u16,
    pub r: [Rule; RULES_MAX],
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            count: 0,
            _pad: 0,
            r: [Rule::default(); RULES_MAX],
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Rule4Key {
    pub prefixlen: u32,
    pub box_id: [u8; 8],
    pub generation: [u8; 4],
    pub dir: u8,
    pub _zero: [u8; 3],
    pub addr: [u8; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Rule6Key {
    pub prefixlen: u32,
    pub box_id: [u8; 8],
    pub generation: [u8; 4],
    pub dir: u8,
    pub _zero: [u8; 3],
    pub addr: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PinKey {
    pub box_id: u64,
    pub addr: [u8; 16],
    pub family: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct PinVal {
    /// Boot-time clock. The programs ignore the entry once this has passed.
    pub expiry_ns: u64,
    pub set_id: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct SetKey {
    pub box_id: u64,
    pub set_id: u64,
    pub generation: u32,
    pub dir: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EndpointKey {
    pub box_id: u64,
    pub generation: u32,
    pub idx: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub addr6: [u8; 16],
    pub addr4: [u8; 4],
    /// 0: no IPv4 address.
    pub port4: u16,
    /// 0: no IPv6 address.
    pub port6: u16,
}

/// Per-CPU counters of a box.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Stats {
    pub tx_pkts: u64,
    pub tx_bytes: u64,
    pub rx_pkts: u64,
    pub rx_bytes: u64,
    pub tx_drop: u64,
    pub rx_drop: u64,
    /// Refusals at a system call.
    pub refused: u64,
    /// Events lost because the ring buffer was full.
    pub ev_lost: u64,
}

impl Stats {
    /// Adds the counters of another CPU.
    pub const fn add(&mut self, other: &Self) {
        self.tx_pkts = self.tx_pkts.wrapping_add(other.tx_pkts);
        self.tx_bytes = self.tx_bytes.wrapping_add(other.tx_bytes);
        self.rx_pkts = self.rx_pkts.wrapping_add(other.rx_pkts);
        self.rx_bytes = self.rx_bytes.wrapping_add(other.rx_bytes);
        self.tx_drop = self.tx_drop.wrapping_add(other.tx_drop);
        self.rx_drop = self.rx_drop.wrapping_add(other.rx_drop);
        self.refused = self.refused.wrapping_add(other.refused);
        self.ev_lost = self.ev_lost.wrapping_add(other.ev_lost);
    }
}

/// The box's end of a redirected flow, as the endpoint sees its peer.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub saddr: [u8; 16],
    pub sport: u16,
    /// One protocol bit.
    pub proto: u8,
    pub family: u8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FlowVal {
    pub box_id: u64,
    pub orig_addr: [u8; 16],
    pub orig_port: u16,
    pub orig_family: u8,
    pub endpoint: u8,
    pub _pad: u32,
}

/// Starts every record of the event ring buffer. A reader skips a kind it
/// does not know by `size`, and reads at most what it knows of a kind that
/// has grown: fields are only appended.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EvHdr {
    pub kind: u16,
    /// Whole record, this header included.
    pub size: u16,
    pub cpu: u32,
    /// Boot-time clock.
    pub ts_ns: u64,
    pub box_id: u64,
}

/// The network record, [`EVENT_NET`].
#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct EvNet {
    pub hdr: EvHdr,
    pub hook: u8,
    pub verdict: u8,
    pub reason: u8,
    pub family: u8,
    /// IP protocol number. For `sock_create`, the protocol asked for.
    pub l4proto: u16,
    pub sock_type: u16,
    pub sport: u16,
    /// For ICMP the message type.
    pub dport: u16,
    /// 0 in the packet hooks.
    pub pid: u32,
    /// `prio` of the deciding rule, [`NO_RULE`] if none.
    pub rule: u32,
    pub saddr: [u8; 16],
    pub daddr: [u8; 16],
    pub _pad: u32,
    pub cookie: u64,
}

/// Which program reported an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Hook {
    SockCreate,
    Connect4,
    Connect6,
    Sendmsg4,
    Sendmsg6,
    Bind4,
    Bind6,
    Egress,
    Ingress,
}

impl Hook {
    pub const ALL: [Self; 9] = [
        Self::SockCreate,
        Self::Connect4,
        Self::Connect6,
        Self::Sendmsg4,
        Self::Sendmsg6,
        Self::Bind4,
        Self::Bind6,
        Self::Egress,
        Self::Ingress,
    ];

    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::SockCreate => 1,
            Self::Connect4 => 2,
            Self::Connect6 => 3,
            Self::Sendmsg4 => 4,
            Self::Sendmsg6 => 5,
            Self::Bind4 => 6,
            Self::Bind6 => 7,
            Self::Egress => 8,
            Self::Ingress => 9,
        }
    }

    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|h| h.code() == code)
    }

    const fn c_name(self) -> &'static str {
        match self {
            Self::SockCreate => "BP_H_SOCK_CREATE",
            Self::Connect4 => "BP_H_CONNECT4",
            Self::Connect6 => "BP_H_CONNECT6",
            Self::Sendmsg4 => "BP_H_SENDMSG4",
            Self::Sendmsg6 => "BP_H_SENDMSG6",
            Self::Bind4 => "BP_H_BIND4",
            Self::Bind6 => "BP_H_BIND6",
            Self::Egress => "BP_H_EGRESS",
            Self::Ingress => "BP_H_INGRESS",
        }
    }
}

/// Why a flow got its verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The cgroup has no box entry: nothing is allowed.
    NoConfig,
    /// A rule of a prefix decided.
    Rule,
    /// A rule of a name set decided.
    SetRule,
    /// No rule matched.
    Default,
    /// The packet did not come from the box's own address.
    SourceAddress,
    /// A socket kind the engine does not let boxes create.
    SocketType,
    /// A packet the programs could not parse.
    Malformed,
    /// A packet to a destination that should have been redirected at the
    /// system call and was not.
    NotSteered,
    /// A redirect to an endpoint without an address of the flow's family.
    NoEndpoint,
    /// The kernel had no memory to remember which box a new socket
    /// belongs to.
    NoMemory,
}

impl Reason {
    pub const ALL: [Self; 10] = [
        Self::NoConfig,
        Self::Rule,
        Self::SetRule,
        Self::Default,
        Self::SourceAddress,
        Self::SocketType,
        Self::Malformed,
        Self::NotSteered,
        Self::NoEndpoint,
        Self::NoMemory,
    ];

    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::NoConfig => 1,
            Self::Rule => 2,
            Self::SetRule => 3,
            Self::Default => 4,
            Self::SourceAddress => 5,
            Self::SocketType => 6,
            Self::Malformed => 7,
            Self::NotSteered => 8,
            Self::NoEndpoint => 9,
            Self::NoMemory => 10,
        }
    }

    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }

    const fn c_name(self) -> &'static str {
        match self {
            Self::NoConfig => "BP_R_NO_CFG",
            Self::Rule => "BP_R_RULE",
            Self::SetRule => "BP_R_SET_RULE",
            Self::Default => "BP_R_DEFAULT",
            Self::SourceAddress => "BP_R_SRC_ADDR",
            Self::SocketType => "BP_R_SOCK_TYPE",
            Self::Malformed => "BP_R_MALFORMED",
            Self::NotSteered => "BP_R_NOT_STEERED",
            Self::NoEndpoint => "BP_R_NO_ENDPOINT",
            Self::NoMemory => "BP_R_NO_MEMORY",
        }
    }
}

/// Declares the C name of each struct and lists its fields once, for the
/// `Plain` impls, the Rust size checks and the generated C assertions.
macro_rules! layouts {
    ($($ty:ident = $c:literal, $size:literal { $($field:ident),* $(,)? })*) => {
        $(
            // SAFETY: repr(C), and the size check below fails if the fields
            // do not add up to the size, which rules out padding.
            unsafe impl Plain for $ty {}
            const _: () = assert!(size_of::<$ty>() == $size);
        )*

        /// C `_Static_assert`s that pin `bpf/abi.h` to the layouts and
        /// constants of this module.
        #[must_use]
        pub fn c_static_asserts() -> String {
            let mut out = String::from("/* Generated from netpol::abi. Do not edit. */\n");
            $(
                line(&mut out, &format!("sizeof(struct {}) == {}", $c, size_of::<$ty>()));
                $(
                    line(&mut out, &format!(
                        "__builtin_offsetof(struct {}, {}) == {}",
                        $c, stringify!($field), offset_of!($ty, $field)
                    ));
                )*
            )*
            constants(&mut out);
            out
        }
    };
}

fn line(out: &mut String, condition: &str) {
    out.push_str(&format!(
        "_Static_assert({condition}, \"netpol::abi: {condition}\");\n"
    ));
}

fn constants(out: &mut String) {
    let pairs: [(&str, u64); 15] = [
        ("BP_ABI_VERSION", u64::from(VERSION)),
        ("BP_ENDPOINTS_MAX", u64::from(ENDPOINTS_MAX)),
        ("BP_RULES_MAX", RULES_MAX as u64),
        ("BP_NO_RULE", u64::from(NO_RULE)),
        ("BP_RULE_KEY_BASE", u64::from(RULE_KEY_BASE)),
        ("BP_F_CHECK_SRC", u64::from(FLAG_CHECK_SRC)),
        ("BP_F_LOG_FLOWS", u64::from(FLAG_LOG_FLOWS)),
        ("BP_F_HAS_SETS", u64::from(FLAG_HAS_SETS)),
        ("BP_DENY", u64::from(ACTION_DENY)),
        ("BP_ALLOW", u64::from(ACTION_ALLOW)),
        ("BP_REDIRECT", u64::from(ACTION_REDIRECT)),
        ("BP_EV_NET", u64::from(EVENT_NET)),
        ("BP_P_TCP", u64::from(Protocols::TCP.bits())),
        ("BP_P_UDP", u64::from(Protocols::UDP.bits())),
        ("BP_P_ICMP", u64::from(Protocols::ICMP.bits())),
    ];
    for (name, value) in pairs {
        line(out, &format!("{name} == {value}"));
    }
    for (name, direction) in [
        ("BP_DIR_EGRESS", Direction::Egress),
        ("BP_DIR_INGRESS", Direction::Ingress),
        ("BP_DIR_BIND", Direction::Bind),
    ] {
        line(out, &format!("{name} == {}", direction.code()));
    }
    for hook in Hook::ALL {
        line(out, &format!("{} == {}", hook.c_name(), hook.code()));
    }
    for reason in Reason::ALL {
        line(out, &format!("{} == {}", reason.c_name(), reason.code()));
    }
}

layouts! {
    BoxCfg = "bp_box_cfg", 36 { flags, generation, default_action, refuse_errno, addr4, addr6 }
    Rule = "bp_rule", 12 { prio, proto_mask, action, port_lo, port_hi, endpoint }
    Rules = "bp_rules", 388 { count, r }
    Rule4Key = "bp_rule4_key", 24 { prefixlen, box_id, generation, dir, addr }
    Rule6Key = "bp_rule6_key", 36 { prefixlen, box_id, generation, dir, addr }
    PinKey = "bp_pin_key", 32 { box_id, addr, family }
    PinVal = "bp_pin_val", 16 { expiry_ns, set_id }
    SetKey = "bp_set_key", 24 { box_id, set_id, generation, dir }
    EndpointKey = "bp_endpoint_key", 16 { box_id, generation, idx }
    Endpoint = "bp_endpoint", 24 { addr6, addr4, port4, port6 }
    Stats = "bp_stats", 64 { tx_pkts, tx_bytes, rx_pkts, rx_bytes, tx_drop, rx_drop, refused, ev_lost }
    FlowKey = "bp_flow_key", 20 { saddr, sport, proto, family }
    FlowVal = "bp_flow_val", 32 { box_id, orig_addr, orig_port, orig_family, endpoint }
    EvHdr = "bp_ev_hdr", 24 { kind, size, cpu, ts_ns, box_id }
    EvNet = "bp_ev_net", 88 {
        hdr, hook, verdict, reason, family, l4proto, sock_type, sport, dport, pid, rule, saddr, daddr, cookie
    }
}

impl Rule4Key {
    /// The key without its prefix length: what the LPM compares.
    #[must_use]
    pub fn data(&self) -> [u8; 20] {
        let mut out = [0u8; 20];
        let bytes = self
            .box_id
            .into_iter()
            .chain(self.generation)
            .chain([self.dir])
            .chain(self._zero)
            .chain(self.addr);
        for (dst, src) in out.iter_mut().zip(bytes) {
            *dst = src;
        }
        out
    }
}

impl Rule6Key {
    /// The key without its prefix length: what the LPM compares.
    #[must_use]
    pub fn data(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        let bytes = self
            .box_id
            .into_iter()
            .chain(self.generation)
            .chain([self.dir])
            .chain(self._zero)
            .chain(self.addr);
        for (dst, src) in out.iter_mut().zip(bytes) {
            *dst = src;
        }
        out
    }
}

/// An address in a 16-byte field and its family code.
#[must_use]
pub fn addr16(addr: IpAddr) -> ([u8; 16], u8) {
    match addr {
        IpAddr::V4(a) => {
            let mut out = [0u8; 16];
            for (dst, src) in out.iter_mut().zip(a.octets()) {
                *dst = src;
            }
            (out, 4)
        }
        IpAddr::V6(a) => (a.octets(), 6),
    }
}

/// The address a 16-byte field and a family code stand for.
#[must_use]
pub fn addr_of(bytes: &[u8; 16], family: u8) -> IpAddr {
    if family == 6 {
        IpAddr::from(*bytes)
    } else {
        let [a, b, c, d, ..] = *bytes;
        IpAddr::from([a, b, c, d])
    }
}

const fn action_code(action: Action) -> (u8, u8) {
    match action {
        Action::Deny => (ACTION_DENY, 0),
        Action::Allow => (ACTION_ALLOW, 0),
        Action::Redirect(index) => (ACTION_REDIRECT, index.0),
    }
}

const fn verdict_code(verdict: Verdict) -> u8 {
    match verdict {
        Verdict::Allow => ACTION_ALLOW,
        Verdict::Deny => ACTION_DENY,
    }
}

/// The compiler never hands over more than [`RULES_MAX`] slots.
fn rules_value(slots: &[Slot]) -> Rules {
    let mut out = Rules::default();
    out.count = u16::try_from(slots.len().min(RULES_MAX)).unwrap_or(0);
    for (dst, slot) in out.r.iter_mut().zip(slots) {
        let (action, endpoint) = action_code(slot.action);
        *dst = Rule {
            prio: slot.prio,
            proto_mask: slot.protocols.bits(),
            action,
            port_lo: slot.ports.lo(),
            port_hi: slot.ports.hi(),
            endpoint,
            _pad: [0; 3],
        };
    }
    out
}

/// Every map entry of one generation of a box's policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoxEntries {
    pub cfg: BoxCfg,
    pub rules4: Vec<(Rule4Key, Rules)>,
    pub rules6: Vec<(Rule6Key, Rules)>,
    pub sets: Vec<(SetKey, Rules)>,
    pub endpoints: Vec<(EndpointKey, Endpoint)>,
}

/// The keys of [`BoxEntries`]: enough to delete a generation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BoxKeys {
    pub rules4: Vec<Rule4Key>,
    pub rules6: Vec<Rule6Key>,
    pub sets: Vec<SetKey>,
    pub endpoints: Vec<EndpointKey>,
}

impl BoxKeys {
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.rules4.is_empty()
            && self.rules6.is_empty()
            && self.sets.is_empty()
            && self.endpoints.is_empty()
    }
}

impl BoxEntries {
    #[must_use]
    pub fn keys(&self) -> BoxKeys {
        BoxKeys {
            rules4: self.rules4.iter().map(|(k, _)| *k).collect(),
            rules6: self.rules6.iter().map(|(k, _)| *k).collect(),
            sets: self.sets.iter().map(|(k, _)| *k).collect(),
            endpoints: self.endpoints.iter().map(|(k, _)| *k).collect(),
        }
    }
}

/// The config entry of a compiled box at a generation.
#[must_use]
pub fn box_cfg(compiled: &Compiled, generation: u32) -> BoxCfg {
    let c = &compiled.config;
    let mut flags = 0;
    if c.source_check {
        flags |= FLAG_CHECK_SRC;
    }
    if c.log_flows {
        flags |= FLAG_LOG_FLOWS;
    }
    if !compiled.sets.is_empty() {
        flags |= FLAG_HAS_SETS;
    }
    BoxCfg {
        flags,
        generation,
        default_action: [
            verdict_code(c.defaults.egress),
            verdict_code(c.defaults.ingress),
            verdict_code(c.defaults.bind),
        ],
        _pad: 0,
        refuse_errno: c.refuse_errno,
        _pad2: 0,
        addr4: c.addrs.v4.map_or([0; 4], |a| a.octets()),
        addr6: c.addrs.v6.map_or([0; 16], |a| a.octets()),
    }
}

/// How many rule entries a compiled policy takes in the maps: one per
/// prefix and one per name set, each per direction it has rules for.
#[must_use]
pub const fn rule_entries(compiled: &Compiled) -> usize {
    compiled.nets.len() + compiled.sets.len()
}

/// Lays a compiled box out as map entries for the box with this cgroup id.
/// Every rule, set and endpoint key carries `generation`, so the entries
/// of two generations of one box lie side by side.
#[must_use]
pub fn entries(compiled: &Compiled, box_id: u64, generation: u32) -> BoxEntries {
    let id = box_id.to_ne_bytes();
    let generation_bytes = generation.to_ne_bytes();
    let mut out = BoxEntries {
        cfg: box_cfg(compiled, generation),
        ..BoxEntries::default()
    };
    for net in &compiled.nets {
        let prefixlen = RULE_KEY_BASE + u32::from(net.prefix.len());
        let dir = net.direction.code();
        let value = rules_value(&net.rules);
        match net.prefix.addr() {
            IpAddr::V4(a) => out.rules4.push((
                Rule4Key {
                    prefixlen,
                    box_id: id,
                    generation: generation_bytes,
                    dir,
                    _zero: [0; 3],
                    addr: a.octets(),
                },
                value,
            )),
            IpAddr::V6(a) => out.rules6.push((
                Rule6Key {
                    prefixlen,
                    box_id: id,
                    generation: generation_bytes,
                    dir,
                    _zero: [0; 3],
                    addr: a.octets(),
                },
                value,
            )),
        }
    }
    for set in &compiled.sets {
        let key = SetKey {
            box_id,
            set_id: set.id.0,
            generation,
            dir: set.direction.code(),
            _pad: [0; 3],
        };
        out.sets.push((key, rules_value(&set.rules)));
    }
    for (index, e) in &compiled.endpoints {
        let value = Endpoint {
            addr6: e.v6.map_or([0; 16], |a| a.ip().octets()),
            addr4: e.v4.map_or([0; 4], |a| a.ip().octets()),
            port4: e.v4.map_or(0, |a| a.port()),
            port6: e.v6.map_or(0, |a| a.port()),
        };
        out.endpoints.push((
            EndpointKey {
                box_id,
                generation,
                idx: index.0,
                _pad: [0; 3],
            },
            value,
        ));
    }
    out
}

/// The key of a pin.
#[must_use]
pub fn pin_key(box_id: u64, addr: IpAddr) -> PinKey {
    let (addr, family) = addr16(crate::eval::canonical(addr));
    PinKey {
        box_id,
        addr,
        family,
        _pad: [0; 7],
    }
}

#[must_use]
pub const fn pin_val(set: SetId, expiry_ns: u64) -> PinVal {
    PinVal {
        expiry_ns,
        set_id: set.0,
    }
}

/// The key under which the egress hook recorded a redirected flow, from
/// the peer address the endpoint's socket reports.
#[must_use]
pub fn flow_key(peer: std::net::SocketAddr, protocol: crate::model::Protocol) -> FlowKey {
    let (saddr, family) = addr16(crate::eval::canonical(peer.ip()));
    FlowKey {
        saddr,
        sport: peer.port(),
        proto: Protocols::from(protocol).bits(),
        family,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        base::{Deployment, Mode, NodeKind},
        compile::{Options, Spec},
        policy::BoxPolicy,
    };

    #[test]
    fn asserts_cover_every_struct_and_constant() {
        let c = c_static_asserts();
        assert!(c.contains("_Static_assert(sizeof(struct bp_box_cfg) == 36,"));
        assert!(c.contains("__builtin_offsetof(struct bp_ev_net, cookie) == 80"));
        assert!(c.contains("__builtin_offsetof(struct bp_rule6_key, addr) == 20"));
        assert!(c.contains("BP_ABI_VERSION == 3"));
        assert!(c.contains("BP_H_INGRESS == 9"));
        assert!(c.contains("BP_R_NO_ENDPOINT == 9"));
        assert_eq!(c.matches("_Static_assert(sizeof(struct").count(), 15);
    }

    #[test]
    fn codes_round_trip() {
        for h in Hook::ALL {
            assert_eq!(Hook::from_code(h.code()), Some(h));
        }
        for r in Reason::ALL {
            assert_eq!(Reason::from_code(r.code()), Some(r));
        }
        assert_eq!(Hook::from_code(0), None);
        assert_eq!(Reason::from_code(200), None);
    }

    #[test]
    fn addresses_round_trip() {
        for a in ["192.0.2.7", "2001:db8::7"] {
            let ip: IpAddr = a.parse().unwrap();
            let (bytes, family) = addr16(ip);
            assert_eq!(addr_of(&bytes, family), ip);
        }
        // A v4-mapped pin is stored as IPv4, as the programs look it up.
        let k = pin_key(1, "::ffff:192.0.2.7".parse().unwrap());
        assert_eq!((k.family, &k.addr[..4]), (4, &[192, 0, 2, 7][..]));
    }

    #[test]
    fn entries_follow_the_compiled_form() {
        let mut deployment = Deployment::new(NodeKind::Native, Mode::HostIp);
        deployment.transport_ipv6 = true;
        let policy = BoxPolicy {
            allow: vec!["10.0.0.0/8".parse().unwrap(), "fd00::/8".parse().unwrap()],
            names: vec!["example.com".parse().unwrap()],
            ..BoxPolicy::default()
        };
        let compiled = Spec {
            deployment,
            policy,
            options: Options::default(),
        }
        .compile()
        .unwrap();
        let e = entries(&compiled, 0x0102_0304_0506_0708, 3);
        assert_eq!(e.cfg.generation, 3);
        assert_eq!(e.cfg.flags, FLAG_HAS_SETS);
        assert_eq!(
            e.cfg.default_action,
            [ACTION_DENY, ACTION_ALLOW, ACTION_ALLOW]
        );
        let (k4, v4) = e.rules4.first().unwrap();
        assert_eq!(k4.prefixlen, RULE_KEY_BASE + 8);
        assert_eq!(k4.box_id, 0x0102_0304_0506_0708u64.to_ne_bytes());
        assert_eq!((k4.dir, k4.addr), (0, [10, 0, 0, 0]));
        assert_eq!(&k4.data()[8..12], &3u32.to_ne_bytes());
        assert_eq!(&k4.data()[12..], &[0, 0, 0, 0, 10, 0, 0, 0]);
        assert_eq!(e.rules6.first().unwrap().0.data()[16], 0xfd);
        assert_eq!(
            (v4.r[0].proto_mask, v4.r[0].action, v4.r[0].port_hi),
            (7, ACTION_ALLOW, u16::MAX)
        );
        assert_eq!((v4.count, v4.r[1].proto_mask), (1, 0));
        assert_eq!(e.rules6.len(), 1);
        assert_eq!(e.sets.len(), 1);
        let set = e.sets.first().unwrap().0;
        assert_eq!(
            (set.set_id, set.generation),
            (compiled.set_for_name("example.com").unwrap().0, 3)
        );
        assert_eq!(rule_entries(&compiled), 3);
        // Another generation of the same policy shares no rule key with it.
        let next = entries(&compiled, 0x0102_0304_0506_0708, 4);
        assert!(
            next.keys()
                .rules4
                .iter()
                .all(|k| !e.keys().rules4.contains(k))
        );
        assert!(next.keys().sets.iter().all(|k| !e.keys().sets.contains(k)));
    }
}
