//! The rule model.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    str::FromStr,
};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ModelError {
    #[error("prefix length {len} is too long for {addr}")]
    PrefixLength { addr: IpAddr, len: u8 },
    #[error("`{0}` is not an address or prefix")]
    PrefixSyntax(String),
    #[error("port range {lo}-{hi} is reversed")]
    PortRange { lo: u16, hi: u16 },
    #[error("`{0}` is not a port or port range")]
    PortSyntax(String),
    #[error("`{0}` is not a host name or `*.` pattern")]
    Name(String),
    #[error("unknown protocol `{0}`")]
    Protocol(String),
}

/// Which way a flow goes, seen from the box.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// The box opens the flow. A rule's target is the destination.
    Egress,
    /// A flow arrives at a box socket. The target is the source, the port
    /// is the local one.
    Ingress,
    /// The box binds a socket. The target is the local address.
    Bind,
}

impl Direction {
    pub const ALL: [Self; 3] = [Self::Egress, Self::Ingress, Self::Bind];

    /// The value the kernel programs use for this direction.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Egress => 0,
            Self::Ingress => 1,
            Self::Bind => 2,
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Egress => "egress",
            Self::Ingress => "ingress",
            Self::Bind => "bind",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Family {
    V4,
    V6,
}

impl Family {
    #[must_use]
    pub const fn of(addr: &IpAddr) -> Self {
        match addr {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }

    /// 4 or 6, as the kernel programs and events carry it.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::V4 => 4,
            Self::V6 => 6,
        }
    }
}

/// `Icmp` means ICMP in an IPv4 rule and ICMPv6 in an IPv6 rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
}

impl Protocol {
    pub const ALL: [Self; 3] = [Self::Tcp, Self::Udp, Self::Icmp];

    const fn bit(self) -> u8 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
            Self::Icmp => 4,
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
            Self::Icmp => "icmp",
        }
    }
}

impl FromStr for Protocol {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|p| p.name().eq_ignore_ascii_case(s))
            .ok_or_else(|| ModelError::Protocol(s.to_owned()))
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A set of protocols. The bits are the ones the kernel programs use.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "Vec<Protocol>", into = "Vec<Protocol>")]
pub struct Protocols(u8);

impl Protocols {
    pub const NONE: Self = Self(0);
    pub const TCP: Self = Self(Protocol::Tcp.bit());
    pub const UDP: Self = Self(Protocol::Udp.bit());
    pub const ICMP: Self = Self(Protocol::Icmp.bit());
    pub const TCP_UDP: Self = Self(Protocol::Tcp.bit() | Protocol::Udp.bit());
    pub const ALL: Self = Self(Protocol::Tcp.bit() | Protocol::Udp.bit() | Protocol::Icmp.bit());

    #[must_use]
    pub const fn bits(self) -> u8 {
        self.0
    }

    #[must_use]
    pub const fn from_bits(bits: u8) -> Self {
        Self(bits & Self::ALL.0)
    }

    #[must_use]
    pub const fn contains(self, p: Protocol) -> bool {
        self.0 & p.bit() != 0
    }

    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Every protocol not in the set.
    #[must_use]
    pub const fn complement(self) -> Self {
        Self(!self.0 & Self::ALL.0)
    }

    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    #[must_use]
    pub const fn is_superset(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn iter(self) -> impl Iterator<Item = Protocol> {
        Protocol::ALL.into_iter().filter(move |p| self.contains(*p))
    }
}

impl From<Protocol> for Protocols {
    fn from(p: Protocol) -> Self {
        Self(p.bit())
    }
}

impl From<Vec<Protocol>> for Protocols {
    fn from(v: Vec<Protocol>) -> Self {
        v.into_iter().collect()
    }
}

impl From<Protocols> for Vec<Protocol> {
    fn from(p: Protocols) -> Self {
        p.iter().collect()
    }
}

impl FromIterator<Protocol> for Protocols {
    fn from_iter<I: IntoIterator<Item = Protocol>>(iter: I) -> Self {
        Self(iter.into_iter().fold(0, |bits, p| bits | p.bit()))
    }
}

impl fmt::Display for Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::ALL {
            return f.write_str("any");
        }
        let mut first = true;
        for p in self.iter() {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            write!(f, "{p}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Protocols {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Protocols({self})")
    }
}

/// An inclusive range of ports. For ICMP it is a range of message types.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PortRange {
    lo: u16,
    hi: u16,
}

impl PortRange {
    pub const ALL: Self = Self {
        lo: 0,
        hi: u16::MAX,
    };

    pub const fn new(lo: u16, hi: u16) -> Result<Self, ModelError> {
        if lo > hi {
            return Err(ModelError::PortRange { lo, hi });
        }
        Ok(Self { lo, hi })
    }

    #[must_use]
    pub const fn one(port: u16) -> Self {
        Self { lo: port, hi: port }
    }

    #[must_use]
    pub const fn lo(self) -> u16 {
        self.lo
    }

    #[must_use]
    pub const fn hi(self) -> u16 {
        self.hi
    }

    #[must_use]
    pub const fn contains(self, port: u16) -> bool {
        self.lo <= port && port <= self.hi
    }

    #[must_use]
    pub const fn covers(self, other: Self) -> bool {
        self.lo <= other.lo && other.hi <= self.hi
    }
}

impl FromStr for PortRange {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ModelError::PortSyntax(s.to_owned());
        let num = |t: &str| t.trim().parse::<u16>().map_err(|_e| bad());
        match s.split_once('-') {
            Some((lo, hi)) => Self::new(num(lo)?, num(hi)?),
            None => num(s).map(Self::one),
        }
    }
}

impl TryFrom<String> for PortRange {
    type Error = ModelError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<PortRange> for String {
    fn from(r: PortRange) -> Self {
        r.to_string()
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if *self == Self::ALL {
            f.write_str("any")
        } else if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

impl fmt::Debug for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PortRange({self})")
    }
}

/// An address prefix of either family. Host bits are always zero.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Prefix {
    addr: IpAddr,
    len: u8,
}

const fn mask4(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - len as u32)
    }
}

const fn mask6(len: u8) -> u128 {
    if len == 0 {
        0
    } else {
        u128::MAX << (128 - len as u32)
    }
}

impl Prefix {
    pub const V4_ALL: Self = Self {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        len: 0,
    };
    pub const V6_ALL: Self = Self {
        addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        len: 0,
    };

    /// Host bits of `addr` beyond `len` are cleared.
    pub fn new(addr: IpAddr, len: u8) -> Result<Self, ModelError> {
        let addr = match addr {
            IpAddr::V4(a) if len <= 32 => IpAddr::V4(Ipv4Addr::from(u32::from(a) & mask4(len))),
            IpAddr::V6(a) if len <= 128 => IpAddr::V6(Ipv6Addr::from(u128::from(a) & mask6(len))),
            _ => return Err(ModelError::PrefixLength { addr, len }),
        };
        Ok(Self { addr, len })
    }

    /// The prefix that holds exactly one address.
    #[must_use]
    pub const fn host(addr: IpAddr) -> Self {
        let len = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        Self { addr, len }
    }

    /// The first `len` bits of the prefix. Only shortens: a `len` beyond
    /// the current one leaves it as it is.
    #[must_use]
    pub const fn truncated(self, len: u8) -> Self {
        if len >= self.len {
            return self;
        }
        let addr = match self.addr {
            IpAddr::V4(a) => IpAddr::V4(Ipv4Addr::from_bits(a.to_bits() & mask4(len))),
            IpAddr::V6(a) => IpAddr::V6(Ipv6Addr::from_bits(a.to_bits() & mask6(len))),
        };
        Self { addr, len }
    }

    #[must_use]
    pub const fn all(family: Family) -> Self {
        match family {
            Family::V4 => Self::V4_ALL,
            Family::V6 => Self::V6_ALL,
        }
    }

    #[must_use]
    pub const fn addr(&self) -> IpAddr {
        self.addr
    }

    #[must_use]
    pub const fn len(&self) -> u8 {
        self.len
    }

    #[must_use]
    pub const fn is_empty(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn family(&self) -> Family {
        Family::of(&self.addr)
    }

    #[must_use]
    pub fn contains(&self, addr: IpAddr) -> bool {
        match (self.addr, addr) {
            (IpAddr::V4(net), IpAddr::V4(a)) => u32::from(a) & mask4(self.len) == u32::from(net),
            (IpAddr::V6(net), IpAddr::V6(a)) => u128::from(a) & mask6(self.len) == u128::from(net),
            _ => false,
        }
    }

    /// True when every address of `other` is in `self`.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        self.len <= other.len && self.contains(other.addr)
    }

    /// The prefix as flows are judged: a prefix of v4-mapped IPv6 addresses
    /// (`::ffff:a.b.c.d/96+n`) is the IPv4 prefix `a.b.c.d/n`, because a
    /// flow to a v4-mapped address is an IPv4 flow.
    #[must_use]
    pub fn canonical(&self) -> Self {
        let IpAddr::V6(a) = self.addr else {
            return *self;
        };
        match (a.segments(), self.len) {
            ([0, 0, 0, 0, 0, 0xffff, hi, lo], 96..=128) => Self {
                addr: IpAddr::V4(Ipv4Addr::from_bits((u32::from(hi) << 16) | u32::from(lo))),
                len: self.len - 96,
            },
            _ => *self,
        }
    }
}

impl FromStr for Prefix {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bad = || ModelError::PrefixSyntax(s.to_owned());
        match s.split_once('/') {
            Some((addr, len)) => {
                let addr: IpAddr = addr.trim().parse().map_err(|_e| bad())?;
                let len: u8 = len.trim().parse().map_err(|_e| bad())?;
                Self::new(addr, len)
            }
            None => s.trim().parse().map(Self::host).map_err(|_e| bad()),
        }
    }
}

impl TryFrom<String> for Prefix {
    type Error = ModelError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<Prefix> for String {
    fn from(p: Prefix) -> Self {
        p.to_string()
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.len)
    }
}

impl fmt::Debug for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Prefix({self})")
    }
}

/// A host name, or `*.domain` for every name below `domain`.
///
/// `*.example.com` matches `a.example.com` and `a.b.example.com`, not
/// `example.com` itself. Stored lower-case without a trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct NamePattern {
    wildcard: bool,
    domain: String,
}

fn valid_domain(d: &str) -> bool {
    !d.is_empty()
        && d.len() <= 253
        && d.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

fn normalize(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

impl NamePattern {
    #[must_use]
    pub const fn is_wildcard(&self) -> bool {
        self.wildcard
    }

    /// The name, or for a wildcard the domain below which it matches.
    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    #[must_use]
    pub fn matches(&self, name: &str) -> bool {
        let name = normalize(name);
        if self.wildcard {
            is_below(&name, &self.domain)
        } else {
            name == self.domain
        }
    }

    /// True when every name `other` matches is matched by `self` too.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        match (self.wildcard, other.wildcard) {
            (false, false) => self.domain == other.domain,
            (false, true) => false,
            (true, false) => is_below(&other.domain, &self.domain),
            (true, true) => other.domain == self.domain || is_below(&other.domain, &self.domain),
        }
    }

    /// Orders patterns that match the same name: an exact name first, then
    /// the wildcard with the longest domain.
    #[must_use]
    pub fn specificity(&self) -> (bool, usize) {
        (!self.wildcard, self.domain.len())
    }

    /// The id of the pattern's name set: a hash of the pattern, so the
    /// same pattern has the same id in every policy that names it. A pin
    /// made under one policy of a box still means the same pattern under
    /// the next.
    #[must_use]
    pub fn set_id(&self) -> SetId {
        // FNV-1a, 64 bits.
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        let prefix: &[u8] = if self.wildcard { b"*." } else { b"" };
        for byte in prefix.iter().chain(self.domain.as_bytes()) {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        SetId(hash)
    }
}

fn is_below(name: &str, domain: &str) -> bool {
    name.strip_suffix(domain)
        .is_some_and(|head| head.ends_with('.') && head.len() > 1)
}

impl FromStr for NamePattern {
    type Err = ModelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n = normalize(s);
        let (wildcard, domain) = match n.strip_prefix("*.") {
            Some(rest) => (true, rest),
            None => (false, n.as_str()),
        };
        if !valid_domain(domain) {
            return Err(ModelError::Name(s.to_owned()));
        }
        Ok(Self {
            wildcard,
            domain: domain.to_owned(),
        })
    }
}

impl TryFrom<String> for NamePattern {
    type Error = ModelError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
    }
}

impl From<NamePattern> for String {
    fn from(p: NamePattern) -> Self {
        p.to_string()
    }
}

impl fmt::Display for NamePattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.wildcard {
            f.write_str("*.")?;
        }
        f.write_str(&self.domain)
    }
}

/// What a rule applies to: the remote address of a flow, or for a bind the
/// local one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// Every address of both families.
    Any,
    /// The addresses of one prefix. The family is the prefix's.
    Net(Prefix),
    /// The addresses the resolver has pinned for names the pattern matches.
    Names(NamePattern),
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Any => f.write_str("any"),
            Self::Net(p) => write!(f, "{p}"),
            Self::Names(n) => write!(f, "{n}"),
        }
    }
}

/// Index of a service endpoint of the box. See [`crate::base`] for the ones
/// the base policy defines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EndpointIndex(pub u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
    /// Rewrite the destination to the endpoint. Egress only.
    Redirect(EndpointIndex),
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Allow => f.write_str("allow"),
            Self::Deny => f.write_str("deny"),
            Self::Redirect(EndpointIndex(i)) => write!(f, "redirect@{i}"),
        }
    }
}

/// Where a rule comes from. Shown with the rule, and lets an event's rule
/// number be explained to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Origin {
    /// The box may use its own service endpoints.
    OwnEndpoints,
    /// No box may use the service endpoints of another.
    OtherEndpoints,
    /// DNS goes to the box's resolver endpoint.
    Resolver,
    /// Steered names go to the box's credential proxy endpoint.
    Steering,
    /// The node's hostname proxy is reached through the box's endpoint.
    HostnameProxy,
    /// A box with its own network namespace may talk to itself.
    OwnAddresses,
    /// The kernel's IPv6 neighbour discovery for a box with its own netns.
    NeighbourDiscovery,
    /// The transport carries no IPv6.
    NoIpv6Transport,
    /// Ports of the host exposed on the host alias.
    HostExposure,
    /// Gateway and host alias of the virtual network.
    Infrastructure,
    /// A protected range: closed unless the box allows a prefix inside
    /// it or lists a name that resolves into it.
    Protected,
    /// A published port.
    Published,
    /// `rules` of the box, by position.
    BoxRule(u16),
    /// The box's protocol list.
    BoxProtocols,
    /// A denied prefix of the box.
    BoxDeny,
    /// An allowed prefix of the box.
    BoxAllow,
    /// An allowed name of the box.
    BoxName,
}

impl Origin {
    /// True for rules of the base policy.
    #[must_use]
    pub const fn is_base(self) -> bool {
        !matches!(
            self,
            Self::BoxRule(_) | Self::BoxProtocols | Self::BoxDeny | Self::BoxAllow | Self::BoxName
        )
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnEndpoints => f.write_str("own service endpoints"),
            Self::OtherEndpoints => f.write_str("service endpoints of other boxes"),
            Self::Resolver => f.write_str("DNS to the box resolver"),
            Self::Steering => f.write_str("steered names to the credential proxy"),
            Self::HostnameProxy => f.write_str("hostname proxy through the box endpoint"),
            Self::OwnAddresses => f.write_str("the box itself"),
            Self::NeighbourDiscovery => f.write_str("IPv6 neighbour discovery"),
            Self::NoIpv6Transport => f.write_str("transport without IPv6"),
            Self::HostExposure => f.write_str("host exposure"),
            Self::Infrastructure => f.write_str("virtual network infrastructure"),
            Self::Protected => f.write_str("protected range"),
            Self::Published => f.write_str("published port"),
            Self::BoxRule(i) => write!(f, "rules[{i}]"),
            Self::BoxProtocols => f.write_str("allow_protocols"),
            Self::BoxDeny => f.write_str("deny_subnets"),
            Self::BoxAllow => f.write_str("allow_subnets"),
            Self::BoxName => f.write_str("allow_dns_hosts"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Rule {
    pub direction: Direction,
    pub protocols: Protocols,
    /// Ports for TCP and UDP, message types for ICMP.
    pub ports: PortRange,
    pub target: Target,
    pub action: Action,
    pub origin: Origin,
}

impl Rule {
    #[must_use]
    pub const fn new(direction: Direction, target: Target, action: Action, origin: Origin) -> Self {
        Self {
            direction,
            protocols: Protocols::ALL,
            ports: PortRange::ALL,
            target,
            action,
            origin,
        }
    }

    #[must_use]
    pub const fn protocols(mut self, protocols: Protocols) -> Self {
        self.protocols = protocols;
        self
    }

    #[must_use]
    pub const fn ports(mut self, ports: PortRange) -> Self {
        self.ports = ports;
        self
    }

    /// True when the rule's protocols and ports match.
    #[must_use]
    pub const fn matches_l4(&self, protocol: Protocol, port: u16) -> bool {
        self.protocols.contains(protocol) && self.ports.contains(port)
    }

    /// Whether the rule applies to addresses of a protected range.
    ///
    /// A wide allow does not open a protected range: `0.0.0.0/0` is not a
    /// decision to reach the other boxes of a virtual network. So an allow
    /// the box wrote for a prefix applies there only when the prefix lies
    /// inside the range. Denies, rules by name and the base policy's own
    /// rules apply everywhere.
    #[must_use]
    pub fn reaches_into(&self, range: &Prefix) -> bool {
        if self.origin.is_base() || self.action == Action::Deny {
            return true;
        }
        match &self.target {
            Target::Names(_) => true,
            Target::Any => false,
            Target::Net(prefix) => range.covers(prefix),
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:<7} {:<10} {:<12} {:<11} {}",
            self.direction, self.action, self.protocols, self.ports, self.target
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Deny,
}

impl fmt::Display for Verdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

/// What happens to a flow no rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Defaults {
    pub egress: Verdict,
    pub ingress: Verdict,
    pub bind: Verdict,
}

impl Defaults {
    #[must_use]
    pub const fn of(&self, direction: Direction) -> Verdict {
        match direction {
            Direction::Egress => self.egress,
            Direction::Ingress => self.ingress,
            Direction::Bind => self.bind,
        }
    }
}

/// A socket of the daemon that serves one box. A redirect needs the address
/// of the flow's family: the kernel cannot move a flow to the other family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Endpoint {
    pub v4: Option<SocketAddrV4>,
    pub v6: Option<SocketAddrV6>,
}

impl Endpoint {
    #[must_use]
    pub const fn has(&self, family: Family) -> bool {
        match family {
            Family::V4 => self.v4.is_some(),
            Family::V6 => self.v6.is_some(),
        }
    }
}

/// Identifies the rules of one name pattern in a compiled policy. See
/// [`NamePattern::set_id`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SetId(pub u64);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_clears_host_bits_and_contains() {
        let p: Prefix = "10.1.2.3/16".parse().unwrap();
        assert_eq!(p.to_string(), "10.1.0.0/16");
        assert!(p.contains("10.1.255.9".parse().unwrap()));
        assert!(!p.contains("10.2.0.0".parse().unwrap()));
        assert!(!p.contains("::1".parse().unwrap()));
        let p6: Prefix = "fd00:1:2::9/48".parse().unwrap();
        assert_eq!(p6.to_string(), "fd00:1:2::/48");
        assert!("fd00:1::/32".parse::<Prefix>().unwrap().covers(&p6));
        assert!(!p6.covers(&"fd00:1::/32".parse().unwrap()));
        assert!(Prefix::V4_ALL.covers(&p));
        assert!(!Prefix::V6_ALL.covers(&p));
        assert_eq!("192.0.2.7".parse::<Prefix>().unwrap().len(), 32);
        "10.0.0.0/33".parse::<Prefix>().unwrap_err();
        "nope/8".parse::<Prefix>().unwrap_err();
        // A v4-mapped prefix is the IPv4 prefix it carries.
        let mapped: Prefix = "::ffff:10.1.0.0/112".parse().unwrap();
        assert_eq!(mapped.canonical(), p);
        assert_eq!(
            "::ffff:0:0/96".parse::<Prefix>().unwrap().canonical(),
            Prefix::V4_ALL
        );
        assert_eq!(p6.canonical(), p6);
        let short: Prefix = "::/64".parse().unwrap();
        assert_eq!(short.canonical(), short);
    }

    #[test]
    fn name_patterns() {
        let exact: NamePattern = "API.Example.com.".parse().unwrap();
        let wild: NamePattern = "*.example.com".parse().unwrap();
        let narrow: NamePattern = "*.pkg.example.com".parse().unwrap();
        assert!(exact.matches("api.example.com"));
        assert!(!exact.matches("x.api.example.com"));
        assert!(wild.matches("a.b.Example.com."));
        assert!(!wild.matches("example.com"));
        assert!(!wild.matches("badexample.com"));
        assert!(wild.covers(&exact) && wild.covers(&narrow) && wild.covers(&wild));
        assert!(!narrow.covers(&wild) && !exact.covers(&wild));
        assert!(exact.specificity() > narrow.specificity());
        assert!(narrow.specificity() > wild.specificity());
        for bad in ["", "*", "*.", "a..b", "a.*.b", "sp ace.com"] {
            assert!(bad.parse::<NamePattern>().is_err(), "{bad}");
        }
        // A set id belongs to the pattern, however it was written.
        assert_eq!(
            exact.set_id(),
            "api.example.com".parse::<NamePattern>().unwrap().set_id()
        );
        assert_ne!(exact.set_id(), wild.set_id());
        assert_ne!(
            wild.set_id(),
            "example.com".parse::<NamePattern>().unwrap().set_id()
        );
    }

    #[test]
    fn ports_and_protocols() {
        assert_eq!("443".parse::<PortRange>().unwrap(), PortRange::one(443));
        let r: PortRange = "8000-8100".parse().unwrap();
        assert!(r.contains(8000) && r.contains(8100) && !r.contains(8101));
        assert!(PortRange::ALL.covers(r) && !r.covers(PortRange::ALL));
        "9-1".parse::<PortRange>().unwrap_err();
        assert_eq!(
            Protocols::TCP.complement(),
            Protocols::UDP.union(Protocols::ICMP)
        );
        assert_eq!(Protocols::ALL.to_string(), "any");
        assert_eq!(Protocols::TCP_UDP.to_string(), "tcp,udp");
        let json = serde_json::to_string(&Protocols::TCP_UDP).unwrap();
        assert_eq!(json, r#"["tcp","udp"]"#);
        assert_eq!(
            serde_json::from_str::<Protocols>(&json).unwrap(),
            Protocols::TCP_UDP
        );
    }
}
