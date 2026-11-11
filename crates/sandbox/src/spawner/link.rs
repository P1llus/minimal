//! The link job: gives a container's network namespace its interface.
//!
//! A child of the calling process joins the container's user and network
//! namespaces, where it may configure the network, and sets the interface
//! up with ioctls. The caller prepares every argument before it creates the
//! child, so the child makes direct syscalls only.

use std::io;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd as _, BorrowedFd, OwnedFd};

use super::core::{self, Namespaces};
use super::wire::{LinkKind, LinkSpec};

/// The name of the interface a container's processes see.
pub const INTERFACE: &str = "eth0";

/// What the child was doing when a call failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
enum Step {
    Join = 1,
    Device,
    Control,
    Mac,
    Mtu,
    Address,
    Netmask,
    Loopback,
    Up,
    Route,
}

impl Step {
    const ALL: [Self; 10] = [
        Self::Join,
        Self::Device,
        Self::Control,
        Self::Mac,
        Self::Mtu,
        Self::Address,
        Self::Netmask,
        Self::Loopback,
        Self::Up,
        Self::Route,
    ];

    fn of(byte: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|step| *step as u8 == byte)
    }

    fn doing(self, name: &str) -> String {
        match self {
            Self::Join => "joining the box's network namespace".into(),
            Self::Device => format!("creating the TAP device {name}"),
            Self::Control => "opening a socket to configure the box's network".into(),
            Self::Mac => format!("setting the hardware address of {name}"),
            Self::Mtu => format!("setting the MTU of {name}"),
            Self::Address => format!("setting the address of {name}"),
            Self::Netmask => format!("setting the netmask of {name}"),
            Self::Loopback => "bringing lo up".into(),
            Self::Up => format!("bringing {name} up"),
            Self::Route => format!("adding the default route through {name}"),
        }
    }
}

/// Every argument the child passes to the kernel.
struct Plan {
    name: [libc::c_char; libc::IFNAMSIZ],
    /// The TAP to create, when the job creates one.
    create: Option<libc::ifreq>,
    mac: libc::ifreq,
    mtu: libc::ifreq,
    address: libc::ifreq,
    netmask: libc::ifreq,
    /// The two interfaces to bring up. The child reads their flags into
    /// these and writes them back.
    lo: libc::ifreq,
    up: libc::ifreq,
    route: libc::rtentry,
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

/// `name` as an `ifreq` holds it. The caller knows that it fits.
fn name_field(name: &str) -> [libc::c_char; libc::IFNAMSIZ] {
    let mut field = [0; libc::IFNAMSIZ];
    for (to, from) in field.iter_mut().zip(name.bytes()) {
        *to = from as libc::c_char;
    }
    field
}

fn interface_name(name: &str) -> io::Result<[libc::c_char; libc::IFNAMSIZ]> {
    let fits = !name.is_empty() && name.len() < libc::IFNAMSIZ;
    let plain = name
        .bytes()
        .all(|byte| byte.is_ascii_graphic() && byte != b'/' && byte != b':');
    if !fits || !plain || name == "lo" {
        return Err(invalid(format!(
            "{name:?} cannot name a box's network interface"
        )));
    }
    Ok(name_field(name))
}

/// An IPv4 address as the `sockaddr` an interface ioctl takes.
fn sockaddr(address: Ipv4Addr) -> libc::sockaddr {
    let mut out = libc::sockaddr {
        sa_family: libc::AF_INET as libc::sa_family_t,
        sa_data: [0; 14],
    };
    // A `sockaddr_in` has its port in the first two bytes.
    for (to, from) in out.sa_data[2..6].iter_mut().zip(address.octets()) {
        *to = from as libc::c_char;
    }
    out
}

fn request(name: [libc::c_char; libc::IFNAMSIZ]) -> libc::ifreq {
    // SAFETY: an `ifreq` is plain data, and all zeroes is a valid one.
    let mut request: libc::ifreq = unsafe { std::mem::zeroed() };
    request.ifr_name = name;
    request
}

fn netmask(prefix: u8) -> io::Result<Ipv4Addr> {
    match prefix {
        0 => Ok(Ipv4Addr::UNSPECIFIED),
        1..=32 => Ok(Ipv4Addr::from(u32::MAX << (32 - u32::from(prefix)))),
        _ => Err(invalid(format!("an IPv4 prefix has no length {prefix}"))),
    }
}

impl Plan {
    fn new(spec: &LinkSpec) -> io::Result<Self> {
        let name = match &spec.kind {
            LinkKind::Tap => interface_name(INTERFACE)?,
            LinkKind::Existing(name) => interface_name(name)?,
        };
        let create = matches!(spec.kind, LinkKind::Tap).then(|| {
            let mut create = request(name);
            // Ethernet frames with no header in front of them.
            create.ifr_ifru.ifru_flags = (libc::IFF_TAP | libc::IFF_NO_PI) as libc::c_short;
            create
        });
        let mut mac = request(name);
        let mut hardware = libc::sockaddr {
            sa_family: libc::ARPHRD_ETHER,
            sa_data: [0; 14],
        };
        for (to, from) in hardware.sa_data.iter_mut().zip(spec.mac) {
            *to = from as libc::c_char;
        }
        mac.ifr_ifru.ifru_hwaddr = hardware;
        let mut mtu = request(name);
        mtu.ifr_ifru.ifru_mtu = libc::c_int::from(spec.mtu);
        let mut address = request(name);
        address.ifr_ifru.ifru_addr = sockaddr(spec.address);
        let mut mask = request(name);
        mask.ifr_ifru.ifru_netmask = sockaddr(netmask(spec.prefix)?);
        // SAFETY: an `rtentry` is plain data, and all zeroes is a valid one.
        let mut route: libc::rtentry = unsafe { std::mem::zeroed() };
        route.rt_dst = sockaddr(Ipv4Addr::UNSPECIFIED);
        route.rt_genmask = sockaddr(Ipv4Addr::UNSPECIFIED);
        route.rt_gateway = sockaddr(spec.gateway);
        route.rt_flags = libc::RTF_UP | libc::RTF_GATEWAY;
        Ok(Self {
            name,
            create,
            mac,
            mtu,
            address,
            netmask: mask,
            lo: request(name_field("lo")),
            up: request(name),
            route,
        })
    }
}

/// Sets up the interface `spec` describes in the network namespace of the
/// process `netns_of`, which also holds the namespace's user namespace.
/// Returns the device's descriptor when the job created a TAP.
///
/// The child that does the work starts in `cgroup`, as every process that
/// runs in a box's namespaces does.
pub(crate) fn link(
    netns_of: u32,
    spec: &LinkSpec,
    cgroup: Option<BorrowedFd<'_>>,
) -> io::Result<Option<OwnedFd>> {
    let mut plan = Plan::new(spec)?;
    let namespaces = Namespaces::of(netns_of)?;
    let (ours, theirs) = std::os::unix::net::UnixStream::pair()?;
    // SAFETY: the child calls `setns`, `open`, `socket`, `ioctl`, `sendmsg`
    // and `_exit` on descriptors and memory prepared above, and nothing else.
    let (pid, _pidfd) = unsafe { core::clone_into(cgroup)? };
    if pid == 0 {
        // SAFETY: see above. The child never returns.
        unsafe { child(&mut plan, namespaces.raw(), theirs.as_raw_fd()) }
    }
    drop(theirs);
    let received = core::receive_report(&ours);
    let _ = core::reap(pid as u32, true);
    let name = match &spec.kind {
        LinkKind::Tap => INTERFACE,
        LinkKind::Existing(name) => name,
    };
    match received? {
        Some((0, _, tap)) if tap.is_some() == plan.create.is_some() => Ok(tap),
        Some((step, error, _)) if step != 0 => {
            let doing = Step::of(step).map_or_else(
                || "setting up the box's network".to_string(),
                |step| step.doing(name),
            );
            Err(io::Error::new(error.kind(), format!("{doing}: {error}")))
        }
        _ => Err(io::Error::other(
            "the process that sets up a box's network exited without its result",
        )),
    }
}

/// Reports the failure of `step` and ends the child.
///
/// # Safety
///
/// Only for the child of a `clone3`, right after the call that failed.
unsafe fn fail(out: libc::c_int, step: Step) -> ! {
    // SAFETY: the caller is the child, and no call came after the failure.
    unsafe { core::send_report(out, step as u8, core::errno(), -1) }
}

/// The child of [`link`]: joins, sets the interface up, reports, exits.
///
/// # Safety
///
/// Only for the child of a `clone3`. It never returns.
unsafe fn child(plan: &mut Plan, namespaces: (libc::c_int, libc::c_int), out: libc::c_int) -> ! {
    // SAFETY: direct syscalls on the parent's descriptors and on the child's
    // own copy of the plan.
    unsafe {
        if !core::join(namespaces) {
            fail(out, Step::Join);
        }
        let mut tap = -1;
        if let Some(create) = &plan.create {
            tap = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
            if tap < 0 || libc::ioctl(tap, libc::TUNSETIFF as _, &raw const *create) != 0 {
                fail(out, Step::Device);
            }
        }
        let control = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if control < 0 {
            fail(out, Step::Control);
        }
        // The hardware address first: a device that is up may refuse a new one.
        let settings = [
            (Step::Mac, libc::SIOCSIFHWADDR, &raw const plan.mac),
            (Step::Mtu, libc::SIOCSIFMTU, &raw const plan.mtu),
            (Step::Address, libc::SIOCSIFADDR, &raw const plan.address),
            (Step::Netmask, libc::SIOCSIFNETMASK, &raw const plan.netmask),
        ];
        for (step, request, argument) in settings {
            if libc::ioctl(control, request as _, argument) != 0 {
                fail(out, step);
            }
        }
        for (step, interface) in [
            (Step::Loopback, &raw mut plan.lo),
            (Step::Up, &raw mut plan.up),
        ] {
            if libc::ioctl(control, libc::SIOCGIFFLAGS as _, interface) != 0 {
                fail(out, step);
            }
            (*interface).ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            if libc::ioctl(control, libc::SIOCSIFFLAGS as _, interface) != 0 {
                fail(out, step);
            }
        }
        // Set here, where the plan has the address the kernel reads it at.
        plan.route.rt_dev = plan.name.as_mut_ptr();
        if libc::ioctl(control, libc::SIOCADDRT as _, &raw const plan.route) != 0 {
            fail(out, Step::Route);
        }
        core::send_report(out, 0, 0, tap)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: LinkKind) -> LinkSpec {
        LinkSpec {
            kind,
            mac: [0x02, 0x00, 0x64, 0x40, 0x01, 0x07],
            address: Ipv4Addr::new(100, 64, 1, 7),
            prefix: 16,
            gateway: Ipv4Addr::new(100, 64, 0, 1),
            mtu: 1500,
        }
    }

    fn name_of(request: &libc::ifreq) -> String {
        request
            .ifr_name
            .iter()
            .take_while(|byte| **byte != 0)
            .map(|byte| *byte as u8 as char)
            .collect()
    }

    fn address_of(sockaddr: libc::sockaddr) -> Ipv4Addr {
        assert_eq!(i32::from(sockaddr.sa_family), libc::AF_INET);
        let octets: Vec<u8> = sockaddr.sa_data[2..6].iter().map(|b| *b as u8).collect();
        Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])
    }

    #[test]
    fn a_plan_carries_the_spec_in_the_layout_the_kernel_reads() {
        // The kernel reads 40 bytes for every interface ioctl.
        assert_eq!(std::mem::size_of::<libc::ifreq>(), 40);
        let plan = Plan::new(&spec(LinkKind::Tap)).unwrap();
        let create = plan.create.expect("a TAP is created");
        assert_eq!(name_of(&create), "eth0");
        // SAFETY: each field read is the one `Plan::new` wrote.
        unsafe {
            assert_eq!(create.ifr_ifru.ifru_flags, 0x1002);
            let hardware = plan.mac.ifr_ifru.ifru_hwaddr;
            assert_eq!(hardware.sa_family, 1);
            assert_eq!(
                hardware.sa_data[..6]
                    .iter()
                    .map(|b| *b as u8)
                    .collect::<Vec<_>>(),
                [0x02, 0x00, 0x64, 0x40, 0x01, 0x07]
            );
            assert_eq!(plan.mtu.ifr_ifru.ifru_mtu, 1500);
            assert_eq!(
                address_of(plan.address.ifr_ifru.ifru_addr),
                Ipv4Addr::new(100, 64, 1, 7)
            );
            assert_eq!(
                address_of(plan.netmask.ifr_ifru.ifru_netmask),
                Ipv4Addr::new(255, 255, 0, 0)
            );
        }
        assert_eq!(name_of(&plan.lo), "lo");
        assert_eq!(name_of(&plan.up), "eth0");
        assert_eq!(
            address_of(plan.route.rt_gateway),
            Ipv4Addr::new(100, 64, 0, 1)
        );
        assert_eq!(address_of(plan.route.rt_dst), Ipv4Addr::UNSPECIFIED);
        assert_eq!(plan.route.rt_flags, 0x0003);
    }

    #[test]
    fn an_existing_interface_is_configured_under_its_own_name() {
        let plan = Plan::new(&spec(LinkKind::Existing("veth7".into()))).unwrap();
        assert!(plan.create.is_none());
        for request in [&plan.mac, &plan.mtu, &plan.address, &plan.netmask, &plan.up] {
            assert_eq!(name_of(request), "veth7");
        }
    }

    #[test]
    fn a_name_the_kernel_would_misread_is_refused() {
        for name in ["", "lo", "sixteen-letters-", "a/b", "eth0:1", "a b", "é"] {
            let refused = Plan::new(&spec(LinkKind::Existing(name.into())));
            assert!(refused.is_err(), "{name:?} was accepted");
        }
        assert!(Plan::new(&spec(LinkKind::Existing("fifteen-letters".into()))).is_ok());
    }

    #[test]
    fn a_prefix_length_becomes_its_netmask() {
        assert_eq!(netmask(0).unwrap(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(netmask(16).unwrap(), Ipv4Addr::new(255, 255, 0, 0));
        assert_eq!(netmask(30).unwrap(), Ipv4Addr::new(255, 255, 255, 252));
        assert_eq!(netmask(32).unwrap(), Ipv4Addr::BROADCAST);
        assert!(netmask(33).is_err());
    }

    #[test]
    fn every_step_has_its_own_number() {
        for step in Step::ALL {
            assert_eq!(Step::of(step as u8), Some(step));
        }
        assert_eq!(Step::of(0), None);
        assert_eq!(Step::of(11), None);
    }
}
