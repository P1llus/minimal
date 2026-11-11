//! A change of a box's policy: what happens to its pins, that the change
//! takes effect whole or not at all, and what one box may take of the maps
//! all boxes share.

use std::{net::IpAddr, time::Duration};

use boxbpf::{Error, Limits};
use netpol::{
    Direction, Flow, FlowVerdict, PortRange, Prefix, Protocol, Protocols, Spec, Target,
    policy::{BoxAction, BoxPolicy, BoxRule},
};

use crate::support::{Harness, REFUSED, host_ip, servers};

fn refused() -> String {
    format!("err {REFUSED}")
}

fn names(list: &[&str]) -> Vec<netpol::NamePattern> {
    list.iter().map(|n| n.parse().expect("name")).collect()
}

fn with_policy(live: &boxbpf::LiveBox, policy: BoxPolicy) -> Spec {
    Spec {
        policy,
        ..live.spec().clone()
    }
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn pins_follow_their_names_through_a_change_of_policy() {
    let Some(mut h) =
        Harness::start("cases::reconfigure::pins_follow_their_names_through_a_change_of_policy")
    else {
        return;
    };
    let port = servers::banner();
    let port_s = port.to_string();
    let minute = Duration::from_secs(60);
    let (gone, kept, api) = (
        IpAddr::V4(h.v4(5, 1)),
        IpAddr::V4(h.v4(5, 2)),
        IpAddr::V4(h.v4(5, 3)),
    );

    let policy = BoxPolicy {
        names: names(&["removed.test", "kept.test", "*.wild.test"]),
        ..BoxPolicy::default()
    };
    let mut live = h.install("n", host_ip(), policy);
    let id = live.id();
    for (addr, name) in [
        (gone, "removed.test"),
        (kept, "kept.test"),
        (api, "api.wild.test"),
    ] {
        h.handles.pin(id, addr, name, minute).expect("pin");
    }
    let wild = live
        .compiled()
        .set_for_name("api.wild.test")
        .expect("the wildcard's set");
    let reach =
        |h: &Harness, addr: IpAddr| h.probe("n", &["tcp", &addr.to_string(), &port_s, "500"]);
    for addr in [gone, kept, api] {
        assert!(reach(&h, addr).ends_with("data=hello"), "{addr} is pinned");
    }
    // A name the box has no rule for cannot be pinned.
    assert!(matches!(
        h.handles.pin(id, gone, "other.test", minute),
        Err(Error::NameWithoutRule(name)) if name == "other.test"
    ));

    // One name goes, one is added in front of the others, and one name
    // that the wildcard covered gets a rule of its own.
    let policy = BoxPolicy {
        rules: vec![BoxRule {
            action: BoxAction::Deny,
            protocols: Protocols::TCP,
            ports: PortRange::ALL,
            to: Target::Names("api.wild.test".parse().expect("name")),
        }],
        names: names(&["added.test", "kept.test", "*.wild.test"]),
        default: Some(netpol::Verdict::Deny),
        ..BoxPolicy::default()
    };
    let spec = with_policy(&live, policy);
    h.handles.reconfigure(&mut live, spec).expect("reconfigure");

    assert_eq!(
        reach(&h, gone),
        refused(),
        "the pin of a removed name must not admit the address any more"
    );
    assert!(
        reach(&h, kept).ends_with("data=hello"),
        "the pin of a name that stayed needs no new lookup: {}",
        reach(&h, kept)
    );
    assert_eq!(
        reach(&h, api),
        refused(),
        "the pin follows its name to the more specific rule"
    );
    assert_eq!(h.handles.pinned_set(id, gone), None);
    assert_eq!(
        h.handles.pinned_set(id, kept),
        live.compiled().set_for_name("kept.test")
    );
    let exact = h.handles.pinned_set(id, api).expect("still pinned");
    assert_ne!(exact, wild);
    assert_eq!(Some(exact), live.compiled().set_for_name("api.wild.test"));
    // The evaluator, given the pins the kernel has, says the same.
    for (addr, denied) in [(gone, true), (kept, false), (api, true)] {
        let flow = Flow {
            direction: Direction::Egress,
            protocol: Protocol::Tcp,
            remote: addr,
            port,
            local: None,
        };
        let verdict = live
            .compiled()
            .evaluate(&flow, h.handles.pinned_set(id, addr))
            .verdict;
        assert_eq!(verdict == FlowVerdict::Deny, denied, "{addr}");
    }
    assert_eq!(h.handles.usage(id).expect("usage").pins, 2);
}

fn prefixes(h: &Harness, group: u8, count: u8) -> Vec<Prefix> {
    (0..count)
        .map(|host| Prefix::host(IpAddr::V4(h.v4(group, host))))
        .collect()
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_box_is_held_to_its_share_of_the_maps() {
    let Some(mut h) = Harness::start("cases::reconfigure::a_box_is_held_to_its_share_of_the_maps")
    else {
        return;
    };
    let port = servers::banner().to_string();
    h.handles.set_limits(Limits {
        rule_entries: 8,
        pins: 2,
    });

    // A policy with more entries than a box may have is refused whole.
    let id = h.new_box("big");
    let spec = |allow: Vec<Prefix>| Spec {
        deployment: host_ip(),
        policy: BoxPolicy {
            allow,
            ..BoxPolicy::default()
        },
        options: netpol::compile::Options::default(),
    };
    let (twenty, eight) = (spec(prefixes(&h, 1, 20)), spec(prefixes(&h, 1, 8)));
    let error = h
        .handles
        .install(id, twenty)
        .err()
        .expect("twenty entries where eight are allowed");
    assert!(
        matches!(
            error,
            Error::RuleEntryLimit {
                needed: 20,
                limit: 8
            }
        ),
        "{error}"
    );
    assert_eq!(h.handles.usage(id), None);
    assert_eq!(h.handles.stats(id).expect("stats"), None);
    let stream = libc::SOCK_STREAM.to_string();
    assert_eq!(
        h.probe("big", &["sock", &libc::AF_INET.to_string(), &stream, "0"]),
        "err 1",
        "a box whose install failed has no network"
    );
    // The same box with a policy that fits.
    let mut live = h.handles.install(id, eight).expect("eight fit");
    assert_eq!(h.handles.usage(id).expect("usage").rule_entries, 8);
    // A reconfigure over the limit leaves the old policy in force.
    let too_many = spec(prefixes(&h, 3, 9));
    assert!(matches!(
        h.handles.reconfigure(&mut live, too_many),
        Err(Error::RuleEntryLimit {
            needed: 9,
            limit: 8
        })
    ));
    let reach = |h: &Harness, group: u8| {
        h.probe("big", &["tcp", &h.v4(group, 1).to_string(), &port, "500"])
    };
    assert!(reach(&h, 1).ends_with("data=hello"), "{}", reach(&h, 1));
    assert_eq!(reach(&h, 3), "err 1");

    // Pins: two at a time. The third is refused and counted.
    let policy = BoxPolicy {
        names: names(&["n.test"]),
        ..BoxPolicy::default()
    };
    let pinned = h.install("pins", host_ip(), policy);
    let id = pinned.id();
    let addrs: Vec<IpAddr> = (0..4).map(|host| IpAddr::V4(h.v4(5, host))).collect();
    let addr = |host: usize| addrs[host];
    h.handles
        .pin(id, addr(1), "n.test", Duration::from_millis(50))
        .expect("first pin");
    h.handles
        .pin(id, addr(2), "n.test", Duration::from_secs(60))
        .expect("second pin");
    let error = h
        .handles
        .pin(id, addr(3), "n.test", Duration::from_secs(60))
        .err()
        .expect("a third pin");
    assert!(matches!(error, Error::PinLimit { limit: 2 }), "{error}");
    let usage = h.handles.usage(id).expect("usage");
    assert_eq!((usage.pins, usage.pins_refused), (2, 1));
    assert_eq!(
        h.probe("pins", &["tcp", &addr(3).to_string(), &port, "500"]),
        refused()
    );
    // Renewing a pin the box has is not a new pin.
    h.handles
        .pin(id, addr(2), "n.test", Duration::from_secs(60))
        .expect("renew");
    // A pin that has run out gives its room to the next.
    std::thread::sleep(Duration::from_millis(80));
    h.handles
        .pin(id, addr(3), "n.test", Duration::from_secs(60))
        .expect("room again");
    assert!(
        h.probe("pins", &["tcp", &addr(3).to_string(), &port, "500"])
            .ends_with("data=hello")
    );
    let usage = h.handles.usage(id).expect("usage");
    assert_eq!((usage.pins, usage.pins_refused), (2, 1));
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_reconfigure_that_fails_leaves_the_old_policy_and_nothing_else() {
    // Rule maps with room for 64 prefixes per family, for all boxes.
    let Some(mut h) = Harness::start_sized(
        "cases::reconfigure::a_reconfigure_that_fails_leaves_the_old_policy_and_nothing_else",
        64,
    ) else {
        return;
    };
    let port = servers::banner().to_string();
    let allow = |list: Vec<Prefix>| BoxPolicy {
        allow: list,
        ..BoxPolicy::default()
    };
    // Box x takes 50 of the 64 entries, box y one.
    let mut wide = prefixes(&h, 1, 32);
    wide.extend(prefixes(&h, 2, 18));
    let x = h.install("x", host_ip(), allow(wide));
    let mut y = h.install("y", host_ip(), allow(prefixes(&h, 3, 1)));
    let reach = |h: &Harness, group: u8, host: u8| {
        h.probe("y", &["tcp", &h.v4(group, host).to_string(), &port, "500"])
    };
    assert!(reach(&h, 3, 0).ends_with("data=hello"));

    // Thirty new entries beside the fifty-one do not fit. The write stops
    // part of the way.
    let bigger = with_policy(&y, allow(prefixes(&h, 4, 30)));
    let error = h
        .handles
        .reconfigure(&mut y, bigger.clone())
        .err()
        .expect("the map is full");
    assert!(
        matches!(error, Error::Map { name: "rules4", .. }),
        "{error}"
    );
    // The old policy judges, whole: the old prefix is open, and none of
    // the new ones is, not even those that were written.
    assert!(
        reach(&h, 3, 0).ends_with("data=hello"),
        "{}",
        reach(&h, 3, 0)
    );
    assert_eq!(reach(&h, 4, 0), refused());
    assert_eq!(y.spec().policy.allow, prefixes(&h, 3, 1));
    assert_eq!(h.handles.usage(y.id()).expect("usage").rule_entries, 1);

    // Nothing of the failed attempt is left in the map: with x gone, 62
    // entries fit beside y's one. They would not beside the entries the
    // attempt had written.
    h.handles.uninstall(&x).expect("remove x");
    let mut most = prefixes(&h, 1, 32);
    most.extend(prefixes(&h, 2, 30));
    let z = h.install("z", host_ip(), allow(most));
    h.handles.uninstall(&z).expect("remove z");

    // Now the change fits, and it switches whole.
    h.handles.reconfigure(&mut y, bigger).expect("reconfigure");
    assert!(
        reach(&h, 4, 0).ends_with("data=hello"),
        "{}",
        reach(&h, 4, 0)
    );
    assert!(reach(&h, 4, 29).ends_with("data=hello"));
    assert_eq!(reach(&h, 3, 0), refused());
    assert_eq!(h.handles.usage(y.id()).expect("usage").rule_entries, 30);
}
