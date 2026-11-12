//! An address that names of several rules resolve to: it is judged by the
//! rules of all of them in list order, through a set the handles make for
//! it, which counts against the box's share and fails closed.

use std::{
    net::{IpAddr, SocketAddr, SocketAddrV4},
    time::Duration,
};

use boxbpf::{BoxId, Error, Limits};
use netpol::{
    Compiled, Direction, Endpoint, Flow, FlowVerdict, PortRange, Protocol, Protocols, Spec, Target,
    base::{CREDENTIAL_PROXY, Steered},
    policy::{BoxAction, BoxPolicy, BoxRule},
};

use crate::support::{Harness, REFUSED, host_ip, servers};

fn refused() -> String {
    format!("err {REFUSED}")
}

fn names(list: &[&str]) -> Vec<netpol::NamePattern> {
    list.iter().map(|n| n.parse().expect("name")).collect()
}

fn to_name(action: BoxAction, port: u16, name: &str) -> BoxRule {
    BoxRule {
        action,
        protocols: Protocols::TCP,
        ports: PortRange::one(port),
        to: Target::Names(name.parse().expect("name")),
    }
}

fn tcp(h: &Harness, name: &str, addr: IpAddr, port: u16) -> String {
    h.probe(name, &["tcp", &addr.to_string(), &port.to_string(), "500"])
}

/// What the evaluator says about TCP to `addr`, given the pins the kernel
/// has.
fn judged(h: &Harness, id: BoxId, compiled: &Compiled, addr: IpAddr, port: u16) -> FlowVerdict {
    let flow = Flow {
        direction: Direction::Egress,
        protocol: Protocol::Tcp,
        remote: addr,
        port,
        local: None,
    };
    compiled
        .evaluate(&flow, |a| h.handles.pinned_sets(id, a))
        .verdict
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn an_address_of_several_names_is_judged_by_the_rules_of_all_of_them() {
    let Some(mut h) = Harness::start(
        "cases::merged::an_address_of_several_names_is_judged_by_the_rules_of_all_of_them",
    ) else {
        return;
    };
    let (open, closed_for_a) = (servers::banner(), servers::banner());
    let proxy_at = SocketAddrV4::new(h.v4(6, 3), servers::free_port(IpAddr::V4(h.v4(6, 3))));
    let flows = h.handles.flows().expect("flows");
    let seen = servers::proxy_endpoint(SocketAddr::V4(proxy_at), &flows);
    let minute = Duration::from_secs(60);

    let mut deployment = host_ip();
    deployment.services.credential_proxy = Some(Endpoint {
        v4: Some(proxy_at),
        v6: None,
    });
    deployment.steered = vec![Steered {
        name: "steered.test".parse().expect("name"),
        port: open,
    }];
    let policy = BoxPolicy {
        rules: vec![to_name(BoxAction::Deny, closed_for_a, "a.test")],
        names: names(&["a.test", "b.test", "steered.test"]),
        ..BoxPolicy::default()
    };
    let mut live = h.install("m", deployment, policy);
    let id = live.id();
    let set = |name: &str| live.compiled().set_for_name(name).expect("a set");
    let (a, b, steered) = (set("a.test"), set("b.test"), set("steered.test"));
    let shared = IpAddr::V4(h.v4(5, 7));

    // One name: its rules alone.
    h.handles.pin(id, shared, "b.test", minute).expect("pin");
    assert!(tcp(&h, "m", shared, open).ends_with("data=hello"));
    assert!(tcp(&h, "m", shared, closed_for_a).ends_with("data=hello"));
    assert_eq!(h.handles.usage(id).expect("usage").merged_sets, 0);

    // A second name: the deny written for it comes before the allow of
    // the first in the list, and decides.
    h.handles.pin(id, shared, "a.test", minute).expect("pin");
    let mut both = vec![a, b];
    both.sort_unstable();
    assert_eq!(h.handles.pinned_sets(id, shared), both);
    assert!(tcp(&h, "m", shared, open).ends_with("data=hello"));
    assert_eq!(tcp(&h, "m", shared, closed_for_a), refused());
    let usage = h.handles.usage(id).expect("usage");
    assert_eq!((usage.merged_sets, usage.pins), (1, 1));
    let static_entries = netpol::abi::rule_entries(live.compiled());
    assert_eq!(usage.rule_entries, static_entries + 1);

    // A steered name too: its redirect is first in the list, and stays
    // first whichever name is answered last.
    h.handles
        .pin(id, shared, "steered.test", minute)
        .expect("pin");
    h.handles.pin(id, shared, "b.test", minute).expect("pin");
    let mut all = vec![a, b, steered];
    all.sort_unstable();
    assert_eq!(h.handles.pinned_sets(id, shared), all);
    assert_eq!(
        tcp(&h, "m", shared, open),
        format!("ok peer={} data=proxied", SocketAddr::new(shared, open))
    );
    let origin = seen
        .recv_timeout(Duration::from_secs(2))
        .expect("the proxy endpoint accepted")
        .origin
        .expect("a recorded flow");
    assert_eq!(
        (origin.destination, origin.endpoint),
        (SocketAddr::new(shared, open), CREDENTIAL_PROXY)
    );
    assert_eq!(
        h.probe("m", &["udp", &shared.to_string(), &open.to_string()]),
        refused()
    );
    assert_eq!(tcp(&h, "m", shared, closed_for_a), refused());
    // The set of two went with its last pin.
    assert_eq!(h.handles.usage(id).expect("usage").merged_sets, 1);
    // The evaluator, given the pins the kernel has, says the same.
    assert_eq!(
        judged(&h, id, live.compiled(), shared, open),
        FlowVerdict::Redirect(SocketAddr::V4(proxy_at))
    );
    assert_eq!(
        judged(&h, id, live.compiled(), shared, closed_for_a),
        FlowVerdict::Deny
    );

    // A change of policy: the merged set is made again from the new rules.
    let policy = BoxPolicy {
        names: names(&["a.test", "b.test", "steered.test"]),
        ..BoxPolicy::default()
    };
    let spec = Spec {
        policy,
        ..live.spec().clone()
    };
    h.handles.reconfigure(&mut live, spec).expect("reconfigure");
    assert!(tcp(&h, "m", shared, closed_for_a).ends_with("data=hello"));
    assert!(tcp(&h, "m", shared, open).ends_with("data=proxied"));
    assert_eq!(h.handles.usage(id).expect("usage").merged_sets, 1);
    // A name the new policy has no rule for leaves the address.
    let policy = BoxPolicy {
        names: names(&["a.test", "b.test"]),
        ..BoxPolicy::default()
    };
    let mut deployment = live.spec().deployment.clone();
    deployment.steered.clear();
    let spec = Spec {
        deployment,
        policy,
        options: live.spec().options,
    };
    h.handles.reconfigure(&mut live, spec).expect("reconfigure");
    assert!(tcp(&h, "m", shared, open).ends_with("data=hello"));
    assert_eq!(h.handles.pinned_sets(id, shared).len(), 2);

    // Without its pins the address has no set, and the merged set is gone.
    h.handles.unpin(id, shared).expect("unpin");
    assert_eq!(tcp(&h, "m", shared, open), refused());
    let usage = h.handles.usage(id).expect("usage");
    assert_eq!((usage.merged_sets, usage.pins), (0, 0));
    assert_eq!(
        usage.rule_entries,
        netpol::abi::rule_entries(live.compiled())
    );
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_name_that_runs_out_takes_its_rules_from_the_address() {
    let Some(mut h) =
        Harness::start("cases::merged::a_name_that_runs_out_takes_its_rules_from_the_address")
    else {
        return;
    };
    let (open, closed_for_a) = (servers::banner(), servers::banner());
    let policy = BoxPolicy {
        rules: vec![to_name(BoxAction::Deny, closed_for_a, "a.test")],
        names: names(&["a.test", "b.test"]),
        ..BoxPolicy::default()
    };
    let live = h.install("e", host_ip(), policy);
    let id = live.id();
    let shared = IpAddr::V4(h.v4(5, 7));
    h.handles
        .pin(id, shared, "b.test", Duration::from_secs(60))
        .expect("pin");
    h.handles
        .pin(id, shared, "a.test", Duration::from_millis(600))
        .expect("pin");
    assert_eq!(tcp(&h, "e", shared, closed_for_a), refused());
    let change = h.handles.next_pin_change().expect("a pin runs out first");
    assert!(change <= Duration::from_millis(600), "{change:?}");

    std::thread::sleep(change + Duration::from_millis(50));
    // The entry ended with its first name. Until the sweep nothing judges
    // the address, so the rules of the name that ran out admit nothing.
    assert_eq!(tcp(&h, "e", shared, open), refused());
    assert_eq!(h.handles.pinned_sets(id, shared), []);
    assert_eq!(h.handles.sweep_pins().expect("sweep"), 1);
    // The other name is live, and now its rules alone judge.
    assert!(tcp(&h, "e", shared, open).ends_with("data=hello"));
    assert!(tcp(&h, "e", shared, closed_for_a).ends_with("data=hello"));
    assert_eq!(h.handles.next_pin_change(), None);
    let usage = h.handles.usage(id).expect("usage");
    assert_eq!((usage.merged_sets, usage.pins), (0, 1));
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_merged_set_the_box_has_no_room_for_leaves_the_address_closed() {
    let Some(mut h) = Harness::start(
        "cases::merged::a_merged_set_the_box_has_no_room_for_leaves_the_address_closed",
    ) else {
        return;
    };
    let open = servers::banner();
    let minute = Duration::from_secs(60);
    let policy = BoxPolicy {
        names: names(&["a.test", "b.test"]),
        ..BoxPolicy::default()
    };
    let live = h.install("c", host_ip(), policy);
    let id = live.id();
    // Room for the policy and nothing more.
    let fits = netpol::abi::rule_entries(live.compiled());
    h.handles.set_limits(Limits {
        rule_entries: fits,
        pins: 16,
    });
    let (shared, other) = (IpAddr::V4(h.v4(5, 7)), IpAddr::V4(h.v4(5, 8)));
    h.handles.pin(id, shared, "a.test", minute).expect("pin");
    h.handles.pin(id, other, "a.test", minute).expect("pin");
    assert!(tcp(&h, "c", shared, open).ends_with("data=hello"));

    let error = h
        .handles
        .pin(id, shared, "b.test", minute)
        .expect_err("no room for a merged set");
    assert!(
        matches!(error, Error::RuleEntryLimit { needed, limit } if needed == fits + 1 && limit == fits),
        "{error}"
    );
    // Each name alone admits the address. Without the set of both it has
    // no pin at all.
    assert_eq!(tcp(&h, "c", shared, open), refused());
    assert_eq!(h.handles.pinned_sets(id, shared), []);
    assert_eq!(
        judged(&h, id, live.compiled(), shared, open),
        FlowVerdict::Deny
    );
    let usage = h.handles.usage(id).expect("usage");
    assert_eq!((usage.merged_sets, usage.pins_refused), (0, 1));
    // An address of one name is not touched.
    assert!(tcp(&h, "c", other, open).ends_with("data=hello"));

    // With room the next answer places the address.
    h.handles.set_limits(Limits {
        rule_entries: fits + 1,
        pins: 16,
    });
    h.handles.pin(id, shared, "b.test", minute).expect("pin");
    assert!(tcp(&h, "c", shared, open).ends_with("data=hello"));
    assert_eq!(h.handles.usage(id).expect("usage").merged_sets, 1);
}

#[test]
#[ignore = "needs BOXBPF_ROOT_TEST=1, sudo -n and systemd (scripts/boxbpf-root-tests.sh)"]
fn a_merged_list_that_does_not_fit_refuses_what_its_missing_rules_would_judge() {
    let Some(mut h) = Harness::start(
        "cases::merged::a_merged_list_that_does_not_fit_refuses_what_its_missing_rules_would_judge",
    ) else {
        return;
    };
    let (early, late) = (servers::banner(), servers::banner());
    let minute = Duration::from_secs(60);
    // Twenty rules for each of two names. The first of all and the last of
    // all are for ports something listens on.
    let mut rules = vec![to_name(BoxAction::Allow, early, "a.test")];
    rules.extend((0..19).map(|i| to_name(BoxAction::Allow, 1000 + i, "a.test")));
    rules.extend((0..19).map(|i| to_name(BoxAction::Allow, 2000 + i, "b.test")));
    rules.push(to_name(BoxAction::Allow, late, "b.test"));
    let policy = BoxPolicy {
        rules,
        ..BoxPolicy::default()
    };
    let live = h.install("o", host_ip(), policy);
    let id = live.id();
    let shared = IpAddr::V4(h.v4(5, 7));

    h.handles.pin(id, shared, "b.test", minute).expect("pin");
    assert!(tcp(&h, "o", shared, late).ends_with("data=hello"));
    assert_eq!(h.handles.take_set_overflow(id), None);

    h.handles.pin(id, shared, "a.test", minute).expect("pin");
    // A rule among the first is judged as before. The last rule is not in
    // the list any more, and what it allowed is refused.
    assert!(tcp(&h, "o", shared, early).ends_with("data=hello"));
    assert_eq!(tcp(&h, "o", shared, late), refused());
    assert_eq!(
        judged(&h, id, live.compiled(), shared, late),
        FlowVerdict::Deny
    );
    let told = h.handles.take_set_overflow(id).expect("told once");
    assert_eq!(told.address, shared);
    assert_eq!(told.names, ["b.test", "a.test"]);
    assert_eq!(
        (told.overflow.direction, told.overflow.rules),
        (Direction::Egress, 40)
    );
    // A box is told once.
    h.handles.unpin(id, shared).expect("unpin");
    h.handles.pin(id, shared, "b.test", minute).expect("pin");
    h.handles.pin(id, shared, "a.test", minute).expect("pin");
    assert_eq!(tcp(&h, "o", shared, late), refused());
    assert_eq!(h.handles.take_set_overflow(id), None);
}
