//! The VM's uplink, the publish verbs and the stream door, through the real
//! `minvmd run`, libkrun and gvproxy, with a probe guest in place of the
//! guest daemon.
//!
//! The probe (`tests/probe/init`) wires the guest the way the guest daemon
//! will: a bridge on the VM's network device and one "box" namespace on a
//! veth. It serves a page and a shell inside the box. This test plays the
//! guest daemon on the two guest doors' host sockets, reaches the box
//! through the forwards it publishes, and runs its checks in the box through
//! the shell.
//!
//! Gated like the other VM harnesses (`MINVMD_E2E=1`). It also needs the
//! host tools the probe is built from: bash, iproute2, socat, curl and a
//! static busybox.

#![cfg(all(minvmd_libkrun, target_os = "linux"))]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use minimald_rpc::{
    BoxControlReply, BoxControlRequest, GuestDoorReply, GuestDoorRequest, IpProto, PublishOrigin,
    PublishPortRequest, RegisterBoxRequest, RegisteredBox,
};
use serial_test::serial;

/// The address the probe gives its box: the first one the VM host hands out.
const PROBE_BOX: Ipv4Addr = Ipv4Addr::new(100, 64, 127, 255);
const GATEWAY: &str = "100.64.0.1";
const HOST_ALIAS: &str = "100.64.255.254";

fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

fn until<T>(what: &str, within: Duration, mut attempt: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + within;
    loop {
        if let Some(value) = attempt() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// One JSON line to a door socket and the one line it answers.
fn door_line(sock: &Path, line: &str) -> String {
    let mut stream =
        UnixStream::connect(sock).unwrap_or_else(|e| panic!("connect to {}: {e}", sock.display()));
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    writeln!(stream, "{line}").unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    reply.trim().to_string()
}

struct Vm {
    child: Child,
    state: tempfile::TempDir,
    host_dir: PathBuf,
    console: PathBuf,
    config: PathBuf,
}

impl Vm {
    fn host_door(&self) -> PathBuf {
        self.host_dir.join("control.sock")
    }

    fn guest_door(&self) -> PathBuf {
        self.host_dir.join("guest-control.sock")
    }

    fn console(&self) -> String {
        std::fs::read_to_string(&self.console).unwrap_or_default()
    }

    fn register(&self, name: &str, ports: &[u16], credentialed: bool) -> RegisteredBox {
        let request = BoxControlRequest::Register(RegisterBoxRequest {
            name: name.to_string(),
            ingress_ports: ports.to_vec(),
            egress: None,
            credentialed_upstream: credentialed.then(boxes::CredentialedUpstream::default),
            dynamic_ingress: None,
            dynamic_allowed_range: None,
            hold: false,
            task_slots: 0,
            host_ip: false,
        });
        let reply = door_line(
            &self.host_door(),
            &serde_json_lenient::to_string(&request).unwrap(),
        );
        match serde_json_lenient::from_str(&reply).unwrap() {
            BoxControlReply::Registered(registered) => registered,
            other => panic!("the registration of {name} was answered {other:?}"),
        }
    }

    /// One request as the guest daemon makes it on the control door.
    fn guest(&self, request: &GuestDoorRequest) -> GuestDoorReply {
        let reply = door_line(
            &self.guest_door(),
            &serde_json_lenient::to_string(request).unwrap(),
        );
        serde_json_lenient::from_str(&reply).unwrap_or_else(|e| panic!("reply {reply:?}: {e}"))
    }

    fn publish(&self, web: &RegisteredBox, external: u16, internal: u16) -> SocketAddrV4 {
        match self.guest(&GuestDoorRequest::PublishPort(PublishPortRequest {
            box_id: web.box_id,
            external,
            internal,
            proto: IpProto::Tcp,
            origin: PublishOrigin::Declared,
        })) {
            GuestDoorReply::Published { listener, .. } => listener,
            other => panic!("publishing {external} was answered {other:?}"),
        }
    }

    fn set_exposures(&self, ports: &[u16]) {
        let mut text = String::from("[host-exposures]\n");
        for port in ports {
            text.push_str(&format!("p{port} = {{ port = {port} }}\n"));
        }
        let next = self.config.with_extension("next");
        std::fs::write(&next, text).unwrap();
        std::fs::rename(&next, &self.config).unwrap();
        // The door looks at the file at most once a second.
        std::thread::sleep(Duration::from_millis(1300));
    }

    fn gvproxy_pid(&self) -> Option<u32> {
        let out = Command::new("pgrep")
            .args(["-f", "--"])
            .arg(format!("-listen unix://{}", self.host_dir.display()))
            .output()
            .ok()?;
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .next()?
            .trim()
            .parse()
            .ok()
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        let _ = Command::new(minvmd_bin())
            .arg("--minimal-state-dir")
            .arg(self.state.path().join("st"))
            .arg("stop")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        common::kill_group(&mut self.child);
        // gvproxy is stopped by the supervisor. One that is left is killed
        // here, so a failed test leaves nothing running.
        if let Some(pid) = self.gvproxy_pid() {
            eprintln!("uplink_boot: a gvproxy outlived its supervisor (pid {pid})");
            let _ = Command::new("kill").args(["-9", &pid.to_string()]).status();
        }
    }
}

/// A shell in the probe's box, reached through a published port.
struct BoxShell(SocketAddrV4);

impl BoxShell {
    /// Runs `script` in the box and returns what it printed.
    fn run(&self, script: &str) -> String {
        let mut stream = TcpStream::connect(self.0).expect("the box shell's forward accepts");
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .unwrap();
        stream
            .write_all(format!("{script}\nexit\n").as_bytes())
            .unwrap();
        let mut out = String::new();
        let _ = stream.read_to_string(&mut out);
        out
    }

    /// One stream on the stream door, opened the way the guest daemon will:
    /// a vsock connection to the host with the header as its first line.
    /// Prints the reply line, then the count of bytes that followed.
    fn stream(&self, header: &str) -> String {
        self.run(&format!(
            "printf '%s\\n' '{header}' | socat -t10 - VSOCK-CONNECT:2:{} | (read -r reply; echo \"$reply\"; busybox wc -c)",
            minimald_rpc::VM_HOST_STREAM_PORT
        ))
    }
}

fn http_get(addr: SocketAddrV4) -> Option<String> {
    let mut stream = TcpStream::connect_timeout(&addr.into(), Duration::from_secs(2)).ok()?;
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    stream
        .write_all(b"GET / HTTP/1.0\r\nHost: probe\r\n\r\n")
        .ok()?;
    let mut answer = String::new();
    stream.read_to_string(&mut answer).ok()?;
    (!answer.is_empty()).then_some(answer)
}

/// A service on the host's loopback: it answers every connection with a
/// megabyte and closes first.
fn loopback_megabyte() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { return };
            let _ = stream.write_all(&vec![b'x'; 1_000_000]);
        }
    });
    port
}

fn boot(gvproxy: &Path, probe: &Path) -> Vm {
    let state = tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("a short state dir");
    let console = state.path().join("console.log");
    let config_home = state.path().join("config");
    std::fs::create_dir_all(config_home.join("minimal")).unwrap();
    let config = config_home.join("minimal/config.toml");
    std::fs::write(&config, "").unwrap();
    let log = std::fs::File::create(state.path().join("minvmd.log")).unwrap();
    let child = Command::new(minvmd_bin())
        .arg("--minimal-state-dir")
        .arg(state.path().join("st"))
        .arg("run")
        .env("HOME", state.path())
        .env("XDG_CONFIG_HOME", &config_home)
        .env("MINVMD_INITRAMFS", probe)
        .env("MINVMD_BOOT_LOG", &console)
        .env("MINVMD_GVPROXY_BIN", gvproxy)
        .env("MINVMD_DATA_VOLUME_PATH", state.path().join("data-vol.raw"))
        .env("MINVMD_READY_TIMEOUT_SECS", "90")
        // The stand-in for the credential proxy, which runs on macOS only.
        .env("MINVMD_BEP_STUB", "1")
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .expect("spawning minvmd run");
    let host_dir = state.path().join("st/providers/local-minvmd0");
    Vm {
        child,
        state,
        host_dir,
        console,
        config,
    }
}

#[test]
#[serial]
#[ignore = "gated MINVMD_E2E=1; needs KVM, the guest kernel, gvproxy and the probe's host tools"]
fn the_vm_reaches_the_network_only_through_the_uplink_and_the_two_doors() {
    if !common::e2e() {
        common::skip_or_fail("uplink_boot", "MINVMD_E2E != 1");
        return;
    }
    let Some(gvproxy) = common::gvproxy_bin() else {
        common::skip_or_fail("uplink_boot", "no gvproxy binary");
        return;
    };
    let scratch = tempfile::tempdir().unwrap();
    let probe = scratch.path().join("probe.cpio");
    let built = Command::new(common::workspace_root().join("crates/minvmd/tests/probe/mkprobe.sh"))
        .arg(&probe)
        .output()
        .expect("running mkprobe.sh");
    if !built.status.success() {
        common::skip_or_fail(
            "uplink_boot",
            &format!(
                "the probe guest could not be built: {}",
                String::from_utf8_lossy(&built.stderr).trim()
            ),
        );
        return;
    }

    let mut vm = boot(&gvproxy, &probe);
    until("the probe's boot checks", Duration::from_secs(120), || {
        assert!(
            vm.child.try_wait().unwrap().is_none(),
            "minvmd exited during boot:\n{}",
            std::fs::read_to_string(vm.state.path().join("minvmd.log")).unwrap_or_default()
        );
        vm.console().contains("PROBE checks done").then_some(())
    });
    let console = vm.console();
    println!("--- probe console\n{}", {
        let lines: Vec<&str> = console.lines().filter(|l| l.starts_with("PROBE")).collect();
        lines.join("\n")
    });

    // The uplink: a network device with the node's MAC, and through it the
    // gateway, name resolution and the internet, from inside a box.
    assert!(
        console.contains("PROBE uplink: eth0 mac 52:54:00:40:ff:fd"),
        "{console}"
    );
    assert!(console.contains("PROBE check gateway: ok"), "{console}");
    assert!(console.contains("PROBE check dns: ok"), "{console}");
    assert!(console.contains("PROBE check internet: 200"), "{console}");
    // gvproxy's API inside the virtual network is closed.
    assert!(
        console.contains("PROBE check gateway-api: 401"),
        "{console}"
    );
    // No socket passthrough, and IPv6 is not turned off on the boot line.
    let cmdline = console
        .lines()
        .find(|l| l.starts_with("PROBE cmdline:"))
        .expect("the probe prints its boot line");
    assert!(!cmdline.contains("tsi_hijack"), "{cmdline}");
    assert!(!cmdline.contains("ipv6"), "{cmdline}");

    // A box registered by a host client, with two declared ports: the
    // probe's page and its shell.
    let web = vm.register("probe", &[18080, 18022], false);
    assert_eq!(
        web.switch_address, PROBE_BOX,
        "the probe's box address is the first one the VM host hands out"
    );

    // A published port: the host listener minvmd chose forwards to the box.
    let page = vm.publish(&web, 18080, 8080);
    assert_eq!(page, SocketAddrV4::new(web.loopback_address, 18080));
    let answer = until("the published page", Duration::from_secs(20), || {
        http_get(page)
    });
    assert!(answer.contains("probe box page"), "{answer}");
    println!("published {page} -> {PROBE_BOX}:8080: page served");

    let shell = BoxShell(vm.publish(&web, 18022, 8022));
    let pinged = shell.run(&format!(
        "busybox ping -c1 -W2 {GATEWAY} >/dev/null && echo gw-ok"
    ));
    assert!(pinged.contains("gw-ok"), "{pinged}");

    // The guest cannot publish past the registration: an undeclared port,
    // and a box the host never registered.
    let undeclared = vm.guest(&GuestDoorRequest::PublishPort(PublishPortRequest {
        box_id: web.box_id,
        external: 18099,
        internal: 8080,
        proto: IpProto::Tcp,
        origin: PublishOrigin::Declared,
    }));
    assert!(
        matches!(undeclared, GuestDoorReply::PublishRefused { .. }),
        "{undeclared:?}"
    );
    println!("undeclared publish: {undeclared:?}");

    // The host's loopback: no route through the virtual network, and the
    // stream door only at an exposed port.
    let service = loopback_megabyte();
    let direct = shell.run(&format!(
        "curl -s -m 4 -o /dev/null -w 'code=%{{http_code}}' http://{HOST_ALIAS}:{service}/"
    ));
    assert!(
        direct.contains("code=000"),
        "the host alias is not routed: {direct}"
    );
    println!("host alias {HOST_ALIAS}:{service} from the box: {direct}");

    let host_port = format!(
        r#"{{"box_id":"{}","purpose":{{"kind":"host_port","port":{service}}}}}"#,
        web.box_id
    );
    let closed = shell.stream(&host_port);
    assert!(
        closed.contains(r#""reason":"port_not_exposed""#),
        "{closed}"
    );
    println!(
        "stream door, port not exposed: {}",
        closed.trim().replace('\n', " | ")
    );

    vm.set_exposures(&[service]);
    let open = shell.stream(&host_port);
    assert!(open.contains(r#"{"stream":"open"}"#), "{open}");
    // The host side sent a megabyte and closed first. All of it arrived.
    assert!(open.contains("1000000"), "{open}");
    println!(
        "stream door, port exposed: {}",
        open.trim().replace('\n', " | ")
    );

    vm.set_exposures(&[]);
    let closed_again = shell.stream(&host_port);
    assert!(
        closed_again.contains(r#""reason":"port_not_exposed""#),
        "{closed_again}"
    );
    println!(
        "stream door, entry removed: {}",
        closed_again.trim().replace('\n', " | ")
    );

    // The credential proxy: only for a box registered with a grant.
    let proxy = |id: &minimald_rpc::BoxId| {
        format!(
            r#"{{"box_id":"{id}","purpose":{{"kind":"credential_proxy","source_port":51234,"destination":"140.82.112.3:443"}}}}"#
        )
    };
    let no_grant = shell.stream(&proxy(&web.box_id));
    assert!(
        no_grant.contains(r#""reason":"no_credentialed_grant""#),
        "{no_grant}"
    );
    let granted = vm.register("granted", &[], true);
    let delivered = shell.run(&format!(
        "printf '%s\\n' '{}' | socat -t10 - VSOCK-CONNECT:2:{}",
        proxy(&granted.box_id),
        minimald_rpc::VM_HOST_STREAM_PORT
    ));
    assert!(delivered.contains(r#"{"stream":"open"}"#), "{delivered}");
    assert!(
        delivered.contains(&format!(
            "source={}:51234 destination=140.82.112.3:443",
            granted.switch_address
        )),
        "{delivered}"
    );
    println!(
        "credential proxy stream: {}",
        delivered.trim().replace('\n', " | ")
    );

    // gvproxy dies. It is started again, the uplink reconnects, and the
    // forwards are bound again from the ledger.
    let old = vm.gvproxy_pid().expect("gvproxy runs");
    assert!(
        Command::new("kill")
            .args(["-9", &old.to_string()])
            .status()
            .unwrap()
            .success()
    );
    let new = until(
        "gvproxy to be started again",
        Duration::from_secs(30),
        || vm.gvproxy_pid().filter(|pid| *pid != old),
    );
    let answer = until(
        "the page after the restart",
        Duration::from_secs(30),
        || http_get(page).filter(|answer| answer.contains("probe box page")),
    );
    assert!(answer.contains("probe box page"));
    let pinged = until(
        "the uplink after the restart",
        Duration::from_secs(30),
        || {
            let out = shell.run(&format!(
                "busybox ping -c1 -W2 {GATEWAY} >/dev/null && echo gw-ok"
            ));
            out.contains("gw-ok").then_some(out)
        },
    );
    println!(
        "gvproxy {old} killed, {new} started: page served again, gateway {}",
        pinged.trim()
    );

    // The guest reports the box ended: its forwards are unbound.
    let ended = vm.guest(&GuestDoorRequest::EndBox(minimald_rpc::EndBoxRequest {
        box_id: web.box_id,
    }));
    assert_eq!(
        ended,
        GuestDoorReply::BoxEnded {
            ended: true,
            box_id: web.box_id,
            forwards_unbound: 2,
            still_bound: 0,
        }
    );
    assert!(
        TcpStream::connect_timeout(&page.into(), Duration::from_secs(2)).is_err(),
        "the ended box's port is closed on the host"
    );
    println!("end box: {ended:?}");
}
