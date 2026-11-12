//! minimald session end-to-end over the libkrun bridge (Stage 2).
//!
//! Reliable counterpart to ad-hoc `ssh`/`socat`/`nc` testing, which does NOT
//! round-trip the libkrun host-UDS↔vsock bridge (even the socat-echo stub
//! returns nothing via the CLI, while a Rust `UnixStream` client works).
//!
//! `minimald_exec_over_bridge` drives a real russh client over a `UnixStream`
//! to the bridge UDS: it authenticates, creates a session (`CreateSession` RPC
//! over an SSH subsystem), uploads a task-only `minimal.toml` into the session
//! workspace over SFTP, runs the `echo_ok` task in that session, and asserts the
//! stdout + exit status that come back — proving the full path host UDS →
//! libkrun bridge → guest vsock → minimald SSH (`run_on_vsock`, direct, no socat
//! relay) → session task exec. The `echo` task is serviced without a package
//! graph or sandbox, so the guest needs no network. Requires libkrun >= 1.19.0
//! on the host.
//!
//! Each test boots the VM under its supervisor (`minvmd run --detach`), which
//! holds the box table and the guest door. The in-VM daemon takes
//! every box id from that door (BOX-002), so a bare `minvmd boot` creates no
//! session.
//!
//! Gates:
//! - `#[cfg(minvmd_libkrun)]`: needs libkrun (macOS, or Linux with libkrun).
//! - `#[ignore]` + `MINVMD_E2E=1`: skipped unless explicitly enabled.
//! - `MINVMD_KERNEL_PATH`, `MINVMD_ROOTFS_PATH`, `MINVMD_INITRAMFS` must point to
//!   the kernel, the GENERIC rootfs, and the minimald initramfs cpio (minimald
//!   boots as the initramfs `/init`; nothing is baked into the rootfs).

#![cfg(minvmd_libkrun)]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use serial_test::serial;
use tempfile::TempDir;

/// Isolated `XDG_STATE_HOME` under /tmp: macOS's $TMPDIR is deep enough that
/// `<tempdir>/minimal/providers/local-minvmd0/*.sock` would overflow sun_path (104).
fn short_state_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("mnl")
        .tempdir_in("/tmp")
        .expect("creating isolated state dir")
}

/// The minvmd binary to boot: `MINVMD_BIN` when set — CI's split build/test
/// jobs run this harness on a different runner than the one that compiled it,
/// where the absolute path baked by `CARGO_BIN_EXE_minvmd` does not exist —
/// otherwise that compile-time cargo-built path.
fn minvmd_bin() -> std::ffi::OsString {
    std::env::var_os("MINVMD_BIN").unwrap_or_else(|| env!("CARGO_BIN_EXE_minvmd").into())
}

/// `run --detach`'s own wait for the host socket, and the guest READY
/// wait pinned beside it: a cold boot can spend 40-70 s before pid-1.
const DETACH_TIMEOUT_SECS: &str = "150";

/// How long `status --json` may take to report Running after the detach.
const RUNNING_TIMEOUT: Duration = Duration::from_secs(90);

/// The cap on one `minvmd` subcommand: above `run --detach`'s own timeout.
const SUBPROC_TIMEOUT: Duration = Duration::from_secs(180);

/// Env var the server reads to scope an exec to a session
/// (mirrors `minimald::MINIMAL_SESSION_ID_ENV`).
const MINIMAL_SESSION_ID_ENV: &str = "MINIMAL_SESSION_ID";

/// Returns true if the e2e suite is enabled (`MINVMD_E2E=1`), asserting the
/// required env vars are present when so.
fn e2e_enabled() -> bool {
    if !common::e2e() {
        common::skip_or_fail("minimald_session_integration", "MINVMD_E2E != 1");
        return false;
    }
    for var in &[
        "MINVMD_KERNEL_PATH",
        "MINVMD_ROOTFS_PATH",
        "MINVMD_INITRAMFS",
    ] {
        assert!(
            std::env::var(var).is_ok(),
            "minimald_session_integration: {var} must be set when MINVMD_E2E=1"
        );
    }
    true
}

/// A booted minimald guest VM under its supervisor, stopped on drop.
struct Guest {
    sock_path: PathBuf,
    state: TempDir,
}

impl Drop for Guest {
    fn drop(&mut self) {
        // Panic-safe teardown: a failed assertion must not leak the detached
        // supervisor whose state dir the `TempDir` then unlinks. Bounded, so
        // a wedged daemon cannot hang the teardown either.
        let _ = minvmd(self.state.path(), &["stop"]);
    }
}

/// Run one `minvmd` subcommand against the isolated state dir, bounded by
/// [`SUBPROC_TIMEOUT`]: a subprocess that overruns it is a wedged daemon,
/// killed so the test fails instead of hanging CI.
fn minvmd(state: &Path, args: &[&str]) -> Output {
    minvmd_with(state, args, &[])
}

/// [`minvmd`] with `env` added to the subcommand's environment.
fn minvmd_with(state: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut child = Command::new(minvmd_bin())
        .args(args)
        .envs(env.iter().copied())
        // HOME too, so no `dirs` fallback reaches the real state dir.
        .env("HOME", state)
        .env("XDG_STATE_HOME", state)
        // `--timeout` bounds only the detach poll. The VMM parent's guest
        // READY wait reads this env, and a cold boot can overrun its
        // default, so pin it here.
        .env("MINVMD_READY_TIMEOUT_SECS", DETACH_TIMEOUT_SECS)
        // Off the terminal, or libkrun's console setup stops the group.
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawning minvmd");
    let deadline = Instant::now() + SUBPROC_TIMEOUT;
    loop {
        if child.try_wait().expect("polling minvmd").is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("minvmd {args:?} did not exit within {SUBPROC_TIMEOUT:?} (wedged daemon?)");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    child.wait_with_output().expect("collecting minvmd output")
}

impl Guest {
    /// Boots the supervised VM with minimald as the guest init
    /// (`minvmd run --detach`) and polls `status --json` until Running.
    ///
    /// The supervisor, not a bare `minvmd boot`, because only the
    /// supervisor holds the box table and binds the guest door: the
    /// VM host daemon that mints every box id (BOX-002). A bare boot has no
    /// door, so the in-VM daemon refuses every create there.
    fn boot() -> Guest {
        Self::boot_with(&[])
    }

    /// [`Self::boot`] with `env` in the supervisor's environment.
    fn boot_with(env: &[(&str, &str)]) -> Guest {
        let state = short_state_dir();
        let host_dir = state.path().join("minimal/providers/local-minvmd0");
        let guest = Guest {
            sock_path: host_dir.join("ssh.sock"),
            state,
        };
        // minimald boots as the initramfs `/init` (MINVMD_INITRAMFS, set by
        // the caller); the rootfs stays generic.
        let run = minvmd_with(
            guest.state.path(),
            &["run", "--detach", "--timeout", DETACH_TIMEOUT_SECS],
            env,
        );
        assert!(
            run.status.success(),
            "minimald_session_integration: minvmd run --detach failed: {}\n--- run.log ---\n{}\n\
             are MINVMD_KERNEL_PATH/MINVMD_ROOTFS_PATH/MINVMD_INITRAMFS set correctly \
             (and libkrun >= 1.19.0)?",
            String::from_utf8_lossy(&run.stderr),
            guest.run_log(),
        );
        let deadline = Instant::now() + RUNNING_TIMEOUT;
        loop {
            let status = minvmd(guest.state.path(), &["status", "--json"]);
            let status: serde_json_lenient::Value = serde_json_lenient::from_slice(&status.stdout)
                .unwrap_or(serde_json_lenient::Value::Null);
            if status.get("state").is_some_and(|s| s == "running")
                && status.get("vmm_pid").is_some_and(|p| p.is_number())
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "minimald_session_integration: VM never reached Running within \
                 {RUNNING_TIMEOUT:?}; last status: {status}\n--- run.log ---\n{}",
                guest.run_log(),
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        guest
    }

    /// The guest's console, with the colour codes of its log lines removed.
    fn boot_log(&self) -> String {
        let path = self
            .state
            .path()
            .join("minimal/providers/local-minvmd0/boot.log");
        let raw = std::fs::read(&path).unwrap_or_default();
        let text = String::from_utf8_lossy(&raw);
        let mut plain = String::with_capacity(text.len());
        let mut chars = text.chars();
        while let Some(c) = chars.next() {
            if c == '\u{1b}' {
                for skipped in chars.by_ref() {
                    if skipped.is_ascii_alphabetic() {
                        break;
                    }
                }
            } else {
                plain.push(c);
            }
        }
        plain
    }

    /// The detached supervisor's stderr (boot-failure diagnosis), for panics.
    fn run_log(&self) -> String {
        let path = self
            .state
            .path()
            .join("minimal/providers/local-minvmd0/run.log");
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| format!("(no run.log at {}: {e})", path.display()))
    }

    /// The `box_id` of every `minted the box id for an in-VM create`
    /// record in the detached supervisor's `minvmd.log*` files, found
    /// anywhere under the isolated state dir. The files hold one JSON
    /// object per line.
    fn minted_box_ids(&self) -> Vec<String> {
        const MINT_RECORD: &str = "minted the box id for an in-VM create";
        let mut ids = Vec::new();
        let mut dirs = vec![self.state.path().to_path_buf()];
        while let Some(dir) = dirs.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    dirs.push(path);
                    continue;
                }
                let is_log = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("minvmd.log"));
                if !is_log {
                    continue;
                }
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                for line in text.lines().filter(|line| line.contains(MINT_RECORD)) {
                    let Ok(record) =
                        serde_json_lenient::from_str::<serde_json_lenient::Value>(line)
                    else {
                        continue;
                    };
                    let box_id = record
                        .get("box_id")
                        .or_else(|| record.get("fields").and_then(|f| f.get("box_id")))
                        .and_then(|v| v.as_str());
                    if let Some(box_id) = box_id {
                        ids.push(box_id.to_string());
                    }
                }
            }
        }
        ids
    }
}

// --- Full session: russh client → CreateSession → exec → stdout ---

/// russh client handler: accept the guest's ephemeral host key.
struct ClientHandler;

impl russh::client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &russh::keys::PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun >=1.19, kernel, rootfs, initramfs"]
async fn minimald_exec_over_bridge() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();
    let sentinel = "MINIMALD_SESSION_OK";
    // A task-only `minimal.toml` uploaded into the session workspace over
    // SFTP. The task is named on the wire as a `min://task/run` request and is
    // serviced straight from this declaration — no `[upstream]`, package graph,
    // or sandbox — so the guest needs no network and nothing baked into the
    // rootfs beyond minimald itself.
    let mfile = format!("[tasks.echo_ok]\necho = \"{sentinel}\"\n");

    // Retry the whole session to absorb the post-READY startup race.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut result = Err("not attempted".to_string());
    for attempt in 1..=6 {
        let task = minimald_rpc::exec::ExecRequest::TaskRun {
            task: "echo_ok".to_string(),
            owns_box: false,
            args: vec![],
            cwd: String::new(),
        }
        .encode();
        result = run_session_exec(&guest.sock_path, Some(&mfile), &task).await;
        if result.is_ok() {
            break;
        }
        eprintln!("session attempt {attempt}: {result:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    let (stdout, exit) = result.unwrap_or_else(|e| panic!("minimald_session_integration: {e}"));
    eprintln!("minimald_session_integration: exec stdout={stdout:?} exit={exit:?}");
    // Exact, not trimmed: the task's output is the whole of stdout, and the
    // in-process twin (`minimald::exec` `exec_runs_echo_task`) asserts the same
    // bytes. A trimming compare would swallow anything that leaked in
    // alongside it — including the leading blank line the old
    // argv-through-a-shell bug produced (gominimal/inbox#558).
    assert_eq!(
        stdout,
        format!("{sentinel}\n"),
        "expected stdout {sentinel:?} and nothing else, got {stdout:?}"
    );
    assert_eq!(exit, Some(0), "expected exit status 0, got {exit:?}");
}

/// The guest daemon wires its node to the VM's network device and loads the
/// policy engine itself, before it serves anything. Without either no box
/// with a network starts in the VM.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires libkrun >=1.19, kernel, rootfs, initramfs"]
async fn the_guest_node_has_its_network_and_its_engine() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();
    let deadline = Instant::now() + Duration::from_secs(30);
    let (network, engine) = (
        "the guest node's network is up",
        "the network policy engine is attached",
    );
    loop {
        let log = guest.boot_log();
        if log.contains(network) && log.contains(engine) {
            // The node sits on the VM host's virtual network, behind the
            // bridge that boxes with their own address hang off.
            let line = log
                .lines()
                .find(|line| line.contains(network))
                .unwrap_or_default();
            assert!(
                line.contains("address=100.64.255.253") && line.contains("gateway=100.64.0.1"),
                "{line}"
            );
            assert!(
                log.contains("br0: port 1(eth0) entered forwarding state"),
                "{log}"
            );
            assert!(!log.contains("no network policy engine"), "{log}");
            return;
        }
        assert!(
            Instant::now() < deadline,
            "the guest never reported its network and its engine:\n{log}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// BOX-002: the VM host daemon mints the id of a box before the in-VM
/// daemon creates it, and the box carries that id. The create request
/// carries a box id of its own, and the box does not take it: the id that
/// comes back is a fresh UUIDv7, never the request's.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1; requires Mac with libkrun >=1.19, kernel, rootfs, initramfs"]
async fn vm_host_mints_box_id_before_in_vm_create() {
    if !e2e_enabled() {
        return;
    }
    let guest = Guest::boot();
    let client_box_id = boxes::BoxId::mint();

    // Retry the create to absorb the post-READY startup race.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let mut result = Err("not attempted".to_string());
    for attempt in 1..=6 {
        result = async {
            let handle = connect_bridge(&guest.sock_path).await?;
            let mut req = e2e_session_request()?;
            req.config.box_id = Some(client_box_id);
            create_session(&handle, &req).await
        }
        .await;
        if result.is_ok() {
            break;
        }
        eprintln!("create attempt {attempt}: {result:?}");
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let id = result.unwrap_or_else(|e| panic!("minimald_session_integration: {e}"));
    eprintln!("minimald_session_integration: created box {id}");
    assert_ne!(
        id, client_box_id,
        "the box never takes the id its create request carried"
    );
    assert_eq!(
        AsRef::<uuid::Uuid>::as_ref(&id).get_version_num(),
        7,
        "the VM host daemon mints a UUIDv7"
    );
    // A UUIDv7 the in-VM store minted passes both asserts above. The
    // supervisor's own log record proves that the VM host daemon minted
    // this id, outside the VM.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let minted = guest.minted_box_ids();
        if minted.iter().any(|minted| minted == &id.to_string()) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "minimald_session_integration: the supervisor's minvmd.log has no \
             mint record for box {id}; it minted {minted:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// A project whose box has a shell, from the package index the daemon's
/// own tests pin.
const SHELL_PROJECT: &str = "[upstream]\nrepo = \"https://github.com/gominimal/pkgs\"\n\
     branch = \"main\"\nlocked_commit = \"1419729941fd3b67cec371b4064daafff0e69c7a\"\n\n\
     [defaults]\nstate_key = \"dev\"\n\n[session]\npackages = [\"base\"]\n";

/// The hosts of a GitHub grant, and a host of the same addresses that no
/// grant names.
const GITHUB_HOSTS: [&str; 4] = [
    "github.com",
    "api.github.com",
    "uploads.github.com",
    "codeload.github.com",
];
const SHARES_ADDRESSES: &str = "gist.github.com";
/// The upstream of a store rule.
const STORE_HOST: &str = "example.com";

/// A TLS ClientHello that asks for `name`, as the escapes bash's `printf`
/// writes it from.
fn client_hello_for_printf(name: &str) -> String {
    let sized = |width: usize, data: &[u8]| {
        let mut out = data.len().to_be_bytes()[8 - width..].to_vec();
        out.extend_from_slice(data);
        out
    };
    let mut entry = vec![0];
    entry.extend(sized(2, name.as_bytes()));
    let mut extensions = vec![0, 0];
    extensions.extend(sized(2, &sized(2, &entry)));
    // Versions, groups, signature algorithms and a key share, which a
    // server needs before it answers.
    extensions.extend_from_slice(&[0, 43, 0, 3, 2, 3, 4]);
    extensions.extend_from_slice(&[0, 10, 0, 4, 0, 2, 0, 29]);
    extensions.extend_from_slice(&[0, 13, 0, 8, 0, 6, 4, 3, 8, 4, 4, 1]);
    extensions.extend_from_slice(&[0, 51, 0, 38, 0, 36, 0, 29, 0, 32]);
    extensions.extend_from_slice(&[9; 32]);
    let mut body = vec![3, 3];
    body.extend_from_slice(&[7; 32]);
    body.extend(sized(1, &[5; 32]));
    body.extend(sized(2, &[0x13, 0x01, 0x13, 0x02]));
    body.extend(sized(1, &[0]));
    body.extend(sized(2, &extensions));
    let mut message = vec![1];
    message.extend(sized(3, &body));
    let mut record = vec![22, 3, 1];
    record.extend(sized(2, &message));
    record.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

/// A script that connects to `host` at 443, asks for the server `name`,
/// and prints what comes back: the line the credential proxy's stand-in
/// answers with, or the first three bytes of a TLS server's answer as
/// numbers.
fn tls_probe(host: &str, name: &str) -> String {
    format!(
        "exec 3<>/dev/tcp/{host}/443 || exit 1\n\
         printf '{hello}' >&3\n\
         LC_ALL=C IFS= read -r -t 20 -N 1 first <&3 || {{ echo nothing; exit 0; }}\n\
         if [ \"$first\" = b ]; then IFS= read -r -t 20 rest <&3; echo \"b$rest\"; exit 0; fi\n\
         printf '%d' \"'$first\"\n\
         for i in 1 2; do LC_ALL=C IFS= read -r -t 20 -N 1 c <&3 || break; printf ' %d' \"'$c\"; done\n\
         echo\n",
        hello = client_hello_for_printf(name),
    )
}

/// The first three bytes of a TLS server's answer: a handshake record.
const TLS_ANSWER: &str = "22 3 3";

/// A script that dials the proxy the box's environment names and asks it
/// for a tunnel, and prints the first line of the answer.
const PROXY_PROBE: &str = "p=\"${HTTPS_PROXY#http://}\"\n\
     [ -n \"$p\" ] || { echo \"no HTTPS_PROXY\"; exit 0; }\n\
     [ \"$HTTP_PROXY\" = \"$HTTPS_PROXY\" ] || echo \"HTTP_PROXY=$HTTP_PROXY\"\n\
     exec 3<>\"/dev/tcp/${p%:*}/${p##*:}\" || exit 1\n\
     printf 'CONNECT github.com:443 HTTP/1.1\\r\\nHost: github.com:443\\r\\n\\r\\n' >&3\n\
     IFS= read -r -t 20 line <&3; echo \"$p $line\"\n";

/// One JSON line to the supervisor's control socket and the line it
/// answers.
fn control_line(sock: &Path, line: &str) -> String {
    use std::io::{BufRead as _, Write as _};
    let mut stream = std::os::unix::net::UnixStream::connect(sock)
        .unwrap_or_else(|e| panic!("connect to {}: {e}", sock.display()));
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .expect("read timeout");
    writeln!(stream, "{line}").expect("write the request");
    let mut reply = String::new();
    std::io::BufReader::new(stream)
        .read_line(&mut reply)
        .expect("read the reply");
    reply.trim().to_string()
}

/// A box in a VM sends its connections for the credential proxy to its own
/// endpoint, and the node carries them to the proxy on the VM's host under
/// the box's id. The proxy here is the supervisor's stand-in, which answers
/// each connection with the box id and the entry it was delivered with.
///
/// Each box has a GitHub grant and the upstream of a store rule, and lists
/// their hosts in its egress, as the client's own checks require. The
/// client registers the box with the VM's host before it creates it, and
/// this test does the same on the control socket.
///
/// The boxes need a shell, which the guest fetches, and they connect to
/// GitHub. So the test runs only with `MINVMD_E2E_INTERNET=1`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
#[ignore = "gated MINVMD_E2E=1 and MINVMD_E2E_INTERNET=1; needs KVM, gvproxy and the internet"]
async fn a_box_s_connections_reach_the_credential_proxy_under_its_own_id() {
    use boxes::core::bep::{BepSettings, GrantSource, SecretGrant, Steering};
    use minimald_rpc::{BoxControlReply, BoxControlRequest, RegisterBoxRequest};

    if !e2e_enabled() {
        return;
    }
    if std::env::var_os("MINVMD_E2E_INTERNET").is_none() {
        eprintln!("skipping: MINVMD_E2E_INTERNET is not set");
        return;
    }
    let guest = Guest::boot_with(&[("MINVMD_BEP_STUB", "1")]);
    let control = guest
        .state
        .path()
        .join("minimal/providers/local-minvmd0/control.sock");
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut listed: Vec<String> = GITHUB_HOSTS.iter().map(|h| (*h).to_string()).collect();
    listed.push(SHARES_ADDRESSES.to_string());
    listed.push(STORE_HOST.to_string());
    let cases = [
        (
            "redirect-shares",
            boxes::NetworkMode::HostNet,
            Steering::Dns,
        ),
        ("redirect-own", boxes::NetworkMode::OwnIp, Steering::Dns),
        (
            "explicit-shares",
            boxes::NetworkMode::HostNet,
            Steering::ProxyEnv,
        ),
        (
            "explicit-own",
            boxes::NetworkMode::OwnIp,
            Steering::ProxyEnv,
        ),
    ];
    for (name, network, steering) in cases {
        let upstream = boxes::CredentialedUpstream {
            bep: BepSettings {
                steering: Some(steering),
                ..BepSettings::default()
            },
            secrets: [(
                "GH_TOKEN".to_string(),
                SecretGrant {
                    source: GrantSource::Broker,
                    scopes: vec!["github:user-token".to_string()],
                    mode: None,
                },
            )]
            .into(),
            store_upstreams: vec![STORE_HOST.to_string()],
        };
        let host_ip = network == boxes::NetworkMode::HostNet;
        let register = BoxControlRequest::Register(RegisterBoxRequest {
            name: name.to_string(),
            ingress_ports: Vec::new(),
            credentialed_upstream: Some(upstream.clone()),
            dynamic_ingress: None,
            dynamic_allowed_range: None,
            hold: false,
            task_slots: 0,
            host_ip,
        });
        let reply = control_line(&control, &serde_json_lenient::to_string(&register).unwrap());
        let (registered_id, addresses) = match serde_json_lenient::from_str(&reply) {
            Ok(BoxControlReply::Registered(row)) if !host_ip => (
                row.box_id,
                Some(boxes::BoxAddresses {
                    switch_address: row.switch_address,
                    loopback_address: row.loopback_address,
                }),
            ),
            Ok(BoxControlReply::BoxIdMinted { minted_box_id }) if host_ip => (minted_box_id, None),
            other => panic!("{name}: the registration was answered {other:?} ({reply})"),
        };

        let mut req = minimald_rpc::CreateSessionRequest::new(
            name.to_string(),
            paths::HostAbsPath::try_new("/tmp").unwrap(),
            network,
            Default::default(),
        );
        req.config.box_addresses = addresses;
        req.config.policy = boxes::BoxPolicy {
            egress: Some(boxes::EgressPolicy {
                allow_dns_hosts: Some(listed.clone()),
                ..boxes::EgressPolicy::default()
            }),
            credentialed_upstream: Some(upstream),
            ..boxes::BoxPolicy::default()
        };
        let (handle, id) = open_session(&guest.sock_path, &req, Some(SHELL_PROJECT))
            .await
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            id, registered_id,
            "{name}: the box has the id its host minted"
        );
        let id_text = id.to_string().replace('-', "");
        let run = |script: String| {
            let handle = &handle;
            async move {
                let argv = vec!["bash".to_string(), "-c".to_string(), script];
                let command = minimald_rpc::exec::ExecRequest::Argv(argv).encode();
                let (stdout, exit) = exec_in_session(handle, id, &command)
                    .await
                    .unwrap_or_else(|e| panic!("{name}: {e}"));
                eprintln!("{name}: exit {exit:?}: {}", stdout.trim_end());
                stdout.trim_end().to_string()
            }
        };

        let proxied = run(PROXY_PROBE.to_string()).await;
        let github = run(tls_probe("github.com", "github.com")).await;
        let store = run(tls_probe(STORE_HOST, STORE_HOST)).await;
        let other_name = run(tls_probe("github.com", SHARES_ADDRESSES)).await;
        let by_its_name = run(tls_probe(SHARES_ADDRESSES, SHARES_ADDRESSES)).await;
        let quic = run("echo x >/dev/udp/github.com/443".to_string()).await;
        let ssh = run(
            "exec 3<>/dev/tcp/github.com/22 && IFS= read -r -t 20 line <&3; echo \"${line:0:4}\""
                .to_string(),
        )
        .await;

        if steering == Steering::Dns {
            // The engine redirects the connection, and the node hands it
            // to the proxy with where the box sent it.
            let redirected = format!("box_id={id_text} entry=redirected destination=");
            for (what, said) in [("github.com", &github), (STORE_HOST, &store)] {
                assert!(
                    said.starts_with(&redirected) && said.ends_with(":443"),
                    "{name}: {what} answered {said:?}"
                );
            }
            // A name no grant names goes to the address the box sent it
            // to, at an address of a steered name too.
            assert_eq!(other_name, TLS_ANSWER, "{name}");
            assert_eq!(by_its_name, TLS_ANSWER, "{name}");
            assert!(quic.contains("Operation not permitted"), "{name}: {quic}");
            assert_eq!(proxied, "no HTTPS_PROXY", "{name}");
        } else {
            // The box dials its own endpoint, and nothing is redirected.
            let (endpoint, answer) = proxied.split_once(' ').unwrap_or_default();
            assert!(endpoint.starts_with("127.0.80.1:"), "{name}: {proxied}");
            assert_eq!(answer, format!("box_id={id_text} entry=dialled"), "{name}");
            for said in [&github, &store, &other_name, &by_its_name] {
                assert_eq!(said, TLS_ANSWER, "{name}");
            }
        }
        // Another port of a steered name follows the box's own rules.
        assert_eq!(ssh, "SSH-", "{name}");
    }
}

/// Open a russh client over the bridge UDS, authenticate, create a session,
/// optionally upload a `minimal.toml` into its workspace over SFTP, then exec
/// `command` in it. Returns `(stdout, exit_status)`.
async fn run_session_exec(
    sock_path: &Path,
    mfile: Option<&str>,
    command: &str,
) -> Result<(String, Option<u32>), String> {
    let (handle, session_id) = open_session(sock_path, &e2e_session_request()?, mfile).await?;
    exec_in_session(&handle, session_id, command).await
}

/// Open a russh client over the bridge UDS, authenticate, create the
/// session `req` asks for, optionally upload a `minimal.toml` into its
/// workspace over SFTP, and make it active.
async fn open_session(
    sock_path: &Path,
    req: &minimald_rpc::CreateSessionRequest,
    mfile: Option<&str>,
) -> Result<(russh::client::Handle<ClientHandler>, boxes::SessionId), String> {
    use minimald_rpc::OneshotSshRpc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let handle = connect_bridge(sock_path).await?;
    // CreateSession: open a channel, request the subsystem, write the JSON
    // request, half-close, read the JSON response.
    let session_id = create_session(&handle, req).await?;

    // Upload the project's `minimal.toml` into the session workspace over
    // SFTP (the subsystem presents the session's working tree at
    // `/workbench` and its home at `/home`, and reads the same session-id env
    // the exec path does).
    if let Some(contents) = mfile {
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open sftp channel: {e}"))?;
        channel
            .set_env(true, MINIMAL_SESSION_ID_ENV, session_id.to_string())
            .await
            .map_err(|e| format!("sftp set_env: {e}"))?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(|e| format!("request sftp subsystem: {e}"))?;
        let sftp = russh_sftp::client::SftpSession::new(channel.into_stream())
            .await
            .map_err(|e| format!("open sftp session: {e}"))?;
        // `create` (CREATE|WRITE|TRUNCATE), not the high-level `write` helper —
        // the latter opens WRITE-only and so fails on a not-yet-existing file.
        let mut file = sftp
            .create("/workbench/minimal.toml")
            .await
            .map_err(|e| format!("sftp create minimal.toml: {e}"))?;
        file.write_all(contents.as_bytes())
            .await
            .map_err(|e| format!("sftp write minimal.toml: {e}"))?;
        file.shutdown()
            .await
            .map_err(|e| format!("sftp close minimal.toml: {e}"))?;
        sftp.close()
            .await
            .map_err(|e| format!("close sftp session: {e}"))?;
    }

    // ConfigureLoadout: compose the session's loadout now that its workspace
    // holds the project files, finalizing it `Pending → Active`. This is the
    // ordering the create flow is split for, and it has to happen before the
    // exec below — a session with an unconfigured loadout has no context to
    // resolve a task against.
    {
        use minimald_rpc::{ConfigureLoadout, ConfigureLoadoutRequest, ConfigureLoadoutResponse};
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open ConfigureLoadout channel: {e}"))?;
        channel
            .request_subsystem(false, ConfigureLoadout::NAME)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;

        let req = ConfigureLoadoutRequest {
            session_id,
            contribution: Default::default(),
        };
        let body =
            serde_json_lenient::to_vec(&req).map_err(|e| format!("serialize request: {e}"))?;

        let mut rpc = channel.into_stream();
        rpc.write_all(&body)
            .await
            .map_err(|e| format!("write request: {e}"))?;
        rpc.shutdown()
            .await
            .map_err(|e| format!("shutdown write half: {e}"))?;
        let mut resp_buf = Vec::with_capacity(256);
        rpc.read_to_end(&mut resp_buf)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        let resp: <ConfigureLoadout as OneshotSshRpc>::Response =
            serde_json_lenient::from_slice(&resp_buf)
                .map_err(|e| format!("decode response: {e}"))?;
        match resp.ok() {
            // The uploaded mfile declares only tasks, so nothing needs a
            // client gate and the loadout finalizes in one shot.
            Some(ConfigureLoadoutResponse::Materialized) => {}
            Some(ConfigureLoadoutResponse::Pending { .. }) => {
                return Err("ConfigureLoadout returned Pending; \
                            this test's mfile gates nothing"
                    .to_string());
            }
            None => return Err("ConfigureLoadout returned an error".to_string()),
        }
    }

    // FinalizeSession: promote the record `Materializing → Active` so the
    // exec below passes minimald's status gate. The task-only mfile yields an
    // empty composition, so there are no patches to upload first — but
    // FinalizeSession is still required: the daemon takes the
    // composition-has-no-patches shortcut past the patches-ready marker check
    // and writes the record `Active`. (See crates/minvmd/examples/exec.rs.)
    {
        use minimald_rpc::{FinalizeSession, FinalizeSessionRequest};
        let channel = handle
            .channel_open_session()
            .await
            .map_err(|e| format!("open FinalizeSession channel: {e}"))?;
        channel
            .request_subsystem(false, FinalizeSession::NAME)
            .await
            .map_err(|e| format!("request_subsystem: {e}"))?;

        let req = FinalizeSessionRequest {
            session_id,
            report_shared_port_collisions: false,
        };
        let body =
            serde_json_lenient::to_vec(&req).map_err(|e| format!("serialize request: {e}"))?;

        let mut rpc = channel.into_stream();
        rpc.write_all(&body)
            .await
            .map_err(|e| format!("write request: {e}"))?;
        rpc.shutdown()
            .await
            .map_err(|e| format!("shutdown write half: {e}"))?;
        let mut resp_buf = Vec::with_capacity(256);
        rpc.read_to_end(&mut resp_buf)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        let resp: <FinalizeSession as OneshotSshRpc>::Response =
            serde_json_lenient::from_slice(&resp_buf)
                .map_err(|e| format!("decode response: {e}"))?;
        resp.ok()
            .ok_or_else(|| "FinalizeSession returned an error".to_string())?;
    }
    Ok((handle, session_id))
}

/// Exec `command` in the session over `handle`. Returns
/// `(stdout, exit_status)`.
async fn exec_in_session(
    handle: &russh::client::Handle<ClientHandler>,
    session_id: boxes::SessionId,
    command: &str,
) -> Result<(String, Option<u32>), String> {
    use russh::ChannelMsg;

    // Exec the command in that session.
    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open exec channel: {e}"))?;
    channel
        .set_env(true, MINIMAL_SESSION_ID_ENV, session_id.to_string())
        .await
        .map_err(|e| format!("set_env: {e}"))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("exec: {e}"))?;
    channel.eof().await.map_err(|e| format!("eof: {e}"))?;

    let mut stdout = Vec::new();
    let mut exit_status = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status: code } => exit_status = Some(code),
            ChannelMsg::Failure => return Err("exec request rejected (CHANNEL_FAILURE)".into()),
            _ => {}
        }
    }

    Ok((String::from_utf8_lossy(&stdout).into_owned(), exit_status))
}

/// Open a russh client over the bridge UDS and authenticate.
async fn connect_bridge(sock_path: &Path) -> Result<russh::client::Handle<ClientHandler>, String> {
    // Connect (retry briefly in case the guest vsock listener is not yet up).
    let stream = {
        let mut conn = None;
        let mut last_err = None;
        for _ in 0..20 {
            match tokio::net::UnixStream::connect(sock_path).await {
                Ok(s) => {
                    conn = Some(s);
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        conn.ok_or_else(|| format!("connect to bridge UDS: {}", last_err.unwrap()))?
    };

    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect_stream(config, stream, ClientHandler)
        .await
        .map_err(|e| format!("ssh connect: {e}"))?;

    let auth = handle
        .authenticate_none("minvmd-e2e")
        .await
        .map_err(|e| format!("authenticate_none: {e}"))?;
    if !auth.success() {
        return Err("auth_none rejected".into());
    }

    Ok(handle)
}

/// A session request under a name unique to this invocation.
fn e2e_session_request() -> Result<minimald_rpc::CreateSessionRequest, String> {
    // Unique name per invocation — minimald dedups sessions by
    // name, so the outer retry loop would otherwise collide on
    // `AlreadyExists` after any prior attempt persisted a record.
    // Matches the convention in `crates/minvmd/examples/exec.rs`.
    let uniq = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    // Hooks stay on, the serde default and what every non-`--no-hooks`
    // activation sends; this session only runs an exec, so it declares
    // no hooks either way. No version assertion: the guest daemon is
    // built from this same tree by the harness, so there is no skew to
    // assert against, and the gate has its own tests.
    let req = minimald_rpc::CreateSessionRequest::new(
        format!("minvmd-e2e-{uniq:x}"),
        paths::HostAbsPath::try_new("/tmp").map_err(|e| format!("project_path: {e}"))?,
        boxes::NetworkMode::default(),
        Default::default(),
    );
    Ok(req)
}

/// Create a session over `handle` with `req`: open a channel, request the
/// subsystem, write the JSON request, half-close, read the JSON response.
async fn create_session(
    handle: &russh::client::Handle<ClientHandler>,
    req: &minimald_rpc::CreateSessionRequest,
) -> Result<boxes::SessionId, String> {
    use minimald_rpc::{CreateSession, OneshotSshRpc};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("open CreateSession channel: {e}"))?;
    channel
        .request_subsystem(false, CreateSession::NAME)
        .await
        .map_err(|e| format!("request_subsystem: {e}"))?;

    let body = serde_json_lenient::to_vec(req).map_err(|e| format!("serialize request: {e}"))?;

    let mut rpc = channel.into_stream();
    rpc.write_all(&body)
        .await
        .map_err(|e| format!("write request: {e}"))?;
    rpc.shutdown()
        .await
        .map_err(|e| format!("shutdown write half: {e}"))?;
    let mut resp_buf = Vec::with_capacity(256);
    rpc.read_to_end(&mut resp_buf)
        .await
        .map_err(|e| format!("read response: {e}"))?;
    let resp: <CreateSession as OneshotSshRpc>::Response =
        serde_json_lenient::from_slice(&resp_buf).map_err(|e| format!("decode response: {e}"))?;
    // The refusal's own text, so a failed attempt names its cause (a create
    // minvmd gave no id is refused with a reply, BOX-002).
    match resp {
        minimald_rpc::Errorable::Ok(created) => Ok(created.id),
        minimald_rpc::Errorable::Err { error } => Err(format!("CreateSession refused: {error}")),
    }
}
