//! The client for gvproxy's forwarder API on its `-listen` unix socket.
//!
//! Every forward minvmd binds or unbinds on the host goes through here. The
//! socket is in the VM's host directory, which only this user can reach, so
//! the calls carry no token. gvproxy's copy of the API inside the virtual
//! network is closed by the token minvmd starts it with.

#![cfg_attr(not(minvmd_libkrun), allow(dead_code))]

use std::io::{self, Read as _, Write as _};
use std::net::SocketAddrV4;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use minimald_rpc::IpProto;

/// How long one call may take from connect to the end of the answer.
const CALL_TIMEOUT: Duration = Duration::from_secs(5);

/// The longest answer read. A forwarder answer is a few bytes.
const MAX_ANSWER: usize = 16 * 1024;

/// gvproxy's answer to an expose of a listener it already holds.
const ALREADY_BOUND: &str = "proxy already running";

/// gvproxy's answer to an unexpose of a listener it does not hold.
const NOT_BOUND: &str = "proxy not found";

/// The kernel's answer, passed on by gvproxy, when another process holds
/// the host port.
const ADDRESS_IN_USE: &str = "address already in use";

/// Why an expose did not bind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ExposeError {
    /// gvproxy holds a forward at the listener already.
    #[error("the switch already holds a forward at the listener")]
    AlreadyBound,
    /// Another process on the host holds the port.
    #[error("the host port is already in use")]
    AddressInUse,
    /// gvproxy answered with another failure.
    #[error("the switch answered the expose with HTTP {status}: {body:?}")]
    Refused { status: u16, body: String },
    /// No answer: gvproxy is down, restarting or stalled. The forward may or
    /// may not be bound.
    #[error("the expose went unanswered: {0}")]
    Unanswered(String),
}

/// Why an unexpose did not unbind.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum UnexposeError {
    #[error("the switch answered the unexpose with HTTP {status}: {body:?}")]
    Refused { status: u16, body: String },
    #[error("the unexpose went unanswered: {0}")]
    Unanswered(String),
}

/// What an unexpose found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Unexposed {
    /// Whether gvproxy held the forward. Either way it holds none now.
    pub(crate) was_bound: bool,
    /// The forwarded connections gvproxy closed with the listener.
    pub(crate) closed: u32,
}

/// A handle on one gvproxy's forwarder API.
#[derive(Debug, Clone)]
pub(crate) struct SwitchApi {
    sock: PathBuf,
    timeout: Duration,
}

impl SwitchApi {
    pub(crate) fn new(sock: PathBuf) -> Self {
        Self {
            sock,
            timeout: CALL_TIMEOUT,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Binds `local` on the host and forwards it to `remote` on the virtual
    /// network.
    pub(crate) fn expose(
        &self,
        local: SocketAddrV4,
        remote: SocketAddrV4,
        proto: IpProto,
    ) -> Result<(), ExposeError> {
        let body = format!(r#"{{"local":"{local}","remote":"{remote}","protocol":"{proto}"}}"#);
        let (status, answer) = self
            .post("expose", &body)
            .map_err(|error| ExposeError::Unanswered(error.to_string()))?;
        if (200..300).contains(&status) {
            return Ok(());
        }
        if answer.contains(ADDRESS_IN_USE) {
            return Err(ExposeError::AddressInUse);
        }
        if answer.trim() == ALREADY_BOUND {
            return Err(ExposeError::AlreadyBound);
        }
        Err(ExposeError::Refused {
            status,
            body: answer.trim().to_string(),
        })
    }

    /// Unbinds `local`. gvproxy closes the connections the forward carried.
    pub(crate) fn unexpose(
        &self,
        local: SocketAddrV4,
        proto: IpProto,
    ) -> Result<Unexposed, UnexposeError> {
        let body = format!(r#"{{"local":"{local}","protocol":"{proto}"}}"#);
        let (status, answer) = self
            .post("unexpose", &body)
            .map_err(|error| UnexposeError::Unanswered(error.to_string()))?;
        if (200..300).contains(&status) {
            return Ok(Unexposed {
                was_bound: true,
                closed: closed_count(&answer),
            });
        }
        if answer.trim() == NOT_BOUND {
            return Ok(Unexposed {
                was_bound: false,
                closed: 0,
            });
        }
        Err(UnexposeError::Refused {
            status,
            body: answer.trim().to_string(),
        })
    }

    /// One request on a fresh connection: the status and the body.
    fn post(&self, verb: &str, body: &str) -> io::Result<(u16, String)> {
        let deadline = std::time::Instant::now() + self.timeout;
        let mut switch = UnixStream::connect(&self.sock)?;
        switch.set_write_timeout(Some(self.timeout))?;
        let request = format!(
            "POST /services/forwarder/{verb} HTTP/1.1\r\nHost: localhost\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        switch.write_all(request.as_bytes())?;
        let mut answer = Vec::with_capacity(256);
        let mut chunk = [0u8; 1024];
        while answer.len() < MAX_ANSWER && !complete(&answer) {
            let left = deadline
                .checked_duration_since(std::time::Instant::now())
                .filter(|left| !left.is_zero())
                .ok_or(io::ErrorKind::TimedOut)?;
            switch.set_read_timeout(Some(left))?;
            let n = switch.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            answer.extend_from_slice(&chunk[..n]);
        }
        let text = String::from_utf8_lossy(&answer);
        let status = text
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse::<u16>().ok())
            .ok_or_else(|| io::Error::other("the switch's answer had no status line"))?;
        let body = text
            .split_once("\r\n\r\n")
            .map_or_else(String::new, |(_, body)| body.to_string());
        Ok((status, body))
    }
}

/// Whether `answer` holds a whole response: the head, and the body its
/// `Content-Length` announces.
fn complete(answer: &[u8]) -> bool {
    let Some(head_end) = answer.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let head = String::from_utf8_lossy(&answer[..head_end]);
    let length = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    });
    length.is_some_and(|length| answer.len() >= head_end + 4 + length)
}

/// The `closed` count of an unexpose answer, `{"closed":n}`.
fn closed_count(body: &str) -> u32 {
    #[derive(serde::Deserialize)]
    struct Answer {
        closed: u32,
    }
    serde_json::from_str::<Answer>(body.trim()).map_or(0, |answer| answer.closed)
}

#[cfg(test)]
pub(crate) mod testing {
    //! A stand-in for gvproxy's forwarder API, for this crate's tests.

    use std::collections::BTreeMap;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    /// One forward the fake holds: the remote it dials.
    pub(crate) type Forwards = BTreeMap<(String, String), String>;

    #[derive(Debug, Default)]
    struct State {
        forwards: Forwards,
        /// Host listeners another process holds: an expose there fails.
        occupied: Vec<String>,
        /// Requests in arrival order, as `verb local`.
        log: Vec<String>,
        /// How many of the next requests get a 500.
        fail_next: usize,
        /// The `closed` count the next unexposes report.
        closed: u32,
    }

    /// A fake switch serving on a unix socket in a temporary directory.
    #[derive(Debug, Clone)]
    pub(crate) struct FakeSwitch {
        pub(crate) sock: PathBuf,
        state: Arc<Mutex<State>>,
        _dir: Arc<tempfile::TempDir>,
    }

    impl FakeSwitch {
        pub(crate) fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let sock = dir.path().join("gv.sock");
            let fake = Self {
                sock: sock.clone(),
                state: Arc::default(),
                _dir: Arc::new(dir),
            };
            fake.listen();
            fake
        }

        fn listen(&self) {
            let listener = UnixListener::bind(&self.sock).unwrap();
            let state = Arc::clone(&self.state);
            std::thread::spawn(move || {
                for stream in listener.incoming() {
                    let Ok(stream) = stream else { return };
                    let mut reader = BufReader::new(stream);
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).unwrap_or(0) == 0 {
                        // A bare connect is how `stop` wakes the loop.
                        if state.lock().unwrap().log.last().map(String::as_str) == Some("stop") {
                            return;
                        }
                        continue;
                    }
                    let mut length = 0usize;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(value) =
                            line.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            length = value.trim().parse().unwrap();
                        }
                    }
                    let mut body = vec![0u8; length];
                    reader.read_exact(&mut body).unwrap();
                    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
                    let verb = request_line
                        .split_whitespace()
                        .nth(1)
                        .unwrap()
                        .rsplit('/')
                        .next()
                        .unwrap()
                        .to_string();
                    let local = body["local"].as_str().unwrap().to_string();
                    let proto = body["protocol"].as_str().unwrap().to_string();
                    let (status, answer) = {
                        let mut state = state.lock().unwrap();
                        state.log.push(format!("{verb} {local}"));
                        if state.fail_next > 0 {
                            state.fail_next -= 1;
                            (500, "the fake was told to fail".to_string())
                        } else if verb == "expose" {
                            let key = (local.clone(), proto);
                            if state.occupied.contains(&local) {
                                (
                                    500,
                                    format!("listen tcp {local}: bind: address already in use"),
                                )
                            } else if state.forwards.contains_key(&key) {
                                (500, "proxy already running".to_string())
                            } else {
                                let remote = body["remote"].as_str().unwrap().to_string();
                                state.forwards.insert(key, remote);
                                (200, String::new())
                            }
                        } else if state.forwards.remove(&(local, proto)).is_some() {
                            (200, format!("{{\"closed\":{}}}", state.closed))
                        } else {
                            (500, "proxy not found".to_string())
                        }
                    };
                    let mut stream = reader.into_inner();
                    let _ = write!(
                        stream,
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n{answer}",
                        answer.len()
                    );
                }
            });
        }

        pub(crate) fn forwards(&self) -> Forwards {
            self.state.lock().unwrap().forwards.clone()
        }

        /// The remote the forward at `local` dials, when one is bound.
        pub(crate) fn dials(&self, local: &str, proto: &str) -> Option<String> {
            self.forwards()
                .get(&(local.to_string(), proto.to_string()))
                .cloned()
        }

        pub(crate) fn log(&self) -> Vec<String> {
            self.state.lock().unwrap().log.clone()
        }

        pub(crate) fn occupy(&self, local: &str) {
            self.state.lock().unwrap().occupied.push(local.to_string());
        }

        pub(crate) fn free(&self, local: &str) {
            self.state
                .lock()
                .unwrap()
                .occupied
                .retain(|held| held != local);
        }

        pub(crate) fn fail_next(&self, count: usize) {
            self.state.lock().unwrap().fail_next = count;
        }

        pub(crate) fn report_closed(&self, closed: u32) {
            self.state.lock().unwrap().closed = closed;
        }

        /// Forgets every forward, as a restarted gvproxy does.
        pub(crate) fn restart(&self) {
            self.state.lock().unwrap().forwards.clear();
        }

        /// Stops serving and removes the socket, as a dead gvproxy leaves it.
        pub(crate) fn stop(&self) {
            self.state.lock().unwrap().log.push("stop".to_string());
            let _ = std::os::unix::net::UnixStream::connect(&self.sock);
            let _ = std::fs::remove_file(&self.sock);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testing::FakeSwitch;
    use super::*;

    fn addr(text: &str) -> SocketAddrV4 {
        text.parse().unwrap()
    }

    #[test]
    fn expose_binds_and_a_second_expose_is_already_bound() {
        let fake = FakeSwitch::start();
        let api = SwitchApi::new(fake.sock.clone());
        api.expose(
            addr("127.0.64.2:8080"),
            addr("100.64.128.2:80"),
            IpProto::Tcp,
        )
        .unwrap();
        assert_eq!(
            fake.dials("127.0.64.2:8080", "tcp").as_deref(),
            Some("100.64.128.2:80")
        );
        assert_eq!(
            api.expose(
                addr("127.0.64.2:8080"),
                addr("100.64.128.2:80"),
                IpProto::Tcp
            ),
            Err(ExposeError::AlreadyBound)
        );
    }

    #[test]
    fn expose_at_a_port_another_process_holds_is_address_in_use() {
        let fake = FakeSwitch::start();
        fake.occupy("127.0.0.1:7654");
        let api = SwitchApi::new(fake.sock.clone());
        assert_eq!(
            api.expose(
                addr("127.0.0.1:7654"),
                addr("100.64.255.253:7654"),
                IpProto::Tcp
            ),
            Err(ExposeError::AddressInUse)
        );
        assert!(fake.forwards().is_empty());
    }

    #[test]
    fn unexpose_reports_the_closed_connections_and_an_unbound_listener() {
        let fake = FakeSwitch::start();
        fake.report_closed(3);
        let api = SwitchApi::new(fake.sock.clone());
        api.expose(
            addr("127.0.0.1:9000"),
            addr("100.64.128.2:9000"),
            IpProto::Udp,
        )
        .unwrap();
        assert_eq!(
            api.unexpose(addr("127.0.0.1:9000"), IpProto::Udp),
            Ok(Unexposed {
                was_bound: true,
                closed: 3
            })
        );
        assert_eq!(
            api.unexpose(addr("127.0.0.1:9000"), IpProto::Udp),
            Ok(Unexposed {
                was_bound: false,
                closed: 0
            })
        );
    }

    #[test]
    fn other_failures_and_a_missing_switch_are_told_apart() {
        let fake = FakeSwitch::start();
        let api = SwitchApi::new(fake.sock.clone());
        fake.fail_next(2);
        assert!(matches!(
            api.expose(
                addr("127.0.0.1:9000"),
                addr("100.64.128.2:9000"),
                IpProto::Tcp
            ),
            Err(ExposeError::Refused { status: 500, .. })
        ));
        assert!(matches!(
            api.unexpose(addr("127.0.0.1:9000"), IpProto::Tcp),
            Err(UnexposeError::Refused { status: 500, .. })
        ));
        fake.stop();
        assert!(matches!(
            api.expose(
                addr("127.0.0.1:9000"),
                addr("100.64.128.2:9000"),
                IpProto::Tcp
            ),
            Err(ExposeError::Unanswered(_))
        ));
    }

    #[test]
    fn a_switch_that_never_answers_is_unanswered_within_the_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("mute.sock");
        let listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let api = SwitchApi::new(sock).with_timeout(Duration::from_millis(100));
        let started = std::time::Instant::now();
        assert!(matches!(
            api.unexpose(addr("127.0.0.1:9000"), IpProto::Tcp),
            Err(UnexposeError::Unanswered(_))
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        drop(listener);
    }
}
