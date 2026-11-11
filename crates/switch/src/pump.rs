//! The frame pump: copies whole Ethernet frames between one local carrier
//! and gvproxy's `/connect` stream.
//!
//! The local carrier is a VM's virtio-net backend socket ([`Prefixed`]) or a
//! box's TAP descriptor ([`Packets`]). The pump converts the length framing
//! and nothing else. It never reads a frame's contents, so it holds no
//! policy.
//!
//! gvproxy can go away and come back while the local side stays up. The pump
//! then drops frames, redials, and carries on. It ends only when the local
//! side ends.

use std::future::Future;
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use tokio::io::unix::AsyncFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex;

/// The largest frame the pump carries. gvproxy's `/connect` framing has a
/// 2-byte length, so a longer frame cannot be sent and is dropped.
pub const MAX_FRAME: usize = 65_535;

/// The request that turns a connection to gvproxy's `-listen` socket into a
/// frame stream. gvproxy writes no response.
const CONNECT_REQUEST: &[u8] = b"POST /connect HTTP/1.0\r\nHost: localhost\r\n\r\n";

/// A length a [`Prefixed`] peer cannot mean. Past it the stream is out of
/// step and the pump stops instead of discarding gigabytes.
const PREFIXED_SANITY_LIMIT: usize = 16 * 1024 * 1024;

/// What one receive on the local side produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Recv {
    /// One frame was appended to the buffer.
    Frame,
    /// A frame longer than [`MAX_FRAME`] was consumed and discarded. The
    /// buffer is unchanged.
    Oversized(usize),
}

/// The receiving half of a local carrier.
pub trait FrameRx: Send {
    /// Appends the next frame to `buf`. `Ok(None)` is the end of the carrier.
    fn recv(&mut self, buf: &mut Vec<u8>) -> impl Future<Output = io::Result<Option<Recv>>> + Send;
}

/// The sending half of a local carrier.
pub trait FrameTx: Send {
    /// Sends one whole frame.
    fn send(&mut self, frame: &[u8]) -> impl Future<Output = io::Result<()>> + Send;
}

/// A local carrier of whole frames.
pub trait LocalSide: Send + 'static {
    type Rx: FrameRx + 'static;
    type Tx: FrameTx + 'static;
    fn split(self) -> (Self::Rx, Self::Tx);
}

/// A byte stream where a 4-byte big-endian length precedes each frame. This
/// is the framing libkrun's unixstream network backend speaks.
#[derive(Debug)]
pub struct Prefixed(pub UnixStream);

#[derive(Debug)]
pub struct PrefixedRx(OwnedReadHalf);

#[derive(Debug)]
pub struct PrefixedTx {
    stream: OwnedWriteHalf,
    out: Vec<u8>,
}

impl LocalSide for Prefixed {
    type Rx = PrefixedRx;
    type Tx = PrefixedTx;

    fn split(self) -> (PrefixedRx, PrefixedTx) {
        let (read, write) = self.0.into_split();
        (
            PrefixedRx(read),
            PrefixedTx {
                stream: write,
                out: Vec::with_capacity(4 + 2048),
            },
        )
    }
}

impl FrameRx for PrefixedRx {
    async fn recv(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<Recv>> {
        let mut head = [0u8; 4];
        // End of file is clean only between frames.
        let mut got = 0;
        while got < head.len() {
            let n = self.0.read(&mut head[got..]).await?;
            if n == 0 {
                return if got == 0 {
                    Ok(None)
                } else {
                    Err(io::ErrorKind::UnexpectedEof.into())
                };
            }
            got += n;
        }
        let len = u32::from_be_bytes(head) as usize;
        if len > PREFIXED_SANITY_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("frame length {len} is not one a network device sends"),
            ));
        }
        if len > MAX_FRAME {
            let mut left = len as u64;
            let mut sink = [0u8; 8192];
            while left > 0 {
                let want = left.min(sink.len() as u64) as usize;
                let n = self.0.read(&mut sink[..want]).await?;
                if n == 0 {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                left -= n as u64;
            }
            return Ok(Some(Recv::Oversized(len)));
        }
        let start = buf.len();
        buf.resize(start + len, 0);
        self.0.read_exact(&mut buf[start..]).await?;
        Ok(Some(Recv::Frame))
    }
}

impl FrameTx for PrefixedTx {
    async fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        // One write per frame, so the peer never sees a length without its
        // frame behind it.
        self.out.clear();
        self.out
            .extend_from_slice(&(frame.len() as u32).to_be_bytes());
        self.out.extend_from_slice(frame);
        self.stream.write_all(&self.out).await
    }
}

/// A descriptor where one read or write is one frame: a TAP device, or a
/// datagram socket.
#[derive(Debug)]
pub struct Packets(Arc<AsyncFd<OwnedFd>>);

impl Packets {
    /// Takes `fd` and makes it non-blocking. Must be called inside a tokio
    /// runtime.
    ///
    /// # Errors
    ///
    /// The error of `fcntl` or of registering the descriptor with the
    /// runtime.
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: `fd` is an open descriptor this value owns; F_GETFL and
        // F_SETFL touch no memory.
        unsafe {
            let flags = libc::fcntl(fd.as_raw_fd(), libc::F_GETFL);
            if flags == -1
                || libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) == -1
            {
                return Err(io::Error::last_os_error());
            }
        }
        // SAFETY: an `OwnedFd` is open, keeps its descriptor until it is
        // dropped, and the `AsyncFd` owns it from here.
        let registered = unsafe { AsyncFd::register(fd) }.map_err(io::Error::from)?;
        Ok(Self(Arc::new(registered)))
    }
}

#[derive(Debug)]
pub struct PacketsRx(Arc<AsyncFd<OwnedFd>>);

#[derive(Debug)]
pub struct PacketsTx(Arc<AsyncFd<OwnedFd>>);

impl LocalSide for Packets {
    type Rx = PacketsRx;
    type Tx = PacketsTx;

    fn split(self) -> (PacketsRx, PacketsTx) {
        (PacketsRx(Arc::clone(&self.0)), PacketsTx(self.0))
    }
}

impl FrameRx for PacketsRx {
    async fn recv(&mut self, buf: &mut Vec<u8>) -> io::Result<Option<Recv>> {
        let start = buf.len();
        // One byte more than the limit, so a frame over it is told apart
        // from one at it.
        buf.resize(start + MAX_FRAME + 1, 0);
        let read = loop {
            let mut ready = self.0.readable().await?;
            let attempt = ready.try_io(|fd| {
                // SAFETY: the pointer and length name the tail of `buf`,
                // which lives across the call.
                let n = unsafe {
                    libc::read(
                        fd.as_raw_fd(),
                        buf[start..].as_mut_ptr().cast(),
                        MAX_FRAME + 1,
                    )
                };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            });
            match attempt {
                Ok(result) => break result,
                Err(_would_block) => {}
            }
        };
        let n = match read {
            Ok(n) => n,
            Err(error) => {
                buf.truncate(start);
                return Err(error);
            }
        };
        if n == 0 {
            buf.truncate(start);
            return Ok(None);
        }
        if n > MAX_FRAME {
            buf.truncate(start);
            return Ok(Some(Recv::Oversized(n)));
        }
        buf.truncate(start + n);
        Ok(Some(Recv::Frame))
    }
}

impl FrameTx for PacketsTx {
    async fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        loop {
            let mut ready = self.0.writable().await?;
            let attempt = ready.try_io(|fd| {
                // SAFETY: the pointer and length name `frame`, which lives
                // across the call.
                let n = unsafe { libc::write(fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
                if n < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
            match attempt {
                Ok(result) => return result,
                Err(_would_block) => {}
            }
        }
    }
}

/// Where gvproxy listens and how fast the pump redials it.
#[derive(Debug, Clone)]
pub struct Config {
    /// gvproxy's `-listen` unix socket.
    pub gvproxy: PathBuf,
    /// The wait before the first redial.
    pub redial_min: Duration,
    /// The longest wait between redials.
    pub redial_max: Duration,
}

impl Config {
    #[must_use]
    pub fn new(gvproxy: PathBuf) -> Self {
        Self {
            gvproxy,
            redial_min: Duration::from_millis(100),
            redial_max: Duration::from_secs(1),
        }
    }
}

/// Counters a pump keeps while it runs.
#[derive(Debug, Default)]
pub struct Stats {
    pub to_switch: AtomicU64,
    pub to_local: AtomicU64,
    pub dropped_oversized: AtomicU64,
    pub dropped_link_down: AtomicU64,
    /// Connections to gvproxy that ended.
    pub redials: AtomicU64,
    pub link_up: AtomicBool,
}

impl Stats {
    fn count(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }
}

/// Why a pump stopped. Both are about the local side: the gvproxy side never
/// stops a pump.
#[derive(Debug)]
pub enum End {
    /// The local carrier reached end of file.
    LocalClosed,
    /// A read from or a write to the local carrier failed.
    LocalFailed(io::Error),
}

/// Runs the pump until the local side ends. Dropping the future stops it.
pub async fn run<L: LocalSide>(local: L, config: Config, stats: Arc<Stats>) -> End {
    let (rx, tx) = local.split();
    let link: Mutex<Option<OwnedWriteHalf>> = Mutex::new(None);
    tokio::select! {
        end = local_to_switch(rx, &link, &stats) => end,
        end = switch_to_local(tx, &link, &config, &stats) => end,
    }
}

async fn local_to_switch(
    mut rx: impl FrameRx,
    link: &Mutex<Option<OwnedWriteHalf>>,
    stats: &Stats,
) -> End {
    let mut buf = Vec::with_capacity(2 + 2048);
    loop {
        buf.clear();
        // Room for gvproxy's length, filled in once the frame is known.
        buf.extend_from_slice(&[0, 0]);
        match rx.recv(&mut buf).await {
            Ok(Some(Recv::Frame)) => {}
            Ok(Some(Recv::Oversized(_))) => {
                Stats::count(&stats.dropped_oversized);
                continue;
            }
            Ok(None) => return End::LocalClosed,
            Err(error) => return End::LocalFailed(error),
        }
        let len = buf.len() - 2;
        if len == 0 {
            continue;
        }
        buf[..2].copy_from_slice(&(len as u16).to_le_bytes());
        let mut link = link.lock().await;
        let Some(switch) = link.as_mut() else {
            Stats::count(&stats.dropped_link_down);
            continue;
        };
        if switch.write_all(&buf).await.is_ok() {
            Stats::count(&stats.to_switch);
        } else {
            // Dropping the write half shuts the connection down, so the
            // reading direction sees it end and redials.
            *link = None;
            Stats::count(&stats.dropped_link_down);
        }
    }
}

async fn switch_to_local(
    mut tx: impl FrameTx,
    link: &Mutex<Option<OwnedWriteHalf>>,
    config: &Config,
    stats: &Stats,
) -> End {
    let mut delay = config.redial_min;
    let mut frame = vec![0u8; MAX_FRAME];
    loop {
        if let Ok(mut read) = dial(config, link).await {
            stats.link_up.store(true, Ordering::Relaxed);
            delay = config.redial_min;
            loop {
                let mut head = [0u8; 2];
                if read.read_exact(&mut head).await.is_err() {
                    break;
                }
                let len = usize::from(u16::from_le_bytes(head));
                if read.read_exact(&mut frame[..len]).await.is_err() {
                    break;
                }
                if len == 0 {
                    continue;
                }
                if let Err(error) = tx.send(&frame[..len]).await {
                    return End::LocalFailed(error);
                }
                Stats::count(&stats.to_local);
            }
            *link.lock().await = None;
            stats.link_up.store(false, Ordering::Relaxed);
            Stats::count(&stats.redials);
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(config.redial_max);
    }
}

async fn dial(config: &Config, link: &Mutex<Option<OwnedWriteHalf>>) -> io::Result<OwnedReadHalf> {
    let mut stream = UnixStream::connect(&config.gvproxy).await?;
    stream.write_all(CONNECT_REQUEST).await?;
    let (read, write) = stream.into_split();
    *link.lock().await = Some(write);
    Ok(read)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UnixListener;

    const WAIT: Duration = Duration::from_secs(5);

    /// A stand-in for gvproxy's `/connect`: accepts, reads the request head,
    /// then speaks 2-byte little-endian frames.
    struct FakeSwitch {
        listener: UnixListener,
        path: PathBuf,
        _dir: tempfile::TempDir,
    }

    impl FakeSwitch {
        fn bind() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("gv.sock");
            let listener = UnixListener::bind(&path).unwrap();
            Self {
                listener,
                path,
                _dir: dir,
            }
        }

        async fn accept(&self) -> UnixStream {
            let (mut stream, _) = tokio::time::timeout(WAIT, self.listener.accept())
                .await
                .expect("the pump dials the switch")
                .unwrap();
            let mut head = Vec::new();
            while !head.ends_with(b"\r\n\r\n") {
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.unwrap();
                head.push(byte[0]);
            }
            assert!(head.starts_with(b"POST /connect HTTP/1.0\r\n"));
            stream
        }
    }

    async fn switch_reads(stream: &mut UnixStream) -> Vec<u8> {
        let mut head = [0u8; 2];
        tokio::time::timeout(WAIT, stream.read_exact(&mut head))
            .await
            .expect("a frame reaches the switch")
            .unwrap();
        let mut frame = vec![0u8; usize::from(u16::from_le_bytes(head))];
        stream.read_exact(&mut frame).await.unwrap();
        frame
    }

    async fn switch_writes(stream: &mut UnixStream, frame: &[u8]) {
        let mut out = (frame.len() as u16).to_le_bytes().to_vec();
        out.extend_from_slice(frame);
        stream.write_all(&out).await.unwrap();
    }

    async fn vm_writes(vm: &mut UnixStream, frame: &[u8]) {
        let mut out = (frame.len() as u32).to_be_bytes().to_vec();
        out.extend_from_slice(frame);
        vm.write_all(&out).await.unwrap();
    }

    async fn vm_reads(vm: &mut UnixStream) -> Vec<u8> {
        let mut head = [0u8; 4];
        tokio::time::timeout(WAIT, vm.read_exact(&mut head))
            .await
            .expect("a frame reaches the VM side")
            .unwrap();
        let mut frame = vec![0u8; u32::from_be_bytes(head) as usize];
        vm.read_exact(&mut frame).await.unwrap();
        frame
    }

    fn fast(path: &std::path::Path) -> Config {
        Config {
            gvproxy: path.to_path_buf(),
            redial_min: Duration::from_millis(10),
            redial_max: Duration::from_millis(40),
        }
    }

    async fn until(what: &str, mut holds: impl FnMut() -> bool) {
        let deadline = tokio::time::Instant::now() + WAIT;
        while !holds() {
            assert!(tokio::time::Instant::now() < deadline, "timed out: {what}");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn frames_cross_both_ways_with_the_length_converted() {
        let switch = FakeSwitch::bind();
        let (mut vm, host_end) = UnixStream::pair().unwrap();
        let stats = Arc::new(Stats::default());
        let pump = tokio::spawn(run(
            Prefixed(host_end),
            fast(&switch.path),
            Arc::clone(&stats),
        ));
        let mut gv = switch.accept().await;

        let up: Vec<u8> = (0..1514u32).map(|i| i as u8).collect();
        vm_writes(&mut vm, &up).await;
        assert_eq!(switch_reads(&mut gv).await, up);

        let down = vec![0xa5u8; 60];
        switch_writes(&mut gv, &down).await;
        assert_eq!(vm_reads(&mut vm).await, down);

        // The largest frame the 2-byte length can carry crosses whole.
        let largest = vec![7u8; MAX_FRAME];
        vm_writes(&mut vm, &largest).await;
        assert_eq!(switch_reads(&mut gv).await.len(), MAX_FRAME);
        switch_writes(&mut gv, &largest).await;
        assert_eq!(vm_reads(&mut vm).await, largest);

        assert_eq!(stats.to_switch.load(Ordering::Relaxed), 2);
        assert_eq!(stats.to_local.load(Ordering::Relaxed), 2);
        pump.abort();
    }

    #[tokio::test]
    async fn an_oversized_frame_is_dropped_and_the_stream_stays_in_step() {
        let switch = FakeSwitch::bind();
        let (mut vm, host_end) = UnixStream::pair().unwrap();
        let stats = Arc::new(Stats::default());
        let pump = tokio::spawn(run(
            Prefixed(host_end),
            fast(&switch.path),
            Arc::clone(&stats),
        ));
        let mut gv = switch.accept().await;

        vm_writes(&mut vm, &vec![1u8; MAX_FRAME + 1]).await;
        vm_writes(&mut vm, b"after the big one").await;
        assert_eq!(switch_reads(&mut gv).await, b"after the big one");
        assert_eq!(stats.dropped_oversized.load(Ordering::Relaxed), 1);
        pump.abort();
    }

    #[tokio::test]
    async fn the_pump_redials_and_drops_frames_while_the_switch_is_away() {
        let switch = FakeSwitch::bind();
        let (mut vm, host_end) = UnixStream::pair().unwrap();
        let stats = Arc::new(Stats::default());
        let pump = tokio::spawn(run(
            Prefixed(host_end),
            fast(&switch.path),
            Arc::clone(&stats),
        ));

        let gv = switch.accept().await;
        until("link up", || stats.link_up.load(Ordering::Relaxed)).await;
        drop(gv);
        until("link down", || stats.redials.load(Ordering::Relaxed) == 1).await;

        // The redial may already sit in the listener's backlog, so the frame
        // written now is either dropped or arrives on the new connection.
        vm_writes(&mut vm, b"lost").await;
        until("a frame is dropped or the pump is back", || {
            stats.dropped_link_down.load(Ordering::Relaxed) >= 1
                || stats.link_up.load(Ordering::Relaxed)
        })
        .await;
        let mut gv = switch.accept().await;
        until("link up again", || stats.link_up.load(Ordering::Relaxed)).await;

        // The VM end never closed, and frames flow again both ways.
        vm_writes(&mut vm, b"again").await;
        let mut seen = switch_reads(&mut gv).await;
        if seen == b"lost" {
            seen = switch_reads(&mut gv).await;
        }
        assert_eq!(seen, b"again");
        switch_writes(&mut gv, b"down again").await;
        assert_eq!(vm_reads(&mut vm).await, b"down again");
        assert!(!pump.is_finished());
        pump.abort();
    }

    #[tokio::test]
    async fn a_switch_that_is_not_there_yet_does_not_stop_the_pump() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("late.sock");
        let (mut vm, host_end) = UnixStream::pair().unwrap();
        let stats = Arc::new(Stats::default());
        let pump = tokio::spawn(run(Prefixed(host_end), fast(&path), Arc::clone(&stats)));

        vm_writes(&mut vm, b"nobody home").await;
        until("the frame is dropped", || {
            stats.dropped_link_down.load(Ordering::Relaxed) == 1
        })
        .await;

        let listener = UnixListener::bind(&path).unwrap();
        let (mut gv, _) = tokio::time::timeout(WAIT, listener.accept())
            .await
            .unwrap()
            .unwrap();
        let mut head = [0u8; CONNECT_REQUEST.len()];
        gv.read_exact(&mut head).await.unwrap();
        until("link up", || stats.link_up.load(Ordering::Relaxed)).await;
        vm_writes(&mut vm, b"hello").await;
        assert_eq!(switch_reads(&mut gv).await, b"hello");
        pump.abort();
    }

    #[tokio::test]
    async fn end_of_file_from_the_local_side_stops_the_pump() {
        let switch = FakeSwitch::bind();
        let (vm, host_end) = UnixStream::pair().unwrap();
        let stats = Arc::new(Stats::default());
        let pump = tokio::spawn(run(Prefixed(host_end), fast(&switch.path), stats));
        let mut gv = switch.accept().await;
        drop(vm);
        let end = tokio::time::timeout(WAIT, pump).await.unwrap().unwrap();
        assert!(matches!(end, End::LocalClosed));
        // The pump's connection to the switch goes with it.
        let mut byte = [0u8; 1];
        assert_eq!(gv.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn end_of_file_inside_a_frame_is_a_failure() {
        let switch = FakeSwitch::bind();
        let (mut vm, host_end) = UnixStream::pair().unwrap();
        let pump = tokio::spawn(run(
            Prefixed(host_end),
            fast(&switch.path),
            Arc::new(Stats::default()),
        ));
        let _gv = switch.accept().await;
        vm.write_all(&[0, 0, 0, 9, 1, 2]).await.unwrap();
        drop(vm);
        let end = tokio::time::timeout(WAIT, pump).await.unwrap().unwrap();
        assert!(matches!(end, End::LocalFailed(_)));
    }

    #[tokio::test]
    async fn packets_side_carries_one_frame_per_datagram() {
        let switch = FakeSwitch::bind();
        let (ours, theirs) = std::os::unix::net::UnixDatagram::pair().unwrap();
        let stats = Arc::new(Stats::default());
        let pump = tokio::spawn(run(
            Packets::new(OwnedFd::from(theirs)).unwrap(),
            fast(&switch.path),
            Arc::clone(&stats),
        ));
        let mut gv = switch.accept().await;
        ours.set_nonblocking(true).unwrap();
        let ours = tokio::net::UnixDatagram::from_std(ours).unwrap();

        ours.send(b"first").await.unwrap();
        ours.send(b"second frame").await.unwrap();
        assert_eq!(switch_reads(&mut gv).await, b"first");
        assert_eq!(switch_reads(&mut gv).await, b"second frame");

        switch_writes(&mut gv, b"to the box").await;
        let mut buf = [0u8; 64];
        let n = tokio::time::timeout(WAIT, ours.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"to the box");
        pump.abort();
    }

    /// Runs [`tap_child`] in a fresh user and network namespace, the way the
    /// native daemon gets a TAP without privilege.
    #[cfg(target_os = "linux")]
    #[test]
    fn packets_side_carries_frames_on_a_real_tap() {
        let can_unshare = std::process::Command::new("unshare")
            .args(["-Urn", "true"])
            .status()
            .is_ok_and(|status| status.success());
        if !can_unshare {
            eprintln!("skipped: this host cannot create a user and network namespace");
            return;
        }
        let out = std::process::Command::new("unshare")
            .args(["-Urn"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "pump::tests::tap_child",
                "--ignored",
                "--nocapture",
            ])
            .env("SWITCH_PUMP_TAP_CHILD", "1")
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "the TAP child failed:\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(String::from_utf8_lossy(&out.stdout).contains("1 passed"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "runs only as the child of packets_side_carries_frames_on_a_real_tap"]
    fn tap_child() {
        if std::env::var_os("SWITCH_PUMP_TAP_CHILD").is_none() {
            return;
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(tap::carries_frames());
    }

    #[cfg(target_os = "linux")]
    mod tap {
        use super::*;
        use std::os::fd::FromRawFd;

        const IFNAME: &[u8] = b"pumptap0";
        const TUNSETIFF: libc::c_ulong = 0x4004_54ca;

        #[repr(C)]
        struct IfReq {
            name: [u8; libc::IFNAMSIZ],
            data: [u8; 24],
        }

        fn ifreq() -> IfReq {
            let mut req = IfReq {
                name: [0; libc::IFNAMSIZ],
                data: [0; 24],
            };
            req.name[..IFNAME.len()].copy_from_slice(IFNAME);
            req
        }

        fn check(rc: libc::c_int, what: &str) {
            assert!(rc >= 0, "{what}: {}", io::Error::last_os_error());
        }

        /// Opens a TAP named [`IFNAME`] and brings it up.
        fn open_tap() -> OwnedFd {
            // SAFETY: plain system calls on descriptors this function owns,
            // with `IfReq` laid out as the kernel's `struct ifreq`.
            unsafe {
                let fd = libc::open(c"/dev/net/tun".as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
                check(fd, "open /dev/net/tun");
                let mut req = ifreq();
                let flags = (libc::IFF_TAP | libc::IFF_NO_PI) as u16;
                req.data[..2].copy_from_slice(&flags.to_ne_bytes());
                check(libc::ioctl(fd, TUNSETIFF as _, &mut req), "TUNSETIFF");

                let ctl = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
                check(ctl, "control socket");
                let mut req = ifreq();
                check(
                    libc::ioctl(ctl, libc::SIOCGIFFLAGS as _, &mut req),
                    "SIOCGIFFLAGS",
                );
                let mut flags = u16::from_ne_bytes([req.data[0], req.data[1]]);
                flags |= libc::IFF_UP as u16;
                req.data[..2].copy_from_slice(&flags.to_ne_bytes());
                check(
                    libc::ioctl(ctl, libc::SIOCSIFFLAGS as _, &mut req),
                    "SIOCSIFFLAGS",
                );
                libc::close(ctl);
                OwnedFd::from_raw_fd(fd)
            }
        }

        /// A packet socket bound to the TAP: what the box's network stack
        /// sends and receives on the interface.
        fn packet_socket() -> OwnedFd {
            // SAFETY: plain system calls; `sockaddr_ll` is zeroed and then
            // filled as the kernel expects.
            unsafe {
                let proto = (libc::ETH_P_ALL as u16).to_be();
                let fd = libc::socket(
                    libc::AF_PACKET,
                    libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                    i32::from(proto),
                );
                check(fd, "packet socket");
                let name = std::ffi::CString::new(IFNAME).unwrap();
                let index = libc::if_nametoindex(name.as_ptr());
                assert!(index > 0, "the TAP has an index");
                let mut addr: libc::sockaddr_ll = std::mem::zeroed();
                addr.sll_family = libc::AF_PACKET as u16;
                addr.sll_protocol = proto;
                addr.sll_ifindex = index as i32;
                check(
                    libc::bind(
                        fd,
                        (&raw const addr).cast(),
                        size_of::<libc::sockaddr_ll>() as u32,
                    ),
                    "bind packet socket",
                );
                OwnedFd::from_raw_fd(fd)
            }
        }

        fn frame(marker: u8, len: usize) -> Vec<u8> {
            let mut frame = vec![marker; len];
            // Broadcast destination, a local source, and an ethertype no
            // protocol handler claims, so the kernel adds nothing of its own.
            frame[..6].copy_from_slice(&[0xff; 6]);
            frame[6..12].copy_from_slice(&[0x02, 0, 0, 0, 0, marker]);
            frame[12..14].copy_from_slice(&[0x88, 0xb5]);
            frame
        }

        pub(super) async fn carries_frames() {
            let switch = FakeSwitch::bind();
            let tap = open_tap();
            let stack = Packets::new(packet_socket()).unwrap();
            let (mut stack_rx, mut stack_tx) = stack.split();
            let stats = Arc::new(Stats::default());
            let pump = tokio::spawn(run(
                Packets::new(tap).unwrap(),
                fast(&switch.path),
                Arc::clone(&stats),
            ));
            let mut gv = switch.accept().await;

            // What the stack sends on the interface reaches the switch. The
            // kernel also sends frames of its own on a new interface, so
            // look for ours.
            let up = frame(0x11, 1514);
            stack_tx.send(&up).await.unwrap();
            loop {
                if switch_reads(&mut gv).await == up {
                    break;
                }
            }

            // What the switch sends arrives on the interface.
            let down = frame(0x22, 600);
            switch_writes(&mut gv, &down).await;
            let mut buf = Vec::new();
            loop {
                buf.clear();
                let got = tokio::time::timeout(WAIT, stack_rx.recv(&mut buf))
                    .await
                    .expect("the frame arrives on the TAP")
                    .unwrap();
                if got == Some(Recv::Frame) && buf == down {
                    break;
                }
            }
            pump.abort();
        }
    }
}
