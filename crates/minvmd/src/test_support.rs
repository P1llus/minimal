//! Helpers shared by this crate's unit tests.

use std::io;
use std::sync::{Arc, Mutex};

use tracing_subscriber::fmt::MakeWriter;

/// A `MakeWriter` that collects everything written, so a test can assert on
/// log lines.
#[derive(Clone, Default)]
pub(crate) struct CaptureWriter(pub(crate) Arc<Mutex<Vec<u8>>>);

impl CaptureWriter {
    /// The captured log so far.
    pub(crate) fn contents(&self) -> String {
        let captured = self
            .0
            .lock()
            .expect("the capture's lock is held only across this read")
            .clone();
        String::from_utf8(captured).expect("tracing writes UTF-8")
    }
}

impl io::Write for CaptureWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("the capture's lock is held only across this append")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl MakeWriter<'_> for CaptureWriter {
    type Writer = CaptureWriter;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

/// Installs a capture as this thread's log subscriber, and returns it with
/// the guard that keeps it installed.
pub(crate) fn capture_log() -> (CaptureWriter, tracing::subscriber::DefaultGuard) {
    let log = CaptureWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(log.clone())
        .with_ansi(false)
        .finish();
    let guard = tracing::subscriber::set_default(subscriber);
    (log, guard)
}

/// A declared TCP mapping from a host port to a port in the box.
pub(crate) const fn tcp_mapping(external: u16, internal: u16) -> boxes::PortMapping {
    boxes::PortMapping {
        external_port: external,
        internal_port: internal,
        proto: boxes::IpProto::Tcp,
    }
}
