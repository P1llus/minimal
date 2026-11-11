//! Reading the engine's event ring buffer.

use std::{
    io,
    os::fd::{AsRawFd, RawFd},
};

use aya::maps::{MapData, RingBuf};
use netpol::event::{self, Event};
use tokio::io::{Interest, unix::AsyncFd};

/// The ring buffer of one engine. Reads never block.
pub struct Source {
    ring: RingBuf<MapData>,
    skipped: u64,
}

impl Source {
    pub(crate) const fn new(ring: RingBuf<MapData>) -> Self {
        Self { ring, skipped: 0 }
    }

    /// The next event, if one is waiting. Records of a kind this reader
    /// does not know are stepped over by their own size and counted, so
    /// this never returns [`Event::Unknown`].
    pub fn try_next(&mut self) -> Option<Event> {
        loop {
            let decoded = event::decode(&self.ring.next()?);
            match decoded {
                Some(Event::Unknown { .. }) | None => self.skipped += 1,
                Some(known) => return Some(known),
            }
        }
    }

    /// How many records were stepped over so far.
    #[must_use]
    pub const fn skipped(&self) -> u64 {
        self.skipped
    }
}

impl AsRawFd for Source {
    fn as_raw_fd(&self) -> RawFd {
        self.ring.as_raw_fd()
    }
}

/// Waits for events on a tokio runtime.
pub struct Reader {
    fd: AsyncFd<Source>,
}

impl Reader {
    /// Must be called from within a tokio runtime.
    pub fn new(source: Source) -> io::Result<Self> {
        // SAFETY: the Source owns the ring buffer map and with it the
        // descriptor, for as long as the AsyncFd owns the Source.
        let fd = unsafe { AsyncFd::register_with_interest(source, Interest::READABLE) }?;
        Ok(Self { fd })
    }

    /// The next event. Waits until the kernel has written one.
    pub async fn next(&mut self) -> io::Result<Event> {
        loop {
            if let Some(e) = self.fd.get_mut().try_next() {
                return Ok(e);
            }
            // The buffer is empty: sleep until the kernel signals new
            // data, then look again.
            self.fd.readable_mut().await?.clear_ready();
        }
    }

    /// How many records were stepped over so far.
    #[must_use]
    pub fn skipped(&self) -> u64 {
        self.fd.get_ref().skipped()
    }
}
