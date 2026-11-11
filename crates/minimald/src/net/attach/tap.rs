//! The uplink of a native node: a TAP device in the box's namespace, whose
//! frames a pump carries to the node's gvproxy.
//!
//! The spawner's link job makes the device inside the namespace and hands
//! it back, so the daemon never enters that namespace itself.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use futures::future::BoxFuture;

use super::{Link, Place, Uplink};

/// Carries box frames to the gvproxy that listens on this socket.
#[derive(Debug, Clone)]
pub(crate) struct TapUplink {
    gvproxy: PathBuf,
}

impl TapUplink {
    pub(crate) const fn new(gvproxy: PathBuf) -> Self {
        Self { gvproxy }
    }
}

impl Uplink for TapUplink {
    fn connect<'a>(
        &'a self,
        spawned: &'a sandbox::Spawned,
        place: Place,
    ) -> BoxFuture<'a, io::Result<Link>> {
        Box::pin(async move {
            let tap = spawned
                .link(place.link_spec(sandbox::LinkKind::Tap))?
                .ok_or_else(|| io::Error::other("the spawner returned no device for the box"))?;
            let frames = ::switch::pump::Packets::new(tap)?;
            let config = ::switch::pump::Config::new(self.gvproxy.clone());
            let root = tracing::info_span!(parent: None, "net.pump", lease = %place.address);
            let pump = crate::traced::spawn_detached(root, async move {
                let stats = Arc::new(::switch::pump::Stats::default());
                let end = ::switch::pump::run(frames, config, stats).await;
                tracing::debug!(?end, "a box's frame pump ended");
            });
            // Ending the task closes the device.
            Ok(Link::new(move || pump.abort()))
        })
    }
}
