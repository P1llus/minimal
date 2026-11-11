//! The client's `[host-exposures]` table, as far as a project file is
//! concerned: only the client's own `config.toml` may set it.

/// The client configuration table that holds the host exposures.
pub const HOST_EXPOSURES_TABLE: &str = "host-exposures";

/// The warning for a project `minimal.toml` with a `[host-exposures]`
/// table.
pub const PROJECT_HOST_EXPOSURES_IGNORED: &str = "minimal.toml has a [host-exposures] table. \
     A project cannot open host ports to its boxes, so the table is ignored. Put the table in \
     your own config.toml instead. Run `min dirs` to find that file.";

/// Whether a project file's unknown keys hold a `[host-exposures]` table,
/// which the reader ignores. Logs [`PROJECT_HOST_EXPOSURES_IGNORED`] once
/// when they do.
pub fn warn_project_host_exposures<'a>(keys: impl IntoIterator<Item = &'a str>) -> bool {
    let found = keys.into_iter().any(|key| key == HOST_EXPOSURES_TABLE);
    if found {
        tracing::warn!("{PROJECT_HOST_EXPOSURES_IGNORED}");
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn project_host_exposures_ignored_with_warning() {
        assert!(warn_project_host_exposures([
            "session",
            HOST_EXPOSURES_TABLE
        ]));
        assert!(!warn_project_host_exposures(["session", "host-exposure"]));
        assert_eq!(
            PROJECT_HOST_EXPOSURES_IGNORED,
            "minimal.toml has a [host-exposures] table. A project cannot open host ports to \
             its boxes, so the table is ignored. Put the table in your own config.toml \
             instead. Run `min dirs` to find that file."
        );
    }
}
