//! The token that closes gvproxy's API inside the virtual network.
//!
//! gvproxy serves its forwarder API at the gateway address, where every
//! guest and box can reach it. Started with a token file it answers 401
//! there to a request without the token. Nobody is given the token: the
//! daemon that runs gvproxy calls the API on gvproxy's unix socket, which
//! asks for none. So nothing on the virtual network can list, add or remove
//! a forward.

use std::io::{self, Read as _, Write as _};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

/// The token file's name, beside gvproxy's other files.
pub const FILE: &str = "gvproxy-api.token";

/// gvproxy's flag that names the token file.
pub const FLAG: &str = "-api-token-file";

/// gvproxy also reads a token from this variable. Only the file may set
/// one, so the daemon removes the variable from gvproxy's environment.
pub const ENV: &str = "GV_API_TOKEN";

/// Writes a fresh token to `path`, readable by this user only. gvproxy
/// refuses a token file with any other mode.
///
/// # Errors
///
/// The I/O error of reading the random source or writing the file.
pub fn write(path: &Path) -> io::Result<()> {
    let mut random = [0u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut random)?;
    let mut token = String::with_capacity(64);
    for byte in random {
        token.push_str(&format!("{byte:02x}"));
    }
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // A new file each time, so the mode is this call's and an old file's
    // wider mode cannot carry over.
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?
        .write_all(token.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn each_write_makes_a_new_private_token() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("run").join(FILE);
        write(&path).expect("first token");
        let first = std::fs::read_to_string(&path).expect("read");
        assert_eq!(first.len(), 64);
        // An earlier file with a wider mode does not keep it.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        write(&path).expect("second token");
        let second = std::fs::read_to_string(&path).expect("read");
        assert_ne!(first, second);
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}
