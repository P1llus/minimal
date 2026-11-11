//! How a process of ours shows in `ps`.

use std::ffi::CStr;

/// Sets the name `ps -e` and `top` show for this process (at most 15 bytes).
pub(crate) fn set_comm(name: &CStr) {
    // SAFETY: `PR_SET_NAME` reads a NUL-terminated string that outlives the call.
    unsafe { libc::prctl(libc::PR_SET_NAME, name.as_ptr()) };
}

/// This process's name, as [`set_comm`] set it.
pub(crate) fn comm() -> [libc::c_char; 16] {
    let mut name = [0; 16];
    // SAFETY: `PR_GET_NAME` writes at most 16 bytes into the buffer.
    unsafe { libc::prctl(libc::PR_GET_NAME, name.as_mut_ptr()) };
    name
}

/// The memory the kernel reads this process's command line from: where
/// `execve` put the argument strings.
fn argument_area() -> Option<&'static mut [u8]> {
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    // The fields after the command name, which ends at the last `)`:
    // `arg_start` and `arg_end` are fields 48 and 49, and the state is 3.
    let fields: Vec<&str> = stat.rsplit_once(')')?.1.split_ascii_whitespace().collect();
    let start: usize = fields.get(45)?.parse().ok()?;
    let end: usize = fields.get(46)?.parse().ok()?;
    if start == 0 || end <= start {
        return None;
    }
    // SAFETY: the kernel reports the range of this process's own argument
    // strings, which stay mapped and writable for the process's life. Only a
    // single-threaded process calls this, so nothing else reads them.
    Some(unsafe { std::slice::from_raw_parts_mut(start as *mut u8, end - start) })
}

/// A changed process title, put back when dropped.
pub(crate) struct Title {
    comm: [libc::c_char; 16],
    arguments: Option<Vec<u8>>,
}

impl Title {
    /// Shows this process as `name` in `ps`, by its short name and by its
    /// command line. A process forked while the title is set keeps it.
    ///
    /// For a single-threaded process only: it writes the argument strings
    /// in place.
    pub(crate) fn set(name: &CStr) -> Self {
        let comm = comm();
        set_comm(name);
        let arguments = argument_area().map(|area| {
            let saved = area.to_vec();
            let bytes = name.to_bytes();
            let shown = bytes.len().min(area.len().saturating_sub(1));
            area.fill(0);
            area[..shown].copy_from_slice(&bytes[..shown]);
            saved
        });
        Self { comm, arguments }
    }
}

impl Drop for Title {
    fn drop(&mut self) {
        // SAFETY: `PR_SET_NAME` reads the NUL-terminated name saved above.
        unsafe { libc::prctl(libc::PR_SET_NAME, self.comm.as_ptr()) };
        if let (Some(saved), Some(area)) = (self.arguments.take(), argument_area())
            && saved.len() == area.len()
        {
            area.copy_from_slice(&saved);
        }
    }
}
