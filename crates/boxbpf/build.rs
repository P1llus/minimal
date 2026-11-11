//! Compiles the kernel programs in `bpf/` with clang and checks the C
//! layouts against `netpol::abi`.
//!
//! Needs `clang` with the BPF target and nothing else: every header the
//! programs include is in `bpf/`. `BOXBPF_CLANG` names another compiler.
//! On targets other than Linux there is nothing to build.

use std::{
    env, fs, io,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest as _, Sha256};

fn fail(message: &str) -> ! {
    println!("cargo::error={message}");
    std::process::exit(1);
}

fn main() {
    println!("cargo::rerun-if-changed=bpf");
    for path in LOADER_SOURCES {
        println!("cargo::rerun-if-changed={path}");
    }
    println!("cargo::rerun-if-env-changed=BOXBPF_CLANG");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let (Some(out), Some(manifest)) = (env::var_os("OUT_DIR"), env::var_os("CARGO_MANIFEST_DIR"))
    else {
        fail("cargo did not set OUT_DIR and CARGO_MANIFEST_DIR");
    };
    let (out, manifest) = (PathBuf::from(out), PathBuf::from(manifest));

    // The C side must match the Rust side: a wrong size or offset is a
    // compile error in clang, here.
    if let Err(e) = fs::write(out.join("abi_check.h"), netpol::abi::c_static_asserts()) {
        fail(&format!("cannot write abi_check.h: {e}"));
    }

    let clang = env::var("BOXBPF_CLANG").unwrap_or_else(|_e| "clang".into());
    let object = out.join("boxbpf.bpf.o");
    let status = Command::new(&clang)
        .current_dir(&manifest)
        .args(["-target", "bpf", "-O2", "-g", "-Wall", "-Werror"])
        // v2 instructions load on every kernel the engine supports.
        .arg("-mcpu=v2")
        // Keep build paths out of the debug info that carries the BTF.
        .arg(format!("-ffile-prefix-map={}=boxbpf", manifest.display()))
        .arg(format!("-ffile-prefix-map={}=out", out.display()))
        .args(["-Ibpf", "-Ibpf/include"])
        .arg("-I")
        .arg(&out)
        .args(["-c", "bpf/boxbpf.bpf.c", "-o"])
        .arg(&object)
        .status();
    match status {
        Ok(s) if s.success() => {}
        Ok(s) => fail(&format!("{clang} failed on bpf/boxbpf.bpf.c ({s})")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => fail(&format!(
            "`{clang}` not found. The box policy programs are built with clang (BPF target). \
             Install clang, or set BOXBPF_CLANG to a clang binary."
        )),
        Err(e) => fail(&format!("cannot run {clang}: {e}")),
    }

    // Loader and daemon compare this, so a daemon never runs on programs
    // other than the ones it was built with.
    let bytes = match fs::read(&object) {
        Ok(bytes) => bytes,
        Err(e) => fail(&format!("cannot read {}: {e}", object.display())),
    };
    let id: String = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    println!("cargo::rustc-env=BOXBPF_OBJECT_ID={id}");

    match loader_id(&manifest) {
        Ok(id) => println!("cargo::rustc-env=BOXBPF_LOADER_ID={id}"),
        Err(e) => fail(&format!("cannot hash the loader's sources: {e}")),
    }
}

/// What the root loader is built from, relative to this crate: the crate
/// itself, the layouts it checks its programs against, and the lock file.
const LOADER_SOURCES: [&str; 6] = [
    "src",
    "bpf",
    "build.rs",
    "Cargo.toml",
    "../netpol/src/abi.rs",
    LOCK_FILE,
];

const LOCK_FILE: &str = "../../Cargo.lock";

/// The packages whose code the loader runs with the kernel and the socket.
/// Of the lock file only their entries count: it changes with every
/// release, and the loader does not.
const LOADER_PACKAGES: [&str; 4] = ["aya", "aya-obj", "libc", "nix"];

/// The lock file's entries for [`LOADER_PACKAGES`].
fn locked_versions(lock: &str) -> String {
    lock.split("[[package]]")
        .filter(|entry| {
            LOADER_PACKAGES.iter().any(|name| {
                entry
                    .trim_start()
                    .starts_with(&format!("name = \"{name}\"\n"))
            })
        })
        .collect()
}

fn files_below(path: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            files_below(&entry?.path(), out)?;
        }
    } else {
        out.push(path.to_path_buf());
    }
    Ok(())
}

/// One hash over the loader's sources: each file's path and content, in
/// path order.
fn loader_id(manifest: &Path) -> io::Result<String> {
    let mut files = Vec::new();
    for source in LOADER_SOURCES {
        files_below(&manifest.join(source), &mut files)?;
    }
    files.sort();
    let mut hash = Sha256::new();
    for file in files {
        let name = file.strip_prefix(manifest).unwrap_or(&file);
        hash.update(name.to_string_lossy().as_bytes());
        hash.update([0]);
        if file.ends_with("Cargo.lock") {
            hash.update(locked_versions(&fs::read_to_string(&file)?).as_bytes());
        } else {
            hash.update(fs::read(&file)?);
        }
        hash.update([0]);
    }
    Ok(hash
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}
