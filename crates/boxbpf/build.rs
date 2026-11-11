//! Compiles the kernel programs in `bpf/` with clang and checks the C
//! layouts against `netpol::abi`.
//!
//! Needs `clang` with the BPF target and nothing else: every header the
//! programs include is in `bpf/`. `BOXBPF_CLANG` names another compiler.
//! On targets other than Linux there is nothing to build.

use std::{env, fs, io, path::PathBuf, process::Command};

fn fail(message: &str) -> ! {
    println!("cargo::error={message}");
    std::process::exit(1);
}

fn main() {
    println!("cargo::rerun-if-changed=bpf");
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
}
