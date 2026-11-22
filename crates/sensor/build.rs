//! Compiles bpf/sensor.bpf.c with clang into $OUT_DIR/sensor.bpf.o (Linux targets only).
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=bpf/sensor.bpf.c");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("linux") {
        return;
    }
    let out = PathBuf::from(env::var("OUT_DIR").unwrap()).join("sensor.bpf.o");
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let (bpf_arch, triple) = match arch.as_str() {
        "x86_64" => ("x86", "x86_64-linux-gnu"),
        "aarch64" => ("arm64", "aarch64-linux-gnu"),
        other => panic!("unsupported architecture for the eBPF sensor: {other}"),
    };
    let clang = env::var("CLANG").unwrap_or_else(|_| "clang".into());
    let status = Command::new(&clang)
        .args(["-O2", "-g", "-target", "bpf", "-Wall", "-Werror"])
        .arg(format!("-D__TARGET_ARCH_{bpf_arch}"))
        .arg(format!("-I/usr/include/{triple}"))
        .args(["-c", "bpf/sensor.bpf.c", "-o"])
        .arg(&out)
        .status()
        .unwrap_or_else(|e| panic!("running {clang} (install clang + libbpf-dev): {e}"));
    assert!(status.success(), "compiling bpf/sensor.bpf.c failed");
}
