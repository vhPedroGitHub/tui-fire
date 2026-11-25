use std::{env, path::PathBuf, process::Command};

fn main() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    if os == "windows" {
        return;
    }
    println!("cargo:rerun-if-changed=bpf/traffic.bpf.c");
    println!("cargo:rerun-if-env-changed=BPF_CLANG");
    println!("cargo:rustc-link-lib=bpf");

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let endian = env::var("CARGO_CFG_TARGET_ENDIAN").unwrap();
    assert!(
        os == "linux" && matches!(arch.as_str(), "x86_64" | "aarch64"),
        "tui-fire requiere Linux de 64 bits (x86_64 o aarch64)"
    );
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap()).join("traffic.bpf.o");
    let clang = env::var_os("BPF_CLANG").unwrap_or_else(|| "clang".into());
    let multiarch = format!("/usr/include/{arch}-linux-gnu");
    let status = Command::new(clang)
        .args([
            "-target",
            if endian == "little" { "bpfel" } else { "bpfeb" },
            "-O2",
            "-g",
            "-Wall",
            "-Werror",
            "-isystem",
            &multiarch,
            "-c",
            "bpf/traffic.bpf.c",
            "-o",
        ])
        .arg(out)
        .status()
        .expect("se necesita Clang con soporte para eBPF");
    assert!(status.success(), "falló la compilación de eBPF");
}
