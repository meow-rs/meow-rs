use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
};

fn sdk_include_path_for(sdk: &str) -> String {
    // sdk path find by `xcrun --sdk {iphoneos|macosx} --show-sdk-path`
    let output = Command::new("xcrun")
        .arg("--sdk")
        .arg(sdk)
        .arg("--show-sdk-path")
        .output()
        .expect("failed to execute xcrun");

    let inc_path = Path::new(String::from_utf8_lossy(&output.stdout).trim()).join("usr/include");

    inc_path.to_str().expect("invalid include path").to_string()
}

/// Whether the target runs in a simulator rather than on device.
///
/// Rust spells these triples `*-sim` (`aarch64-apple-ios-sim`,
/// `aarch64-apple-tvos-sim`). The older `x86_64-apple-{ios,tvos}` triples are
/// simulator-only too -- no Intel iPhone or Apple TV hardware exists.
fn is_apple_simulator() -> bool {
    env::var("TARGET").unwrap_or_default().ends_with("-sim")
        || env::var("CARGO_CFG_TARGET_ARCH").unwrap() == "x86_64"
}

/// SDK name to hand to `xcrun --sdk`, or `None` off Apple platforms.
fn apple_sdk_name() -> Option<&'static str> {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    match (os.as_str(), is_apple_simulator()) {
        ("ios", false) => Some("iphoneos"),
        ("ios", true) => Some("iphonesimulator"),
        ("tvos", false) => Some("appletvos"),
        ("tvos", true) => Some("appletvsimulator"),
        ("macos", _) => Some("macosx"),
        _ => None,
    }
}

fn sdk_include_path() -> Option<String> {
    apple_sdk_name().map(sdk_include_path_for)
}

fn compile_lwip() {
    println!("cargo:rerun-if-changed=old-src/core");
    let mut build = cc::Build::new();
    build
        .file("old-src/core/init.c")
        .file("old-src/core/def.c")
        // .file("old-src/core/dns.c")
        .file("old-src/core/inet_chksum.c")
        .file("old-src/core/ip.c")
        .file("old-src/core/mem.c")
        .file("old-src/core/memp.c")
        .file("old-src/core/netif.c")
        .file("old-src/core/pbuf.c")
        .file("old-src/core/raw.c")
        // .file("old-src/core/stats.c")
        // .file("old-src/core/sys.c")
        .file("old-src/core/tcp.c")
        .file("old-src/core/tcp_in.c")
        .file("old-src/core/tcp_out.c")
        .file("old-src/core/timeouts.c")
        .file("old-src/core/udp.c")
        // .file("old-src/core/ipv4/autoip.c")
        // .file("old-src/core/ipv4/dhcp.c")
        // .file("old-src/core/ipv4/etharp.c")
        .file("old-src/core/ipv4/icmp.c")
        // .file("old-src/core/ipv4/igmp.c")
        .file("old-src/core/ipv4/ip4_frag.c")
        .file("old-src/core/ipv4/ip4.c")
        .file("old-src/core/ipv4/ip4_addr.c")
        // .file("old-src/core/ipv6/dhcp6.c")
        // .file("old-src/core/ipv6/ethip6.c")
        .file("old-src/core/ipv6/icmp6.c")
        // .file("old-src/core/ipv6/inet6.c")
        .file("old-src/core/ipv6/ip6.c")
        .file("old-src/core/ipv6/ip6_addr.c")
        .file("old-src/core/ipv6/ip6_frag.c")
        // .file("old-src/core/ipv6/mld6.c")
        .file("old-src/core/ipv6/nd6.c")
        .file("old-src/custom/sys_arch.c")
        .file("src/api/err.c")
        .include("old-src/custom")
        .include("old-src/include")
        .warnings(false)
        .flag_if_supported("-Wno-everything");
    if let Some(sdk_include_path) = sdk_include_path() {
        build.include(sdk_include_path);
    }
    if env::var_os("CARGO_FEATURE_LIBC_MALLOC").is_some() {
        build.define("MEOW_LWIP_LIBC_MALLOC", "1");
    }
    build.debug(true);
    build.compile("liblwip.a");

    // `sys_win_rand` (old-src/custom/sys_arch.c) calls BCryptGenRandom, which
    // lives in bcrypt.lib. Without this the MSVC link fails with
    // `LNK2019: unresolved external symbol BCryptGenRandom`.
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        println!("cargo:rustc-link-lib=bcrypt");
    }
}

fn generate_lwip_bindings() {
    println!("cargo:rustc-link-lib=lwip");
    // println!("cargo:rerun-if-changed=old-src/custom/wrapper.h");
    println!("cargo:include=old-src/include");

    let sdk_include_path = sdk_include_path();

    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap();
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    let mut builder = bindgen::Builder::default()
        .header("old-src/custom/wrapper.h")
        .clang_arg("-I./old-src/include")
        .clang_arg("-I./old-src/custom")
        .clang_arg("-Wno-everything")
        .layout_tests(false)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()));
    if arch == "aarch64" && matches!(os.as_str(), "ios" | "tvos") {
        // https://github.com/rust-lang/rust-bindgen/issues/1211
        // Clang spells the simulator environment `-simulator`; passing Rust's
        // own `-sim` suffix through is rejected.
        let env_suffix = if is_apple_simulator() {
            "-simulator"
        } else {
            ""
        };
        builder = builder.clang_arg(format!("--target=arm64-apple-{os}{env_suffix}"));
    }
    if let Some(sdk_include_path) = sdk_include_path {
        builder = builder.clang_arg(format!("-I{}", sdk_include_path));
    }

    if os == "windows" {
        builder = builder.size_t_is_usize(false);
    }

    let bindings = builder.generate().expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}

fn main() {
    let os = env::var("CARGO_CFG_TARGET_OS").unwrap();
    println!("cargo:warning=host os {}", os);
    compile_lwip();
    generate_lwip_bindings();
    println!("cargo:rerun-if-changed=build.rs");
}
