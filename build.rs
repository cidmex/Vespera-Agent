use std::process::Command;

fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    println!("cargo:rustc-env=VESPERA_AGENT_VERSION={version}");

    let sha = std::env::var("VESPERA_GIT_SHA").ok().filter(|s| !s.is_empty()).or_else(|| {
        Command::new("git")
            .args(["rev-parse", "--short=7", "HEAD"])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    });
    println!("cargo:rustc-env=VESPERA_GIT_SHA={}", sha.unwrap_or_else(|| "unknown".into()));
    println!("cargo:rerun-if-env-changed=VESPERA_GIT_SHA");
    println!("cargo:rerun-if-changed=.git/HEAD");
}
