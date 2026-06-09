//! Build script for HIVE binary.
//!
//! Embeds compile-time metadata:
//! - GIT_HASH: short git commit hash (or "unknown" if not in a repo)
//! - BUILD_DATE: YYYY-MM-DD build date

fn main() {
    // Git short hash
    let output = std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();
    let hash = match output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    };
    println!("cargo:rustc-env=GIT_HASH={}", hash);

    // Build date (YYYY-MM-DD via `date` command, no chrono dependency)
    let date_output = std::process::Command::new("date")
        .args(["+%Y-%m-%d"])
        .output();
    let date = match date_output {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).trim().to_string(),
        _ => "unknown".to_string(),
    };
    println!("cargo:rustc-env=BUILD_DATE={}", date);

    // Rebuild when git HEAD changes (new commits)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=build.rs");
}
