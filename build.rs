use std::env;
use std::process::Command;

fn main() {
    // Prefer CI-provided monotonically increasing build/run numbers
    let ci_vars = [
        "APP_BUILD",                // explicit override
        "GITHUB_RUN_NUMBER",        // GitHub Actions
        "CI_PIPELINE_IID",          // GitLab CI (per project incremental)
        "CI_JOB_ID",                // GitLab CI (fallback)
        "CIRCLE_BUILD_NUM",         // CircleCI
        "BITBUCKET_BUILD_NUMBER",   // Bitbucket Pipelines
        "BUILD_BUILDID",            // Azure Pipelines
        "TEAMCITY_BUILD_ID",        // TeamCity
        "DRONE_BUILD_NUMBER",       // Drone CI
        "JENKINS_BUILD_NUMBER",     // Jenkins (often BUILD_NUMBER)
        "BUILD_NUMBER",             // Generic/legacy
    ];

    for var in &ci_vars {
        println!("cargo:rerun-if-env-changed={}", var);
    }

    // Rerun when Git HEAD moves (for local dev fallback)
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads");

    // 1) Try CI environment variables first
    let mut build_number = None;
    for var in &ci_vars {
        if let Ok(val) = env::var(var) {
            if !val.trim().is_empty() {
                build_number = Some(val);
                break;
            }
        }
    }

    // 2) Fallback: count commits in current repository
    if build_number.is_none() {
        let output = Command::new("git")
            .args(["rev-list", "--count", "HEAD"])
            .output();
        if let Ok(out) = output {
            if out.status.success() {
                if let Ok(s) = String::from_utf8(out.stdout) {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        build_number = Some(s);
                    }
                }
            }
        }
    }

    // 3) Final fallback: 0
    let build_number = build_number.unwrap_or_else(|| "0".to_string());

    // Export to Rust code
    println!("cargo:rustc-env=APP_BUILD={}", build_number);
}
