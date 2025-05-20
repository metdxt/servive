use std::collections::HashSet; // For the allow-list
use std::env;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("[build.rs] INFO: Starting build script execution.");

    eprintln!("[build.rs] INFO: Attempting to get git hash.");
    let git_hash_output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output();

    let git_hash = match git_hash_output {
        Ok(output) => {
            if output.status.success() {
                String::from_utf8(output.stdout)?
                    .trim()
                    .to_string()
            } else {
                let stderr = String::from_utf8_lossy(&output.stderr);
                eprintln!(
                    "[build.rs] WARNING: Git command failed with status {}. Stderr: '{}'. Defaulting git_hash.",
                    output.status, stderr.trim()
                );
                "unknown_git_hash".to_string()
            }
        }
        Err(e) => {
            eprintln!("[build.rs] WARNING: Failed to execute git command: {}. Defaulting git_hash.", e);
            "unknown_git_hash".to_string()
        }
    };
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs/heads/");
    eprintln!("[build.rs] INFO: GIT_HASH set to: {}", git_hash);

    let displayable_main_features: HashSet<String> = [
        "tls".to_string(),
        "default".to_string(),
    ]
    .into_iter()
    .collect();

    // 3. Collect and filter enabled features
    eprintln!("[build.rs] INFO: Collecting and filtering enabled Cargo features.");
    let mut features_to_display = Vec::new();
    for (key, _value) in env::vars() {
        if key.starts_with("CARGO_FEATURE_") {
            let feature_name = key
                .trim_start_matches("CARGO_FEATURE_")
                .to_lowercase()
                .replace('_', "-");

            // Only include it if it's in our list of displayable main features
            if displayable_main_features.contains(&feature_name) {
                features_to_display.push(feature_name);
            }
        }
    }
    features_to_display.sort();

    let features_string = if features_to_display.is_empty() {
        "none".to_string()
    } else {
        features_to_display.join(", ")
    };
    eprintln!("[build.rs] INFO: Filtered features for display: [{}]", features_string);

    println!("cargo:rustc-env=COMPILED_FEATURES={}", features_string);
    eprintln!("[build.rs] INFO: COMPILED_FEATURES env var set for crate compilation.");

    println!("cargo:rerun-if-changed=build.rs");
    eprintln!("[build.rs] INFO: Build script finished successfully.");
    Ok(())
}