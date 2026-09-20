//! The opt-in harness must fail closed before any live provider is launched.
#![cfg(unix)]

use std::process::Command;

#[test]
fn claude_qualification_harness_safety_contracts() {
    let status = Command::new("python3")
        .args(["-m", "unittest", "scripts.test_integrated_claude"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .status()
        .expect("python3 is required for the qualification harness");
    assert!(status.success());
}
