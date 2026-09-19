//! The smoke harness's safety checks run without credentials or provider calls.
#![cfg(unix)]
use std::process::Command;

#[test]
fn codex_qualification_harness_has_offline_safety_contracts() {
    let output = Command::new("python3")
        .args([
            "-m",
            "unittest",
            "scripts.test_integrated_codex",
            "scripts.test_ci_codex_sandbox",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("python3 is required for integrated provider fixtures");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("Ran "));
}

#[test]
fn codex_smoke_help_is_offline_and_documents_explicit_targets() {
    let output = Command::new("python3")
        .args(["scripts/test_integrated_codex.py", "--help"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout);
    for option in [
        "--session",
        "--scratch",
        "--provider-path",
        "--herdr-bin",
        "--provider-fixtures-only",
    ] {
        assert!(help.contains(option), "missing {option}");
    }
}

#[test]
fn codex_ci_covers_both_bootstrap_platforms_without_live_authentication() {
    let workflow = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/.github/workflows/integrated-agents.yml"
    ))
    .expect("a dedicated integrated-agent fixture workflow is required");
    for required in [
        "ubuntu-24.04",
        "macos-latest",
        "1.98.1",
        "--provider-fixtures-only",
        "just ci",
        "just docs-contract-test",
    ] {
        assert!(
            workflow.contains(required),
            "missing CI coverage: {required}"
        );
    }
    assert!(
        !workflow.contains("secrets."),
        "provider fixture CI must not require authentication secrets"
    );
}
