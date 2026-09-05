use std::process::Command;

fn run_scenario(scenario: &str) {
    let output = Command::new("python3")
        .args(["-c", include_str!("fixtures/local_picker.py")])
        .arg(env!("CARGO_BIN_EXE_attached"))
        .arg(scenario)
        .output()
        .expect("compiled CLI PTY regression requires Python 3");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn compiled_cli_selects_and_attaches_a_local_session() {
    run_scenario("select");
}

#[test]
fn compiled_cli_propagates_local_herdr_exit_status() {
    run_scenario("client-exit");
}

#[test]
fn compiled_cli_treats_picker_cancellation_as_success_without_launching_herdr() {
    run_scenario("cancel");
}

#[test]
fn compiled_cli_treats_picker_no_match_as_success_without_launching_herdr() {
    run_scenario("no-match");
}

#[test]
fn compiled_cli_reports_picker_failure_without_launching_herdr() {
    run_scenario("picker-error");
}
