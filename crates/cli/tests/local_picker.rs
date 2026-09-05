use std::process::Command;

#[test]
fn compiled_cli_selects_and_attaches_a_local_session() {
    let output = Command::new("python3")
        .args(["-c", include_str!("fixtures/local_picker.py")])
        .arg(env!("CARGO_BIN_EXE_attached"))
        .output()
        .expect("compiled CLI PTY regression requires Python 3");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
