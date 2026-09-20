//! Guards for our cargo-dist-generated workflow contract. No YAML interpreter
//! or additional test-language dependencies are needed; GitHub validates YAML,
//! and `dist generate --mode ci --check` validates the generated file itself.
const RELEASE: &str = include_str!("../../../.github/workflows/release.yml");
const GATE: &str = include_str!("../../../.github/workflows/release-e2e.yml");
const E2E: &str = include_str!("../../../.github/workflows/e2e.yml");

fn job(workflow: &str, name: &str) -> String {
    let marker = format!("\n  {name}:\n");
    workflow
        .split_once(&marker)
        .expect("expected workflow job")
        .1
        .lines()
        .take_while(|line| {
            !line.starts_with("  ")
                || line.starts_with("    ")
                || line.trim_start().starts_with('#')
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn candidate_gate_is_direct_dependency_of_hosting_not_a_skippable_downstream_build() {
    let gate = job(RELEASE, "custom-release-e2e");
    assert!(gate.contains("- build-local-artifacts"));
    assert!(gate.contains("uses: ./.github/workflows/release-e2e.yml"));
    let host = job(RELEASE, "host");
    assert!(host.contains("- custom-release-e2e"));
    assert!(host.contains("&& (needs.custom-release-e2e.result == 'skipped' || needs.custom-release-e2e.result == 'success')"));
    assert!(
        include_str!("../../../dist-workspace.toml")
            .contains("global-artifacts-jobs = [\"./release-e2e\"]")
    );
}

#[test]
fn gate_tests_this_release_candidate_only_on_real_releases_never_production() {
    let gate = job(GATE, "local-backend");
    let normalized = gate.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(normalized.contains("github.event_name == 'workflow_dispatch' && github.event.inputs.tag != '' && github.event.inputs.tag != 'dry-run'"));
    assert!(gate.contains("name: artifacts-build-local-x86_64-unknown-linux-gnu"));
    assert!(!gate.contains("run-id:"));
    assert!(gate.contains("ref: ${{ github.sha }}"));
    assert!(gate.contains("persist-credentials: false"));
    let run = gate
        .lines()
        .find(|line| line.trim_start().starts_with("run:"))
        .unwrap();
    assert!(run.contains("cargo run --locked --package attached-e2e -- --archive candidate/attached-x86_64-unknown-linux-gnu.tar.xz"));
    assert!(!run.contains("--release"));
    assert!(!run.contains("--service"));
    assert!(GATE.contains("permissions:\n  contents: read"));
}

#[test]
fn manual_runs_default_local_and_prs_only_run_rust_harness_tests() {
    let service = E2E
        .split_once("      service:")
        .unwrap()
        .1
        .split_once("\npermissions:")
        .unwrap()
        .0;
    assert!(service.contains("default: ''"));
    let live = job(E2E, "live");
    assert!(live.contains("if: github.event_name == 'workflow_dispatch'"));
    assert!(live.contains("if [[ -n \"$E2E_SERVICE\" ]]; then"));
    assert!(live.contains("cargo run --locked --package attached-e2e"));
    let harness = job(E2E, "harness");
    assert!(harness.contains("cargo test --locked --package attached-e2e"));
    assert!(!harness.contains("cargo run"));
    assert!(!E2E.contains("python3"));
    assert!(!GATE.contains("python3"));
}
