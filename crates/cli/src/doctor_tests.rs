use super::*;
use crate::client_ipc::{ConnectionInfo, ConnectionPath};

fn host(label: &str, key: u8) -> SyncedHost {
    SyncedHost {
        target: iroh::SecretKey::from_bytes(&[key; 32]).public().to_string(),
        host: label.into(),
        attached_version: [0, 3, 8],
        published_at: Some(Utc::now()),
    }
}

#[test]
fn selection_rejects_ambiguous_labels_and_never_falls_back_from_identity_to_label() {
    let first = host("office", 1);
    let second = host("office", 2);
    assert!(select_hosts(vec![first.clone(), second.clone()], Some("office")).is_err());
    assert!(select_hosts(vec![first.clone()], Some("missing")).is_err());
    let selected = select_hosts(vec![first.clone(), second], Some(&first.target)).unwrap();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0].target, first.target);
    let impersonator = host(&first.target, 3);
    assert!(select_hosts(vec![impersonator], Some(&first.target)).is_err());
}

fn sample_host(online: bool) -> HostStatus {
    HostStatus {
        host: "office\x1b[31m\nforged".into(),
        endpoint_id: iroh::SecretKey::from_bytes(&[1; 32]).public().to_string(),
        attached_version: "0.3.8".into(),
        published_at: Some(Utc::now()),
        expires_at: Some(Utc::now()),
        online,
        connection: online.then_some(ConnectionInfo {
            path: ConnectionPath::Relay,
            rtt_ms: Some(17),
        }),
        failure: (!online).then_some(ssh::ProbeFailure::TimedOut),
        message: "fixture",
    }
}

#[test]
fn health_distinguishes_warnings_failures_and_live_probes() {
    let mut report = Report::new(Vec::new());
    report.check("ssh", Level::Warn, "not installed");
    report.hosts.push(sample_host(true));
    report.finish();
    assert!(report.healthy);
    report.hosts[0] = sample_host(false);
    report.finish();
    assert!(!report.healthy, "advertised does not imply online");
    report.hosts[0] = sample_host(true);
    report.check("discovery", Level::Fail, "offline");
    report.finish();
    assert!(
        !report.healthy,
        "cached online hosts cannot hide failed discovery"
    );
}

#[test]
fn json_is_one_object_per_line_and_text_escapes_terminal_control_characters() {
    let mut report = Report::new(Vec::new());
    report.hosts.push(sample_host(true));
    report.finish();
    let mut output = Vec::new();
    render(&report, true, &mut output).unwrap();
    assert_eq!(output.iter().filter(|&&byte| byte == b'\n').count(), 1);
    let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["hosts"][0]["online"], true);
    assert_eq!(value["hosts"][0]["connection"]["path"], "relay");
    assert_eq!(value["hosts"][0]["connection"]["rtt_ms"], 17);
    assert!(value["hosts"][0].get("endpoint_ticket").is_none());
    assert!(value["hosts"][0].get("attach_capability").is_none());
    output.clear();
    render(&report, false, &mut output).unwrap();
    assert!(!output.contains(&0x1b));
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("not a liveness check"));
    assert!(output.contains("ONLINE"));
}
