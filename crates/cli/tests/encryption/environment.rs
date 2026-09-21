//! Exercise environment passwords in real CLI processes, never mutating the test environment.
use super::*;
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

const PASSWORD_ENV: &str = "ATTACHED_ENCRYPTION_PASSWORD";
const STATE: &str = "home/.config/attached";
const EXPORT: &[&str] = &[
    "-vv",
    "account",
    "export",
    "--type",
    "download",
    "--output",
    "export.bundle",
];

fn forbid_one_password(fixture: &CliFixture) {
    fixture.script("op", "touch \"$FIXTURE_ROOT/op-called\"; exit 90");
}

fn assert_no_secret(output: &support::CliOutput, password: &str, bundle: &str) {
    for text in [&output.stdout, &output.stderr] {
        assert!(!text.contains(password), "password leaked to output");
        assert!(!text.contains(bundle), "bundle leaked to output");
        assert!(!text.contains("Confirm Attached encryption password"));
    }
}

#[tokio::test]
async fn environment_password_roundtrips_verbatim_without_a_terminal_or_one_password() {
    for password in ["  injected-sécret\n\t".to_owned(), "é".repeat(512)] {
        let fixture = CliFixture::new();
        forbid_one_password(&fixture);
        let encoded = bundle("http://127.0.0.1:1", IDENTITY);
        fs::write(fixture.path("input.bundle"), &encoded).unwrap();
        let mut command = fixture.command(&[
            "-vv",
            "--flamegraph",
            "import.folded",
            "account",
            "import",
            "--bundle-stdin",
        ]);
        command
            .env(PASSWORD_ENV, &password)
            .stdin(fs::File::open(fixture.path("input.bundle")).unwrap());
        let output = fixture.spawn(command).wait().await;
        output.assert_code(0);
        assert_no_secret(&output, &password, &encoded);

        let account_path = fixture.path(&format!("{STATE}/sync-account.bundle"));
        let salt_path = fixture.path(&format!("{STATE}/encryption-salt.argon2id-v1"));
        let stored = fs::read(&account_path).unwrap();
        let salt = fs::read(&salt_path).unwrap();
        assert!(stored.starts_with(b"ATSECR01"));
        assert_private(&account_path);
        assert_private(&salt_path);
        for bytes in [
            &stored,
            &salt,
            &fs::read(fixture.path("import.folded")).unwrap(),
        ] {
            for secret in [&password, &encoded] {
                assert!(
                    !bytes
                        .windows(secret.len())
                        .any(|window| window == secret.as_bytes())
                );
            }
        }

        // A separate process has no cached key and must derive the same one.
        let mut command = fixture.command(EXPORT);
        command.env(PASSWORD_ENV, &password);
        let output = fixture.spawn(command).wait().await;
        output.assert_code(0);
        assert_no_secret(&output, &password, &encoded);
        assert_eq!(
            fs::read_to_string(fixture.path("export.bundle")).unwrap(),
            format!("{encoded}\n")
        );
        assert_private(&fixture.path("export.bundle"));
        fs::remove_file(fixture.path("export.bundle")).unwrap();

        // Trimming or changing the password must not silently unlock or replace state.
        let wrong_password = if password.trim() != password {
            password.trim().to_owned()
        } else {
            "different-secret".to_owned()
        };
        let mut command = fixture.command(EXPORT);
        command.env(PASSWORD_ENV, &wrong_password);
        let output = fixture.spawn(command).wait().await;
        output.assert_code(1);
        assert!(
            output.stderr.contains("authentication failed"),
            "{output:?}"
        );
        assert_no_secret(&output, &wrong_password, &encoded);
        assert!(!fixture.path("export.bundle").exists());
        assert_eq!(fs::read(account_path).unwrap(), stored);
        assert_eq!(fs::read(salt_path).unwrap(), salt);
        assert!(!fixture.path("op-called").exists());
    }
}

#[tokio::test]
async fn invalid_environment_passwords_fail_without_prompting_or_echoing_values() {
    let cases = [
        (OsString::from(""), "cannot be empty"),
        (OsString::from("s".repeat(1025)), "exceeds 1024 bytes"),
        (OsString::from("é".repeat(513)), "exceeds 1024 bytes"),
        (
            OsString::from_vec(b"private-invalid-secret-\xff".to_vec()),
            "must contain valid UTF-8",
        ),
    ];
    for (password, expected) in cases {
        let fixture = CliFixture::new();
        forbid_one_password(&fixture);
        let encoded = bundle("http://127.0.0.1:1", IDENTITY);
        fs::write(fixture.path("input.bundle"), &encoded).unwrap();
        let mut command =
            fixture.command(&["-vv", "account", "import", "--bundle-file", "input.bundle"]);
        command.env(PASSWORD_ENV, &password);
        let output = fixture.spawn(command).wait().await;
        output.assert_code(1);
        assert!(output.stderr.contains(PASSWORD_ENV), "{output:?}");
        assert!(output.stderr.contains(expected), "{output:?}");
        assert!(
            !output.stderr.contains("controlling terminal"),
            "{output:?}"
        );
        assert!(
            !output
                .stderr
                .contains("Create Attached encryption password")
        );
        assert!(!output.stderr.contains("private-invalid-secret"));
        assert!(!output.stderr.contains(&encoded));
        assert!(output.stdout.is_empty());
        if !password.is_empty() {
            assert!(!output.stderr.contains(password.to_string_lossy().as_ref()));
        }
        assert!(
            !fixture
                .path(&format!("{STATE}/sync-account.bundle"))
                .exists()
        );
        assert!(!fixture.path("op-called").exists());
    }
}

#[tokio::test]
async fn one_password_flag_and_configuration_take_precedence_over_environment_password() {
    for configuration in [false, true] {
        let fixture = CliFixture::new();
        let encoded = import(&fixture, "http://127.0.0.1:1").await;
        if configuration {
            fs::write(
                fixture.path(&format!("{STATE}/config.toml")),
                "password_source = \"1password\"\n",
            )
            .unwrap();
        }
        // Even an invalid environment value is irrelevant when 1Password is selected.
        for password in ["different-injected-secret", ""] {
            let mut command = fixture.command(EXPORT);
            if !configuration {
                command.arg("--use-1password");
            }
            command.env(PASSWORD_ENV, password);
            let output = fixture.spawn(command).wait().await;
            output.assert_code(0);
            assert!(!output.stderr.contains("different-injected-secret"));
            assert_eq!(
                fs::read_to_string(fixture.path("export.bundle")).unwrap(),
                format!("{encoded}\n")
            );
            fs::remove_file(fixture.path("export.bundle")).unwrap();
        }
    }
}

#[tokio::test]
async fn absent_environment_password_keeps_noninteractive_credentials_locked() {
    let fixture = CliFixture::new();
    import(&fixture, "http://127.0.0.1:1").await;
    forbid_one_password(&fixture);
    for args in [
        &["-vv", "ssh", "remote", "true"][..],
        &["-vv", "export-ssh-config"][..],
    ] {
        let output = fixture.run(args).await;
        output.assert_code(1);
        assert!(
            output.stderr.contains("Attached credentials are locked"),
            "{output:?}"
        );
        assert!(output.stderr.contains(PASSWORD_ENV), "{output:?}");
        assert!(
            output.stderr.contains("attached export-ssh-config"),
            "{output:?}"
        );
        assert!(!output.stderr.contains("--expose-config"), "{output:?}");
        assert!(output.stdout.is_empty());
    }
    assert!(!fixture.path("home/.ssh").exists());
    assert!(!fixture.path("op-called").exists());
}

#[tokio::test]
async fn environment_password_unlocks_noninteractive_ssh_export() {
    let fixture = CliFixture::new();
    let encoded = import(&fixture, "http://127.0.0.1:1").await;
    forbid_one_password(&fixture);
    // Fail configuration setup after unlocking, before any Iroh endpoint is bound.
    let blocker = fixture.path("home/.ssh");
    fs::write(&blocker, "not a directory").unwrap();
    let password = "fixture-only-encryption-password";
    let mut command = fixture.command(&["-vv", "export-ssh-config"]);
    command.env(PASSWORD_ENV, password);
    let output = fixture.spawn(command).wait().await;
    output.assert_code(1);
    assert!(
        output.stderr.contains("~/.ssh is not a directory"),
        "{output:?}"
    );
    assert!(!output.stderr.contains("Attached credentials are locked"));
    assert_no_secret(&output, password, &encoded);
    assert!(output.stdout.is_empty());
    assert_eq!(fs::read_to_string(blocker).unwrap(), "not a directory");
    assert!(!fixture.path("op-called").exists());
}

#[tokio::test]
async fn environment_password_can_unlock_state_previously_encrypted_using_one_password() {
    let fixture = CliFixture::new();
    let encoded = import(&fixture, "http://127.0.0.1:1").await;
    forbid_one_password(&fixture);
    let mut command = fixture.command(EXPORT);
    command.env(PASSWORD_ENV, "fixture-only-encryption-password");
    fixture.spawn(command).wait().await.assert_code(0);
    assert_eq!(
        fs::read_to_string(fixture.path("export.bundle")).unwrap(),
        format!("{encoded}\n")
    );
    assert!(!fixture.path("op-called").exists());
}

#[tokio::test]
async fn publisher_bootstraps_and_reopens_encrypted_state_from_environment_secrets() {
    use attached_session_sync_protocol::account::ApiKeyScope;
    let fixture = CliFixture::new();
    forbid_one_password(&fixture);
    // A renamed executable fails startup validation after credential/identity setup,
    // before binding Iroh or publishing to a service. No Herdr dependency is needed.
    let executable = fixture.path("bin/attached-publisher-test");
    fs::copy(env!("CARGO_BIN_EXE_attached"), &executable).unwrap();
    let encoded = AccountBundle::Scoped(
        ScopedAccountBundle::from_parts(
            ServiceOrigin::parse("http://127.0.0.1:1").unwrap(),
            AccountId::parse(ACCOUNT).unwrap(),
            ApiKeyScope::Publish,
            ApiToken::from_bytes(TOKEN),
            AccountRootKey::from_bytes(ROOT_KEY),
            Some(ConsumerIdentitySecret::from_bytes(IDENTITY).authorized_identity()),
        )
        .unwrap(),
    )
    .encode();
    let password = "ephemeral-publisher-encryption-secret";
    let state_paths = [
        "sync-account.bundle",
        "admin-identity.key",
        "encryption-salt.argon2id-v1",
    ]
    .map(|name| fixture.path(&format!("{STATE}/{name}")));
    let mut initial_state = None;
    for first_run in [true, false] {
        let mut command = fixture.command_at(&executable, &["-vv", "serve"]);
        command.env(PASSWORD_ENV, password);
        if first_run {
            command.env("ATTACHED_PUBLISH_BUNDLE", &encoded);
        }
        let output = fixture.spawn(command).wait().await;
        output.assert_code(1);
        assert!(
            output
                .stderr
                .contains("cannot safely manage an Attached executable renamed to"),
            "{output:?}"
        );
        assert_no_secret(&output, password, &encoded);
        assert!(!output.stderr.contains("Enter the publish bundle"));
        let stored = state_paths.each_ref().map(|path| {
            assert_private(path);
            fs::read(path).unwrap()
        });
        assert!(stored[0].starts_with(b"ATSECR01"));
        assert!(stored[1].starts_with(b"ATSECR01"));
        if let Some(initial) = initial_state.as_ref() {
            assert_eq!(&stored, initial, "restart must preserve encrypted state");
        } else {
            initial_state = Some(stored);
        }
    }
    let mut command = fixture.command(&[
        "-vv",
        "account",
        "export",
        "--type",
        "publish",
        "--output",
        "export.bundle",
    ]);
    command.env(PASSWORD_ENV, password);
    let output = fixture.spawn(command).wait().await;
    output.assert_code(0);
    assert_no_secret(&output, password, &encoded);
    assert_eq!(
        fs::read_to_string(fixture.path("export.bundle")).unwrap(),
        format!("{encoded}\n")
    );
    let account_path = fixture.path(&format!("{STATE}/sync-account.bundle"));
    assert!(fs::read(&account_path).unwrap().starts_with(b"ATSECR01"));
    assert_private(&account_path);
    assert!(!fixture.path("op-called").exists());
}
