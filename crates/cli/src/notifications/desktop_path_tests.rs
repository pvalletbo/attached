use super::*;

fn executable(path: &Path, script: &str) {
    std::fs::write(path, script).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn run_shell(shell: &str, search_path: &Path) -> std::process::Output {
    std::process::Command::new("/bin/bash")
        .args(["--noprofile", "--norc", "-c", shell])
        .env("PATH", search_path)
        .output()
        .unwrap()
}

#[test]
fn macos_callback_and_terminal_restore_tool_lookup_after_environment_loss() {
    let root = crate::test_support::canonical_tempdir();
    // Apostrophes, spaces, and shell syntax must remain literal in PATH too.
    let tools = root.path().join("tools ' $(false)");
    let empty_path = root.path().join("empty");
    std::fs::create_dir(&tools).unwrap();
    std::fs::create_dir(&empty_path).unwrap();
    executable(&tools.join("op"), "#!/bin/sh\nprintf 'op-found\\n'\n");
    executable(&tools.join("herdr"), "#!/bin/sh\nprintf 'herdr-found\\n'\n");
    let attached = root.path().join("attached ' executable");
    executable(
        &attached,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$PATH\" \"$@\"\nop\nherdr\n",
    );

    // Reproduce the original missing-executable failure without using real
    // credentials, changing the test runner's PATH, or opening a GUI terminal.
    let missing = std::process::Command::new(&attached)
        .env("PATH", &empty_path)
        .output()
        .unwrap();
    assert_eq!(missing.status.code(), Some(127));

    let target = "host/work';$(false)";
    let tool_path = tools.to_str().unwrap();
    for terminal in ["ghostty", "terminal"] {
        let launch = Launch {
            attached: attached.clone(),
            terminal: Some(terminal.into()),
            search_path: Some(tools.clone().into_os_string()),
            pane: None,
        };
        let notice = Notice {
            title: "finished".into(),
            body: "ready".into(),
            pane: None,
        };
        let notification =
            mac_notification_command(Path::new("terminal-notifier"), &launch, target, &notice)
                .unwrap();
        let callback = notification
            .as_std()
            .get_args()
            .last()
            .unwrap()
            .to_str()
            .unwrap();
        let output = run_shell(callback, &empty_path);
        assert!(output.status.success(), "callback: {:?}", output.stderr);
        assert_eq!(
            output.stdout,
            format!("{tool_path}\nnotifications\nopen\n-v\n--terminal\n{terminal}\n--\n{target}\nop-found\nherdr-found\n").as_bytes()
        );

        // The actual callback captures its restored PATH before starting the
        // terminal. Simulate that handoff, then lose the ambient PATH again as
        // can happen when Launch Services opens Ghostty.
        let callback_output = String::from_utf8(output.stdout).unwrap();
        let restored_path = callback_output.lines().next().unwrap();
        let callback_launch = Launch {
            search_path: Some(restored_path.into()),
            ..launch
        };
        let command = callback_launch.terminal_command(target, true).unwrap();
        let initial = command
            .as_std()
            .get_args()
            .last()
            .unwrap()
            .to_str()
            .unwrap();
        let shell = match initial.strip_prefix("--initial-command=shell:") {
            Some(initial) => format!("exec -l {initial}"),
            None => initial.to_owned(), // Terminal.app already has an exec.
        };
        let output = run_shell(&shell, &empty_path);
        assert!(output.status.success(), "{terminal}: {:?}", output.stderr);
        assert_eq!(
            output.stdout,
            format!("{tool_path}\nattach\n-v\n--\n{target}\nop-found\nherdr-found\n").as_bytes()
        );
    }
}

#[test]
fn path_wrapper_preserves_unset_and_empty_paths_without_copying_other_variables() {
    let mut launch = Launch {
        attached: "/tmp/attached".into(),
        terminal: Some("ghostty".into()),
        search_path: None,
        pane: None,
    };
    let args = launch.attach_args("host/work");
    assert_eq!(
        launch.command_with_search_path(args.clone()),
        (launch.attached.clone(), args.clone())
    );
    launch.search_path = Some(OsString::new());
    let (program, wrapped) = launch.command_with_search_path(args);
    assert_eq!(program, Path::new("/usr/bin/env"));
    assert_eq!(
        wrapped,
        ["PATH=", "/tmp/attached", "attach", "-v", "--", "host/work"]
    );
}
