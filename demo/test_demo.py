#!/usr/bin/env python3
"""Offline checks: python3 -m unittest discover -s demo -p 'test_*.py'
Live recording assertions (also run by record.py): python3 demo/test_demo.py --recording
"""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from record import ROOT, isolated_env, prepare, stop_demo, verify_remote


class IsolationTests(unittest.TestCase):
    def test_does_not_inherit_live_herdr_or_attached_state(self):
        original = {
            "HOME": "/real/home", "PATH": "/usr/bin", "HERDR_ENV": "1",
            "HERDR_SOCKET_PATH": "/real/server.sock", "HERDR_SESSION": "work",
            "HERDR_CONFIG_PATH": "/real/herdr.toml", "ATTACHED_PUBLISH_BUNDLE": "secret",
            "XDG_CONFIG_HOME": "/real/config", "XDG_RUNTIME_DIR": "/real/runtime",
            "TMUX": "live", "SSH_AUTH_SOCK": "/real/agent", "BASH_ENV": "/real/init",
            "DOCKER_CONTEXT": "colima",
        }
        env = isolated_env(Path("/demo/home"), Path("/demo/bin"), "unix:///docker.sock", original)
        self.assertFalse(any(k.startswith(("HERDR_", "ATTACHED_", "SSH_", "TMUX")) for k in env))
        self.assertEqual(env["HOME"], "/demo/home")
        self.assertEqual(env["XDG_CONFIG_HOME"], "/demo/home/.config")
        self.assertEqual(env["DOCKER_CONFIG"], "/real/home/.docker")
        self.assertEqual(env["DOCKER_HOST"], "unix:///docker.sock")
        self.assertNotIn("DOCKER_CONTEXT", env)
        self.assertNotIn("BASH_ENV", env)
        self.assertEqual(original["HOME"], "/real/home")

    def test_ssh_wrapper_uses_only_demo_config_and_preserves_arguments(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake_ssh = base / "real ssh"
            fake_ssh.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\n')
            fake_ssh.chmod(0o700)
            home, tools = base / "home", base / "bin"
            prepare(home, tools, str(fake_ssh))
            result = subprocess.check_output(
                [str(tools / "ssh"), "attached-office", "printf 'with spaces'"],
                env=dict(os.environ, HOME=str(home)), text=True,
            ).splitlines()
            self.assertEqual(result, ["-F", str(home / ".ssh/config"),
                                      "attached-office", "printf 'with spaces'"])
            self.assertEqual(home.stat().st_mode & 0o777, 0o700)
            self.assertEqual((home / ".ssh/config").stat().st_mode & 0o777, 0o600)
            self.assertFalse((home / ".config/attached").exists())


class LifecycleTests(unittest.TestCase):
    @patch("record.subprocess.run")
    def test_cleanup_continues_after_herdr_timeout(self, command):
        command.side_effect = [subprocess.TimeoutExpired("herdr", 20), None, None]
        env = {"HOME": "/demo"}
        stop_demo(["tmux", "-S", "/demo/socket"], env, True)
        self.assertEqual(command.call_count, 3)
        self.assertEqual(command.call_args_list[0].kwargs["env"], env)
        self.assertEqual(command.call_args_list[1].args[0],
                         ["tmux", "-S", "/demo/socket", "kill-server"])
        self.assertEqual(command.call_args_list[2].args[0],
                         ["docker", "rm", "-f", "attached-demo-office"])

    @patch("record.subprocess.run")
    def test_cleanup_does_not_remove_container_it_did_not_create(self, command):
        stop_demo(["tmux", "-S", "/demo/socket"], {"HOME": "/demo"}, False)
        self.assertEqual(command.call_count, 2)

    @patch("record.run")
    def test_verification_rejects_wrong_machine(self, command):
        command.return_value.stdout = "my-real-mac\nherdr 0.9.1\nattached 0.3.4\n"
        with self.assertRaisesRegex(RuntimeError, "unexpected remote"):
            verify_remote({"HOME": "/demo"})


class TapeTests(unittest.TestCase):
    def setUp(self):
        self.tape = (ROOT / "demo/attached-demo.tape").read_text()

    def test_full_onboarding_order_and_no_direct_ssh(self):
        commands = [
            "attached account create",
            "attached account export --type publish --output publish.bundle",
            "docker cp publish.bundle",
            "https://install.attached.sh | sh",
            "attached serve --host-label office --bundle-file publish.bundle",
            "attached export-ssh-config",
            "herdr machine add attached-office --label Office",
            "Hello from office!",
        ]
        positions = [self.tape.index(command) for command in commands]
        self.assertEqual(positions, sorted(positions))
        self.assertNotIn('Type "attached ssh', self.tape)
        self.assertNotIn('Type "ssh ', self.tape)
        self.assertNotIn("pbcopy", self.tape)
        self.assertNotIn("pbpaste", self.tape)

    def test_success_is_observed_not_assumed_from_sleeps(self):
        for marker in ("Account created and saved", "Serving Attached SSH tunnels",
                       "Ready: ssh attached-office", "Remote server is ready",
                       "Office", "Hello from office!"):
            self.assertTrue(any(line.startswith("Wait+Screen") and marker in line
                                for line in self.tape.splitlines()), marker)
        self.assertEqual(self.tape.count('Type "1234"'), 6)


def check_recording():
    text = (ROOT / "demo/.artifacts/attached-demo.txt").read_text()
    for marker in ("Account created and saved", "Serving Attached SSH tunnels",
                   "Ready: ssh attached-office", "Remote server is ready",
                   "machines", "Office", "Hello from office!"):
        if marker not in text:
            raise AssertionError(f"recording did not show {marker!r}")
    for error in ("machine was not saved", "Permission denied", "command not found",
                  "could not decrypt", "Connection refused"):
        if error in text:
            raise AssertionError(f"recording contains an error: {error}")
    gif = ROOT / "demo/attached-demo.gif"
    metadata = json.loads(subprocess.check_output([
        "ffprobe", "-v", "error", "-show_entries", "format=duration:stream=width,height",
        "-of", "json", str(gif),
    ], text=True))
    duration = float(metadata["format"]["duration"])
    assert 30 < duration < 150, f"unexpected GIF duration: {duration}"
    assert metadata["streams"][0]["width"] == 1600
    assert metadata["streams"][0]["height"] == 960
    for name in ("01-account", "02-serving", "03-forwarding", "04-machine-added",
                 "05-machines", "06-remote-terminal"):
        assert (ROOT / f"demo/.artifacts/{name}.png").is_file(), name
    print(f"Recording passed: all onboarding milestones; {duration:.1f}s; {gif.stat().st_size:,} bytes")


if __name__ == "__main__":
    if sys.argv[1:] == ["--recording"]:
        check_recording()
    else:
        unittest.main()
