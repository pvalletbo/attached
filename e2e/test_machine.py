"""Offline PTY/assertion checks; run inside the runtime image (needs pexpect)."""

import sys
import unittest
from unittest.mock import patch

from machine import Terminal, verify


class TerminalTests(unittest.TestCase):
    def test_real_terminal_creation_confirmation_and_exit_status(self):
        program = """
import getpass, sys
assert sys.stdin.isatty() and sys.stderr.isatty()
first = getpass.getpass('Create Attached encryption password: ')
second = getpass.getpass('Confirm Attached encryption password: ')
assert first == second == 'test-secret'
print('remote output')
sys.exit(37)
"""
        with Terminal([sys.executable, "-c", program], "test-secret", timeout=5) as terminal:
            terminal.unlock(create=True)
            self.assertEqual(terminal.finish(expected_status=37), "remote output")

    def test_unlock_and_wrong_exit_status_fail_with_diagnostics(self):
        program = """
import getpass
getpass.getpass('Attached encryption password: ')
print('SSH failure')
raise SystemExit(255)
"""
        with Terminal([sys.executable, "-c", program], "test-secret", timeout=5) as terminal:
            terminal.unlock()
            with self.assertRaisesRegex(RuntimeError, "255, expected 0.*SSH failure"):
                terminal.finish()

    def test_prompt_failure_redacts_password_and_closes_process(self):
        program = "print('test-secret'); raise SystemExit(1)"
        with Terminal([sys.executable, "-c", program], "test-secret", timeout=5) as terminal:
            with self.assertRaises(RuntimeError) as caught:
                terminal.unlock()
        self.assertNotIn("test-secret", str(caught.exception))
        self.assertIn("[redacted]", str(caught.exception))
        self.assertFalse(terminal.child.isalive())

    def test_timeout_kills_hung_cli(self):
        with Terminal([sys.executable, "-c", "import time; time.sleep(60)"],
                      "test-secret", timeout=0.1) as terminal:
            with self.assertRaisesRegex(RuntimeError, "timed out"):
                terminal.unlock()
        self.assertFalse(terminal.child.isalive())


class SshAssertions(unittest.TestCase):
    @patch("machine.command")
    def test_remote_output_and_nonzero_status_are_both_verified(self, command):
        command.side_effect = ["e2e-publisher\nattached\nunique-proof", ""]
        verify("unique-proof")
        self.assertIn("--no-cache", command.call_args_list[0].args[0])
        self.assertEqual(command.call_args_list[1].kwargs, {"expected_status": 37})

    @patch("machine.command")
    def test_wrong_machine_missing_output_or_stale_proof_fails(self, command):
        for output in ("e2e-client\nattached\nunique-proof", "", "e2e-publisher\nattached\nstale"):
            command.return_value = output
            with self.assertRaisesRegex(RuntimeError, "unexpected remote output"):
                verify("unique-proof")


if __name__ == "__main__":
    unittest.main()
