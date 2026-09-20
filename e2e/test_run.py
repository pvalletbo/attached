"""Offline orchestration checks: python3 -m unittest discover -s e2e -p test_run.py"""

import hashlib
import io
import subprocess
import tarfile
import unittest
from unittest.mock import patch

from install_release import executable, release_asset
from run import DEFAULT_SERVICE, SmokeTest


def ok(stdout="", stderr="", code=0):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class LifecycleTests(unittest.TestCase):
    def test_production_default_and_unique_resources(self):
        first, second = SmokeTest(), SmokeTest()
        self.assertEqual(first.service, DEFAULT_SERVICE)
        self.assertNotEqual(first.prefix, second.prefix)

    @patch("run.docker", return_value=ok())
    def test_container_is_disposable_and_never_mounts_host_state_or_ports(self, docker):
        test = SmokeTest()
        client = test.create_machine("client")
        publisher = test.create_machine("publisher")
        creates = [call.args for call in docker.call_args_list if call.args[0] == "create"]
        self.assertNotEqual(client, publisher)
        self.assertNotEqual(test.networks[0], test.networks[1])
        for args in creates:
            for required in ("--read-only", "--cap-drop", "--tmpfs", "--init"):
                self.assertIn(required, args)
            for forbidden in ("--volume", "-v", "--mount", "--publish", "-p", "--privileged"):
                self.assertNotIn(forbidden, args)
            self.assertIn("/home/attached:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700", args)
            self.assertEqual(args[-3:], (test.image, "sleep", "600"))

    @patch("run.docker")
    def test_bundle_only_crosses_memory_and_stdin(self, docker):
        docker.side_effect = [ok(stdout=b"secret bundle"), ok(), ok()]
        SmokeTest().transfer_bundle("client", "publisher")
        calls = docker.call_args_list
        self.assertTrue(calls[0].kwargs["capture_output"])
        self.assertEqual(calls[1].kwargs["input"], b"secret bundle")
        self.assertIn("umask 077", calls[1].args[-1])
        self.assertTrue(all("secret bundle" not in str(call.args) for call in calls))
        self.assertEqual(calls[2].args, ("exec", "client", "rm", "/home/attached/publish.bundle"))

    def test_cleanup_runs_on_build_failure_ssh_failure_and_interrupt(self):
        for failure_stage in ("build", "exercise"):
            for failure in (RuntimeError("failed"), KeyboardInterrupt(), SystemExit(143)):
                with self.subTest(stage=failure_stage, failure=type(failure)):
                    test = SmokeTest()
                    with patch.object(test, "build") as build, \
                            patch.object(test, "exercise") as exercise, \
                            patch.object(test, "diagnostics") as diagnostics, \
                            patch.object(test, "cleanup") as cleanup:
                        {"build": build, "exercise": exercise}[failure_stage].side_effect = failure
                        with self.assertRaises(type(failure)):
                            test.run()
                        diagnostics.assert_called_once()
                        cleanup.assert_called_once()

    @patch("run.docker")
    def test_cleanup_attempts_every_resource_even_after_timeout(self, docker):
        test = SmokeTest()
        test.containers = ["client", "publisher"]
        test.networks = ["client-net", "publisher-net"]
        test.build_attempted = True
        docker.side_effect = [subprocess.TimeoutExpired("docker", 30), ok(), ok(), ok(), ok()]
        with self.assertRaisesRegex(RuntimeError, "could not clean up: publisher"):
            test.cleanup()
        self.assertEqual(docker.call_count, 5)
        self.assertEqual(docker.call_args_list[-1].args, ("image", "rm", test.image))

    @patch("run.docker", return_value=ok(code=1, stderr="No such container"))
    def test_cleanup_tolerates_objects_that_were_never_created(self, _docker):
        test = SmokeTest()
        test.containers = ["not-created"]
        test.cleanup()

    @patch("run.docker")
    @patch("run.time.sleep")
    def test_wait_is_readiness_based_not_a_fixed_delay(self, sleep, docker):
        docker.side_effect = [ok(code=1), ok(code=1), ok()]
        SmokeTest().wait_for_publisher("publisher")
        sleep.assert_called_once_with(1)

    @patch("run.docker", return_value=ok())
    def test_failed_publisher_fails_without_retrying_account_creation(self, docker):
        docker.side_effect = [ok(code=1), ok()]
        with self.assertRaisesRegex(RuntimeError, "publisher startup failed"):
            SmokeTest().wait_for_publisher("publisher")
        self.assertEqual(docker.call_count, 2)

    @patch("run.time.monotonic", side_effect=[0, 131])
    def test_readiness_deadline_is_bounded(self, _clock):
        with self.assertRaisesRegex(RuntimeError, "deadline"):
            SmokeTest().wait_for_publisher("publisher")

    @patch("run.docker")
    def test_release_version_is_checked_before_account_creation(self, docker):
        docker.side_effect = [ok(), ok(stdout="attached 0.3.4\n")]
        with self.assertRaisesRegex(RuntimeError, "unexpected binary version"):
            SmokeTest(release="0.3.5").build()
        self.assertIn("ATTACHED_VERSION=0.3.5", docker.call_args_list[0].args)

    @patch("run.docker")
    def test_version_container_is_tracked_even_if_version_check_hangs(self, docker):
        test = SmokeTest(release="0.3.5")
        docker.side_effect = [ok(), subprocess.TimeoutExpired("docker", 30)]
        with self.assertRaises(subprocess.TimeoutExpired):
            test.build()
        self.assertEqual(test.containers, [test.prefix + "-version"])
        self.assertIn(test.containers[0], docker.call_args_list[1].args)

    @patch("run.docker", return_value=ok())
    def test_backend_override_and_workflow_order(self, docker):
        test = SmokeTest(service="https://test.example")
        with patch.object(test, "create_machine", side_effect=["client", "publisher"]), \
                patch.object(test, "transfer_bundle"), patch.object(test, "wait_for_publisher"):
            test.exercise()
        commands = [call.args for call in docker.call_args_list]
        self.assertIn(("exec", "client", "python3", "/opt/e2e/machine.py", "create",
                       "--service", "https://test.example"), commands)
        self.assertEqual(sum("create" in command for command in commands), 1)
        self.assertEqual(commands[1][-1], "export")
        self.assertEqual(commands[-1][4], "verify")


class ReleaseTests(unittest.TestCase):
    def test_release_url_is_pinned_and_supports_both_linux_architectures(self):
        for architecture in ("aarch64", "x86_64"):
            self.assertEqual(release_asset("0.3.5", architecture),
                             "https://github.com/pvalletbo/attached/releases/download/v0.3.5/"
                             f"attached-{architecture}-unknown-linux-gnu.tar.xz")
        for version in ("latest", "v0.3.5", "0.3.5;echo bad", "../foo"):
            with self.assertRaises(ValueError):
                release_asset(version, "x86_64")

    def test_release_checksum_and_member_are_verified(self):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:xz") as tar:
            info = tarfile.TarInfo("package/attached")
            info.size = 6
            tar.addfile(info, io.BytesIO(b"binary"))
        archive = buffer.getvalue()
        checksum = hashlib.sha256(archive).hexdigest() + "  archive.tar.xz\n"
        self.assertEqual(executable(archive, checksum, "package/attached"), b"binary")
        with self.assertRaisesRegex(ValueError, "checksum mismatch"):
            executable(archive, "0" * 64, "package/attached")
        with self.assertRaises(KeyError):
            executable(archive, checksum, "wrong/attached")


if __name__ == "__main__":
    unittest.main()
