import os
import shutil
import signal
import subprocess
import tempfile
import textwrap
import time
import unittest
from pathlib import Path


RECIPES = Path(__file__).resolve().parents[1]
ENTRYPOINT = RECIPES / "docker" / "entrypoint.sh"
EXPECT_DRIVER = RECIPES / "docker" / "run-attached.exp"


FAKE_ATTACHED = r"""#!/bin/sh
set -eu
bundle_file=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--bundle-file" ]; then
        bundle_file="$2"
        shift 2
    else
        shift
    fi
done
[ -n "$bundle_file" ]
pwd >"$CAPTURED_STARTUP_CWD"
cat "$bundle_file" >"$CAPTURED_BUNDLE"
if [ "${ATTACHED_LOCAL_PASSWORD+x}" = x ] || \
   [ "${ATTACHED_LOCAL_PASSWORD_FILE+x}" = x ] || \
   [ "${ATTACHED_PUBLISH_BUNDLE+x}" = x ] || \
   [ "${ATTACHED_PUBLISH_BUNDLE_FILE+x}" = x ]; then
    : >"$SECRET_LEAK_MARKER"
fi
if [ "${MODEL_API_TOKEN-}" != "test-model-token" ]; then
    : >"$MODEL_TOKEN_MISSING_MARKER"
fi

stty -echo
if [ "$PASSWORD_MODE" = "create" ]; then
    printf 'Create Attached encryption password: ' >/dev/tty
    IFS= read -r first </dev/tty
    printf '\nConfirm Attached encryption password: ' >/dev/tty
    IFS= read -r second </dev/tty
    printf '%s\n%s\n' "$first" "$second" >"$CAPTURED_PASSWORDS"
else
    printf 'Attached encryption password: ' >/dev/tty
    IFS= read -r first </dev/tty
    printf '%s\n' "$first" >"$CAPTURED_PASSWORDS"
fi
stty echo
if [ -e "$bundle_file" ]; then
    : >"$BUNDLE_RETAINED_MARKER"
fi

printf '\nServing synchronized Herdr sessions as `recipe-test`.\n' >&2
: >"$PUBLISHER_READY_MARKER"
trap 'printf stopped >"$ATTACHED_STOP_MARKER"; exit 0' INT TERM HUP
while :; do sleep 1; done
"""

FAKE_HERDR = r"""#!/bin/sh
printf '%s\n' "$*" >>"$HERDR_CALLS"
exit 0
"""

FAKE_INIT = r"""#!/bin/sh
set -eu
[ "$1" = "--" ]
shift
if [ "${ATTACHED_LOCAL_PASSWORD+x}" = x ] || \
   [ "${ATTACHED_LOCAL_PASSWORD_FILE+x}" = x ] || \
   [ "${ATTACHED_PUBLISH_BUNDLE+x}" = x ] || \
   [ "${ATTACHED_PUBLISH_BUNDLE_FILE+x}" = x ]; then
    : >"$SECRET_LEAK_MARKER"
fi
: >"$INIT_STARTED_MARKER"
exec "$@"
"""

FAKE_BUSYBOX = r"""#!/bin/sh
set -eu
[ "$1" = "httpd" ]
shift
root=""
test_root="${PATH%%:*}"
printf '%s\n' "$*" >"$test_root/health-arguments"
while [ "$#" -gt 0 ]; do
    case "$1" in
        -f) shift ;;
        -p) shift 2 ;;
        -h) root="$2"; shift 2 ;;
        *) exit 2 ;;
    esac
done
cat "$root/healthz" >"$test_root/health-content"
if [ "${MODEL_API_TOKEN+x}" = x ]; then
    : >"$test_root/health-env-leaked"
fi
: >"$test_root/health-started"
trap 'exit 0' INT TERM HUP
while :; do sleep 1; done
"""


class EntrypointTests(unittest.TestCase):
    def setUp(self):
        self.expect = shutil.which("expect")
        if self.expect is None:
            self.skipTest("expect is not installed")

    def write_executable(self, path: Path, content: str) -> None:
        path.write_text(textwrap.dedent(content), encoding="utf-8")
        path.chmod(0o700)

    def isolated_environment(self, root: Path) -> dict[str, str]:
        path = os.environ.get("PATH", "/usr/bin:/bin")
        return {
            "PATH": f"{root}:{path}",
            "HOME": str(root / "home"),
            "TMPDIR": str(root / "tmp"),
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
            "MODEL_API_TOKEN": "test-model-token",
            "ATTACHED_BIN": str(root / "attached"),
            "HERDR_BIN": str(root / "herdr"),
            "EXPECT_BIN": self.expect or "expect",
            "ATTACHED_EXPECT_SCRIPT": str(EXPECT_DRIVER),
            "ATTACHED_INIT_BIN": str(root / "fake-init"),
            "ATTACHED_STATE_DIR": str(root / "state"),
            "HERDR_STARTUP_CWD": str(root / "workspace"),
            "ATTACHED_HOST_LABEL": "recipe-test",
            "ATTACHED_STARTUP_TIMEOUT_SECONDS": "10",
            "CAPTURED_BUNDLE": str(root / "captured-bundle"),
            "CAPTURED_PASSWORDS": str(root / "captured-passwords"),
            "CAPTURED_STARTUP_CWD": str(root / "captured-startup-cwd"),
            "SECRET_LEAK_MARKER": str(root / "secret-leaked"),
            "MODEL_TOKEN_MISSING_MARKER": str(root / "model-token-missing"),
            "BUNDLE_RETAINED_MARKER": str(root / "bundle-retained"),
            "PUBLISHER_READY_MARKER": str(root / "publisher-ready"),
            "ATTACHED_STOP_MARKER": str(root / "attached-stopped"),
            "HERDR_CALLS": str(root / "herdr-calls"),
            "INIT_STARTED_MARKER": str(root / "init-started"),
        }

    @staticmethod
    def wait_for(path: Path, timeout: float = 10) -> None:
        deadline = time.monotonic() + timeout
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        if not path.exists():
            raise AssertionError(f"timed out waiting for {path}")

    def launch_case(self, *, from_files: bool, password_mode: str, health: bool) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tmp").mkdir()
            self.write_executable(root / "attached", FAKE_ATTACHED)
            self.write_executable(root / "herdr", FAKE_HERDR)
            self.write_executable(root / "fake-init", FAKE_INIT)
            self.write_executable(root / "busybox", FAKE_BUSYBOX)

            password = "test-local-password"
            bundle = "test-publish-bundle"
            environment = self.isolated_environment(root)
            environment["PASSWORD_MODE"] = password_mode
            if from_files:
                password_file = root / "source-password"
                bundle_file = root / "source-bundle"
                password_file.write_text(f"{password}\n", encoding="utf-8")
                bundle_file.write_text(bundle, encoding="utf-8")
                password_file.chmod(0o600)
                bundle_file.chmod(0o600)
                environment["ATTACHED_LOCAL_PASSWORD_FILE"] = str(password_file)
                environment["ATTACHED_PUBLISH_BUNDLE_FILE"] = str(bundle_file)
            else:
                environment["ATTACHED_LOCAL_PASSWORD"] = password
                environment["ATTACHED_PUBLISH_BUNDLE"] = bundle

            port = 43210 if health else 0
            environment["ATTACHED_HEALTH_PORT"] = str(port)
            process = subprocess.Popen(
                [str(ENTRYPOINT)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
            output = ""
            try:
                self.wait_for(root / "publisher-ready")
                if health:
                    self.wait_for(root / "health-started")
                    self.assertEqual((root / "health-content").read_text(), "ok\n")
                    self.assertFalse((root / "health-env-leaked").exists())
                    arguments = (root / "health-arguments").read_text()
                    self.assertIn("0.0.0.0:43210", arguments)

                process.send_signal(signal.SIGTERM)
                output, _ = process.communicate(timeout=10)
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    output, _ = process.communicate(timeout=5)

            self.assertEqual(process.returncode, 0, output)
            self.assertTrue((root / "attached-stopped").exists(), output)
            self.assertTrue((root / "init-started").exists(), output)
            self.assertFalse((root / "secret-leaked").exists(), output)
            self.assertFalse((root / "model-token-missing").exists(), output)
            self.assertFalse((root / "bundle-retained").exists(), output)
            self.assertEqual((root / "captured-bundle").read_text(), bundle)
            self.assertEqual(
                Path((root / "captured-startup-cwd").read_text().strip()),
                root / "workspace",
            )
            expected_passwords = (
                f"{password}\n{password}\n" if password_mode == "create" else f"{password}\n"
            )
            self.assertEqual((root / "captured-passwords").read_text(), expected_passwords)
            self.assertEqual((root / "herdr-calls").read_text(), "server stop\n")
            self.assertNotIn(password, output)
            self.assertNotIn(bundle, output)
            self.assertEqual(list((root / "tmp").iterdir()), [])

    def test_environment_secrets_are_scrubbed_and_health_waits_for_publication(self):
        self.launch_case(from_files=False, password_mode="create", health=True)

    def test_secret_files_support_an_existing_encrypted_state(self):
        self.launch_case(from_files=True, password_mode="existing", health=False)

    def test_invalid_health_port_cleans_staged_secrets_before_startup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tmp").mkdir()
            self.write_executable(root / "attached", FAKE_ATTACHED)
            self.write_executable(root / "herdr", FAKE_HERDR)
            self.write_executable(root / "fake-init", FAKE_INIT)
            self.write_executable(root / "busybox", FAKE_BUSYBOX)
            environment = self.isolated_environment(root)
            environment.update(
                {
                    "ATTACHED_PUBLISH_BUNDLE": "test-bundle",
                    "ATTACHED_LOCAL_PASSWORD": "test-password",
                    "ATTACHED_HEALTH_PORT": "70000",
                }
            )
            result = subprocess.run(
                [str(ENTRYPOINT)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("at most 65535", result.stdout)
            self.assertFalse((root / "publisher-ready").exists())
            self.assertEqual(list((root / "tmp").iterdir()), [])

    def test_missing_password_fails_before_attached_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "tmp").mkdir()
            self.write_executable(root / "attached", FAKE_ATTACHED)
            self.write_executable(root / "herdr", FAKE_HERDR)
            self.write_executable(root / "fake-init", FAKE_INIT)
            environment = self.isolated_environment(root)
            environment["ATTACHED_PUBLISH_BUNDLE"] = "test-bundle"
            result = subprocess.run(
                [str(ENTRYPOINT)],
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 2)
            self.assertIn("ATTACHED_LOCAL_PASSWORD", result.stdout)
            self.assertFalse((root / "publisher-ready").exists())
            self.assertEqual(list((root / "tmp").iterdir()), [])


if __name__ == "__main__":
    unittest.main()
