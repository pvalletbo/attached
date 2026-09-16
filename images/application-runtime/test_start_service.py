import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

WRAPPER = Path(__file__).with_name("start-service.py")

FAKE = '''#!/usr/bin/env python3
import os, sys, time, signal
from pathlib import Path
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
mode = os.environ.get("MODE", "ok")
print("Create Attached encryption password: ", end="", flush=True)
password = input()
print("Confirm Attached encryption password: ", end="", flush=True)
assert input() == password == "test-password"
if mode == "fail":
    print("sensitive-diagnostic", flush=True)
    sys.exit(1)
if mode == "hang":
    time.sleep(30)
label = sys.argv[sys.argv.index("--host-label")+1]
Path(os.environ["PUBLISHED"]).touch()
print(f"Serving synchronized Herdr sessions as `{label}`.", flush=True)
if mode == "die":
    time.sleep(0.5)
    sys.exit(1)
time.sleep(30)
'''


class StartupTests(unittest.TestCase):
    def run_case(self, mode="ok", missing=False, terminate=False):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fake = root / "attached"
            fake.write_text(FAKE.replace("#!/usr/bin/env python3", f"#!{sys.executable}"))
            fake.chmod(0o755)
            bundle, password = root / "bundle", root / "password"
            if not missing:
                bundle.write_text("synthetic-bundle")
            password.write_text("test-password\n")
            published, started = root / "published", root / "started"
            env = dict(os.environ, PATH=f"{folder}:{os.environ['PATH']}", MODE=mode,
                       PUBLISHED=str(published), ATTACHED_PUBLISH_BUNDLE_FILE=str(bundle),
                       ATTACHED_LOCAL_PASSWORD_FILE=str(password), ATTACHED_HOST_LABEL="test-pod",
                       ATTACHED_STARTUP_TIMEOUT_SECONDS="1")
            service = (f"from pathlib import Path; import time; assert Path({str(published)!r}).exists(); "
                       f"Path({str(started)!r}).touch(); " + ("time.sleep(30)" if terminate or mode == "die" else "raise SystemExit(7)"))
            proc = subprocess.Popen([sys.executable, str(WRAPPER), sys.executable, "-c", service],
                                    env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            try:
                if terminate:
                    deadline = time.monotonic() + 5
                    while not started.exists() and time.monotonic() < deadline:
                        time.sleep(0.05)
                    self.assertTrue(started.exists())
                    proc.send_signal(signal.SIGTERM)
                output, _ = proc.communicate(timeout=15)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
            self.assertNotIn(b"test-password", output)
            self.assertNotIn(b"synthetic-bundle", output)
            self.assertNotIn(b"sensitive-diagnostic", output)
            self.assertTrue(password.exists(), "Secret mounts must not be deleted")
            return proc.returncode, started.exists()

    def test_publication_precedes_service_and_exit_status_is_preserved(self):
        self.assertEqual(self.run_case(), (7, True))

    def test_missing_bundle_never_starts_service(self):
        self.assertEqual(self.run_case(missing=True), (1, False))

    def test_failed_publication_never_starts_service(self):
        self.assertEqual(self.run_case(mode="fail"), (1, False))

    def test_timeout_never_starts_service(self):
        self.assertEqual(self.run_case(mode="hang"), (1, False))

    def test_publisher_death_stops_service(self):
        self.assertEqual(self.run_case(mode="die"), (1, True))

    def test_sigterm_stops_both_children(self):
        self.assertEqual(self.run_case(terminate=True), (143, True))


if __name__ == "__main__":
    unittest.main()
