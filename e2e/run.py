#!/usr/bin/env python3
"""Live account -> publish bundle -> SSH smoke test (Python 3.9+ and Docker).

    python3 e2e/run.py                  # build/test this checkout
    python3 e2e/run.py --release 0.3.5  # test official release assets
    python3 e2e/run.py --service https://other-backend.example

The default backend is PRODUCTION. Each invocation creates ONE real account;
there is currently no account-deletion API, so its backend state remains. Never
retry account creation automatically or run this as a load test. Credentials,
passwords and SSH state live only in disposable container tmpfs filesystems.
No host credentials, ports, Docker socket, or host directories are mounted.

Client and publisher use separate Docker networks with outbound internet access
(sync service and Iroh). --service is embedded in the new account's bundle, so
both sides use the same backend. A future local backend must be reachable from
both containers and use an origin accepted by Attached (HTTPS, or HTTP loopback
via a container-local forwarder; host localhost is not container localhost).

All waits are bounded. Ctrl-C/SIGTERM and failures remove this run's containers,
networks and image. Hard kills may require removing resources with the printed
io.attached.e2e-run label; container processes self-expire after ten minutes.
No credential-bearing state is retained as an artifact.
"""

import argparse
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time
import uuid

from install_release import release_asset

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SERVICE = "https://herdr.attached.sh"
LABEL = "io.attached.e2e-run"


def docker(*arguments, timeout=30, check=True, **kwargs):
    result = subprocess.run(
        ["docker", *arguments], timeout=timeout, check=False, **kwargs,
    )
    if check and result.returncode:
        raise RuntimeError(f"docker {arguments[0]} failed with exit status {result.returncode}")
    return result


class SmokeTest:
    def __init__(self, service=DEFAULT_SERVICE, release=None):
        self.service = service
        self.release = release
        self.run_id = uuid.uuid4().hex
        self.prefix = f"attached-e2e-{self.run_id}"
        self.image = f"attached-e2e:{self.run_id}"
        self.containers = []
        self.networks = []
        self.build_attempted = False

    def build(self):
        self.build_attempted = True
        arguments = [
            "build", "--force-rm", "--file", str(ROOT / "e2e/Dockerfile"),
            "--tag", self.image, "--label", f"{LABEL}={self.run_id}",
            "--target", "release" if self.release else "source",
        ]
        if self.release:
            arguments += ["--build-arg", f"ATTACHED_VERSION={self.release}"]
        docker(*arguments, str(ROOT), timeout=2400)
        version_container = self.prefix + "-version"
        self.containers.append(version_container)
        result = docker("run", "--rm", "--name", version_container,
                        "--label", f"{LABEL}={self.run_id}", "--network", "none",
                        "--read-only", "--cap-drop", "ALL", self.image,
                        "attached", "--version", capture_output=True, text=True)
        version = result.stdout.strip()
        if not version.startswith("attached ") or (
            self.release and version != f"attached {self.release}"
        ):
            raise RuntimeError(f"unexpected binary version: {version!r}")
        print(f"Testing {version} against {self.service}", flush=True)

    def create_machine(self, role):
        name = f"{self.prefix}-{role}"
        network = name + "-net"
        # Unique names are registered before creation to clean up even if the
        # Docker client times out after the daemon accepted its request.
        self.networks.append(network)
        docker("network", "create", "--label", f"{LABEL}={self.run_id}", network,
               stdout=subprocess.DEVNULL)
        self.containers.append(name)
        docker(
            "create", "--name", name, "--hostname", f"e2e-{role}",
            "--label", f"{LABEL}={self.run_id}", "--network", network,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--pids-limit", "256", "--memory", "512m", "--init",
            "--tmpfs", "/home/attached:rw,nosuid,nodev,uid=1000,gid=1000,mode=0700",
            "--tmpfs", "/tmp:rw,nosuid,nodev,mode=1777",
            "--tmpfs", "/var/tmp:rw,nosuid,nodev,mode=1777",
            self.image, "sleep", "600", stdout=subprocess.DEVNULL,
        )
        docker("start", name, stdout=subprocess.DEVNULL)
        return name

    def execute(self, container, action, *arguments):
        docker("exec", container, "python3", "/opt/e2e/machine.py", action,
               *arguments, timeout=200)

    def transfer_bundle(self, client, publisher):
        # The only credential crossing the host stays in memory, never in argv,
        # logs, environment, or a temporary file. Write as the publisher's user
        # (docker cp defaults to root ownership and cannot always copy to tmpfs).
        bundle = docker("exec", client, "cat", "/home/attached/publish.bundle",
                        capture_output=True).stdout
        docker("exec", "--interactive", publisher, "sh", "-c",
               "umask 077; cat > /home/attached/publish.bundle", input=bundle)
        docker("exec", client, "rm", "/home/attached/publish.bundle")

    def wait_for_publisher(self, publisher, timeout=130):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = docker("exec", publisher, "test", "-f", "/home/attached/ready",
                            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if result.returncode == 0:
                return
            # The detached driver writes a failure sentinel if startup fails.
            failed = docker("exec", publisher, "test", "-f", "/home/attached/failed",
                            check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if failed.returncode == 0:
                raise RuntimeError("publisher startup failed")
            time.sleep(1)
        raise RuntimeError("publisher did not become ready before the deadline")

    def exercise(self):
        client = self.create_machine("client")
        publisher = self.create_machine("publisher")
        self.execute(client, "create", "--service", self.service)
        self.execute(client, "export")
        self.transfer_bundle(client, publisher)
        proof = secrets.token_hex(16)
        # Keep a bounded, read-only log separate from account state. No raw
        # pexpect transcript or portable bundle is ever logged.
        docker("exec", "--detach", publisher, "sh", "-c",
               'python3 /opt/e2e/machine.py serve --proof "$1" '
               '> /home/attached/publisher.log 2>&1 || touch /home/attached/failed',
               "sh", proof)
        self.wait_for_publisher(publisher)
        self.execute(client, "verify", "--proof", proof)
        print("PASS: account creation -> bundle publishing -> remote SSH", flush=True)

    def diagnostics(self):
        for container in self.containers:
            if container.endswith("-publisher"):
                try:
                    docker("exec", container, "tail", "-c", "8000",
                           "/home/attached/publisher.log", check=False)
                except (OSError, subprocess.TimeoutExpired):
                    pass

    def cleanup(self):
        failures = []
        resources = [("rm", "--force", name) for name in reversed(self.containers)]
        resources += [("network", "rm", name) for name in reversed(self.networks)]
        if self.build_attempted:
            resources.append(("image", "rm", self.image))
        for resource in resources:
            try:
                result = docker(*resource, check=False, capture_output=True, text=True)
                # Partially completed creates/builds may leave no object behind.
                missing = any(message in result.stderr for message in (
                    "No such container", "No such image", f"network {resource[-1]} not found",
                ))
                if result.returncode and not missing:
                    failures.append(resource[-1])
            except (OSError, subprocess.TimeoutExpired):
                failures.append(resource[-1])
        if failures:
            raise RuntimeError("could not clean up: " + ", ".join(failures))

    def run(self):
        print(f"Run label: {LABEL}={self.run_id}", flush=True)
        print("Creates one backend account; the backend has no account-deletion API.", flush=True)
        try:
            self.build()
            self.exercise()
        finally:
            try:
                self.diagnostics()
            finally:
                self.cleanup()


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--service", default=DEFAULT_SERVICE, help="backend origin (default: production)")
    parser.add_argument("--release", help="official stable version; omitted = build this checkout")
    args = parser.parse_args()
    if args.release:
        try:
            release_asset(args.release, "x86_64")  # validate before building or contacting production
        except ValueError as error:
            parser.error(str(error))
    signal.signal(signal.SIGTERM, interrupted)
    docker("info", stdout=subprocess.DEVNULL)
    SmokeTest(args.service, args.release).run()


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        sys.exit(1)
