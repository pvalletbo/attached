"""In-container CLI driver. Uses real password prompts, not an encryption bypass."""

import argparse
import os
from pathlib import Path
import secrets
import signal
import sys
import time

import pexpect

HOME = Path("/home/attached")
CREATE = "Create Attached encryption password: "
CONFIRM = "Confirm Attached encryption password: "
UNLOCK = "Attached encryption password: "


class Terminal:
    def __init__(self, command, password, timeout=90):
        self.password = password
        self.deadline = time.monotonic() + timeout
        self.output = ""
        self.child = pexpect.spawn(command[0], command[1:], encoding="utf-8", echo=False)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.child.close(force=True)

    def expect(self, pattern):
        try:
            self.child.expect_exact(pattern, timeout=max(0, self.deadline - time.monotonic()))
        except (pexpect.EOF, pexpect.TIMEOUT):
            self.output += self.child.before
            # Do not print pexpect's exception: it includes input buffers and
            # process arguments. Bundles never enter this terminal's output.
            tail = self.output.replace(self.password, "[redacted]")[-4000:]
            raise RuntimeError(f"CLI exited early or timed out; output: {tail}") from None
        self.output += self.child.before

    def unlock(self, create=False):
        for prompt in (CREATE, CONFIRM) if create else (UNLOCK,):
            self.expect(prompt)
            self.child.sendline(self.password)

    def finish(self, expected_status=0):
        self.expect(pexpect.EOF)
        self.child.close()
        output = self.output.replace(self.password, "[redacted]").replace("\r\n", "\n").strip()
        if self.child.exitstatus != expected_status:
            raise RuntimeError(
                f"CLI exit status {self.child.exitstatus}, expected {expected_status}; "
                f"output: {output[-4000:]}"
            )
        return output


def password():
    path = HOME / ".test-password"
    if not path.exists():
        path.write_text(secrets.token_urlsafe(32))
    return path.read_text()


def command(arguments, *, create=False, expected_status=0):
    with Terminal(["attached", *arguments], password()) as terminal:
        terminal.unlock(create=create)
        return terminal.finish(expected_status)


def verify(proof):
    # No IP address, docker exec, sshd, or port mapping can satisfy this check:
    # the client must discover the fresh publisher via its new account.
    output = command([
        "ssh", "--no-cache", "e2e-publisher",
        "hostname; id -un; cat /home/attached/remote-proof",
    ])
    expected = f"e2e-publisher\nattached\n{proof}"
    if output != expected:
        raise RuntimeError(f"unexpected remote output: {output!r}; expected {expected!r}")
    command(["ssh", "e2e-publisher", "exit 37"], expected_status=37)
    print("PASS: SSH executed on the publisher; output and remote exit status verified", flush=True)


def serve(proof):
    (HOME / "remote-proof").write_text(proof + "\n")
    with Terminal([
        "attached", "serve", "--host-label", "e2e-publisher",
        "--bundle-file", str(HOME / "publish.bundle"),
    ], password(), timeout=120) as terminal:
        terminal.unlock(create=True)
        terminal.expect("Serving Attached SSH tunnels as `e2e-publisher`.")
        (HOME / "publish.bundle").unlink()
        (HOME / "ready").touch()
        print("PASS: publisher imported the bundle and published its host", flush=True)
        # Also bound the publisher lifetime if the orchestrator is killed.
        terminal.deadline = time.monotonic() + 600
        terminal.finish()
        raise RuntimeError("publisher stopped before test cleanup")


def main():
    os.umask(0o077)
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("create", "export", "serve", "verify"))
    parser.add_argument("--service")
    parser.add_argument("--proof")
    args = parser.parse_args()
    if args.action == "create":
        command(["account", "create", "--service", args.service], create=True)
        print("PASS: new account created and saved", flush=True)
    elif args.action == "export":
        command(["account", "export", "--type", "publish", "--output", str(HOME / "publish.bundle")])
        print("PASS: publish-only bundle exported", flush=True)
    elif args.action == "serve":
        serve(args.proof)
    else:
        verify(args.proof)


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"FAIL: {error}", file=sys.stderr, flush=True)
        sys.exit(1)
