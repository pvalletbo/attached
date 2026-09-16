#!/usr/bin/env python3
"""Publish a Herdr session before starting the container's original command."""
import errno
import os
from pathlib import Path
import pty
import re
import select
import signal
import subprocess
import sys
import tempfile
import termios
import time
import fcntl

STOP = 0


def interrupted(signum, _frame):
    global STOP
    STOP = signum


def stop(children):
    for child, sig in children:
        if child is not None:
            try:
                os.killpg(child.pid, sig)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if all(child is None or child.poll() is not None for child, _ in children):
            break
        time.sleep(0.1)
    for child, _ in children:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()


def main(command):
    if not command:
        raise ValueError("service command is required")
    bundle = Path(os.environ.get("ATTACHED_PUBLISH_BUNDLE_FILE", "/run/secrets/attached/publish.bundle"))
    password_file = Path(os.environ.get("ATTACHED_LOCAL_PASSWORD_FILE", "/run/secrets/attached/local-password"))
    if not bundle.is_file() or not bundle.stat().st_size:
        raise ValueError("publisher bundle file is missing or empty")
    with password_file.open("rb") as source:
        password = source.read(4097)
    password = password.removesuffix(b"\n").removesuffix(b"\r")
    if not password or len(password) > 1024 or any(c < 32 or c == 127 for c in password):
        raise ValueError("local password must be 1-1024 bytes without terminal control characters")
    label = os.environ.get("ATTACHED_HOST_LABEL", os.environ.get("HOSTNAME", "application"))
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", label):
        raise ValueError("host label must contain only letters, digits, dots, underscores and hyphens")
    timeout = int(os.environ.get("ATTACHED_STARTUP_TIMEOUT_SECONDS", "120"))
    if not 1 <= timeout <= 900:
        raise ValueError("startup timeout must be between 1 and 900 seconds")

    # Private ephemeral state; no image-baked identity and no writes to Secret mounts.
    with tempfile.TemporaryDirectory(prefix="attached-home-") as home:
        config = Path(home, ".config/herdr")
        config.mkdir(parents=True, mode=0o700)
        (config / "config.toml").write_text('onboarding = false\n\n[theme]\nname = "terminal"\n')
        env = os.environ.copy()
        env.update(HOME=home, XDG_CONFIG_HOME=f"{home}/.config", XDG_DATA_HOME=f"{home}/.local/share",
                   XDG_STATE_HOME=f"{home}/.local/state", XDG_RUNTIME_DIR=home,
                   SHELL="/bin/sh", TERM="xterm-256color")
        for name in list(env):
            if name.startswith("HERDR_") or name in ("ATTACHED_PUBLISH_BUNDLE", "OP_SERVICE_ACCOUNT_TOKEN"):
                env.pop(name, None)
        master, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(slave, termios.TCSANOW, attrs)

        def terminal_session():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        publisher = service = None
        try:
            publisher = subprocess.Popen(
                ["attached", "serve", "--bundle-file", str(bundle.resolve()), "--host-label", label],
                stdin=slave, stdout=slave, stderr=slave, env=env, preexec_fn=terminal_session,
            )
            os.close(slave)
            slave = None
            deadline = time.monotonic() + timeout
            buffer = b""
            ready = f"Serving synchronized Herdr sessions as `{label}`.".encode()
            prompts = (b"Create Attached encryption password: ", b"Confirm Attached encryption password: ",
                       b"Attached encryption password: ")
            while not STOP:
                if publisher.poll() is not None:
                    raise RuntimeError("publisher exited; service will not remain running")
                if service is not None and service.poll() is not None:
                    return service.returncode if service.returncode >= 0 else 128 - service.returncode
                if service is None and time.monotonic() >= deadline:
                    raise RuntimeError("initial publication timed out; service was not started")
                if not select.select([master], [], [], 0.1)[0]:
                    continue
                try:
                    data = os.read(master, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b""
                if not data:
                    raise RuntimeError("publisher terminal closed")
                # Never forward PTY output: prompts/echo/errors may contain credentials.
                buffer = (buffer + data)[-16384:]
                if service is None:
                    for prompt in prompts:
                        if prompt in buffer:
                            os.write(master, password + b"\r")
                            buffer = buffer.split(prompt, 1)[1]
                    if ready + b"\r\n" in buffer or ready + b"\n" in buffer:
                        if STOP:
                            break
                        password = b""
                        print("attached: initial session catalog published; starting service", flush=True)
                        service = subprocess.Popen(command, start_new_session=True)
                        buffer = b""
            return 128 + STOP
        finally:
            stop([(service, signal.SIGTERM), (publisher, signal.SIGINT)])
            os.close(master)
            if slave is not None:
                os.close(slave)


if __name__ == "__main__":
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        sys.exit(main(sys.argv[1:]))
    except (OSError, ValueError, RuntimeError):
        # Do not print exception strings from subprocesses or secret-file operations.
        print("attached: publisher/service startup or supervision failed; check secret mounts and connectivity", file=sys.stderr)
        sys.exit(1)
