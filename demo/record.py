#!/usr/bin/env python3
"""Record with: python3 demo/record.py [--skip-build]

Requires macOS/Linux, Docker, attached, herdr, tmux, VHS, ttyd and ffmpeg.
Uses the installed client binaries and the real hosted Attached service. The
remote image contains the latest stable Herdr; Attached is installed on camera.
1234 is a disposable demo password, not a recommendation for real accounts.

All credentials, OpenSSH configuration, Herdr state and tmux sockets are private
and temporary. No clipboard is used. The GIF and tape never contain a bundle.
Only the demo container and isolated Herdr/tmux servers are stopped at exit.
"""

import argparse
import os
from pathlib import Path
import shlex
import shutil
import signal
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "attached-demo-herdr:latest"
CONTAINER = "attached-demo-office"


def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)


def isolated_env(home, tools, docker_host, original=None):
    original = os.environ if original is None else original
    env = {
        key: value for key, value in original.items()
        if not key.startswith(("HERDR_", "ATTACHED_", "XDG_", "TMUX", "SSH_"))
        and key not in {"BASH_ENV", "ENV", "PROMPT_COMMAND", "ZDOTDIR"}
    }
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_STATE_HOME=str(home / ".local/state"),
        PATH=f"{tools}:{original['PATH']}",
        SHELL="/bin/bash",
        DOCKER_HOST=docker_host,
        DOCKER_CONFIG=original.get("DOCKER_CONFIG", str(Path(original["HOME"]) / ".docker")),
        TERM="xterm-256color",
        COLORTERM="truecolor",
        HISTFILE="/dev/null",
        BASH_SILENCE_DEPRECATION_WARNING="1",
    )
    env.pop("DOCKER_CONTEXT", None)  # DOCKER_HOST selects the original daemon.
    return env


def prepare(home, tools, ssh):
    home.mkdir(mode=0o700)
    tools.mkdir(mode=0o700)
    (home / ".ssh").mkdir(mode=0o700)
    (home / ".ssh/config").touch(mode=0o600)
    config = home / ".config/herdr"
    config.mkdir(parents=True)
    (config / "config.toml").write_text(
        'onboarding = false\n\n[theme]\nname = "terminal"\n'
    )
    (home / ".bashrc").write_text(
        "export PS1='\\[\\e[38;5;75m\\]client \\[\\e[0m\\]$ '\n"
        "unset PROMPT_COMMAND\n"
    )
    (home / ".bash_profile").write_text('. "$HOME/.bashrc"\n')
    # OpenSSH resolves ~/.ssh through getpwuid(), not $HOME. Keep all its reads
    # in the demo home, including when Herdr invokes it indirectly.
    wrapper = tools / "ssh"
    wrapper.write_text(f'#!/bin/sh\nexec {shlex.quote(ssh)} -F "$HOME/.ssh/config" "$@"\n')
    wrapper.chmod(0o700)


def stop_demo(tmux, env, created):
    # A stuck local server must not prevent stopping the container/exporter.
    try:
        subprocess.run(["herdr", "session", "stop", "default"], env=env,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20)
    except (OSError, subprocess.TimeoutExpired):
        pass
    finally:
        try:
            subprocess.run([*tmux, "kill-server"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
        finally:
            if created:
                subprocess.run(["docker", "rm", "-f", CONTAINER],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)


def verify_remote(env):
    # Verification only: this command is deliberately outside the VHS recording.
    # Attached intentionally gives noninteractive SSH commands a minimal PATH.
    result = run("ssh", "attached-office",
                 'hostname; herdr --version; "$HOME/.local/bin/attached" --version',
                 env=env, capture_output=True, text=True, timeout=30)
    lines = result.stdout.splitlines()
    if (len(lines) != 3 or lines[0] != "office"
            or not lines[1].startswith("herdr ") or not lines[2].startswith("attached ")):
        raise RuntimeError(f"unexpected remote verification output: {result.stdout}")
    print("Verified through the live SSH exporter: " + ", ".join(lines))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true", help="reuse the demo image")
    args = parser.parse_args()
    for binary in ("docker", "attached", "herdr", "ssh", "tmux", "vhs", "ttyd", "ffmpeg", "ffprobe"):
        if not shutil.which(binary):
            parser.error(f"missing prerequisite: {binary}")
    run("attached", "--version")
    run("herdr", "--version")
    run("docker", "info", stdout=subprocess.DEVNULL)
    exists = subprocess.run(
        ["docker", "container", "inspect", CONTAINER],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    if exists.returncode == 0:
        parser.error(f"{CONTAINER} already exists; refusing to change it")
    if not args.skip_build:
        run("docker", "build", "--pull", "--no-cache", "-t", IMAGE, str(ROOT / "demo"))
    docker_host = os.environ.get("DOCKER_HOST") or run(
        "docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}",
        capture_output=True, text=True,
    ).stdout.strip()
    artifacts = ROOT / "demo/.artifacts"
    artifacts.mkdir(exist_ok=True)
    # Route external cancellation through the same finally-based cleanup.
    signal.signal(signal.SIGTERM, interrupted)
    with tempfile.TemporaryDirectory(prefix="ad-", dir="/tmp") as temporary:
        # Attached intentionally rejects symlinked state ancestors (/tmp on macOS).
        directory = Path(temporary).resolve()
        home, tools = directory / "client", directory / "bin"
        prepare(home, tools, shutil.which("ssh"))
        env = isolated_env(home, tools, docker_host)
        tmux = ["tmux", "-S", str(directory / "tmux.sock")]
        config = directory / "tmux.conf"
        config.write_text(
            "set -g prefix C-a\n"
            "unbind C-b\n"
            "set -g base-index 1\n"
            "set -g default-terminal tmux-256color\n"
            "set -g allow-rename off\n"
            "set -g update-environment ''\n"
            "set -g status-position top\n"
            "set -g status-style 'bg=#24283b,fg=#a9b1d6'\n"
            "set -g status-left ' ATTACHED  |  '\n"
            "set -g status-left-length 20\n"
            "set -g status-right ''\n"
            "set -g window-status-format ' #I: #W '\n"
            "set -g window-status-current-format '#[fg=#24283b,bg=#7aa2f7,bold] #I: #W #[default]'\n"
            "set -g window-status-separator '  '\n"
            "set -g status-interval 0\n"
        )
        created = False
        try:
            run("docker", "run", "--detach", "--rm", "--name", CONTAINER,
                "--hostname", "office", IMAGE)
            created = True
            run(*tmux, "-f", str(config), "new-session", "-d", "-s", "demo",
                "-n", "Client", "-c", str(home), "bash --noprofile --rcfile ~/.bashrc",
                env=env)
            run(*tmux, "new-window", "-t", "demo:2", "-n", "Remote (Docker)",
                f"docker exec -it {CONTAINER} bash --noprofile --rcfile /root/.bashrc",
                env=env)
            run(*tmux, "new-window", "-t", "demo:3", "-n", "Client: SSH forwarding",
                "-c", str(home), "bash --noprofile --rcfile ~/.bashrc", env=env)
            run(*tmux, "select-window", "-t", "demo:1", env=env)
            # VHS keeps the real HOME for its browser/cache. Only its terminal
            # attaches to our private tmux server, whose processes use demo HOME.
            vhs_env = dict(os.environ, DEMO_TMUX_SOCKET=str(directory / "tmux.sock"))
            run("vhs", "demo/attached-demo.tape", cwd=ROOT, env=vhs_env)
            verify_remote(env)
            run("python3", "demo/test_demo.py", "--recording", cwd=ROOT)
        finally:
            # Capture diagnostics before deleting state, but never export bundles.
            try:
                for window in (1, 2, 3):
                    result = subprocess.run(
                        [*tmux, "capture-pane", "-p", "-S", "-200", "-t", f"demo:{window}"],
                        capture_output=True, text=True, timeout=10,
                    )
                    (artifacts / f"terminal-{window}.txt").write_text(result.stdout)
            finally:
                stop_demo(tmux, env, created)


def interrupted(signum, _frame):
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    main()
