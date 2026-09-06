# Controlled PTY fixture for the production CLI; no credentials or real Herdr/fzf.
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess
import sys
import tempfile
import time

binary, scenario = sys.argv[1:]
assert scenario in {'select', 'client-exit', 'no-match', 'cancel', 'picker-error'}


def script(path, body):
    path.write_text('#!/bin/sh\nset -eu\n' + body)
    path.chmod(0o700)


with tempfile.TemporaryDirectory(prefix='attached-picker-') as temporary:
    root = Path(temporary).resolve()
    home = root / 'home'
    state = home / '.config' / 'attached'
    state.mkdir(parents=True, mode=0o700)
    bindir = root / 'bin'
    bindir.mkdir()
    tui = socket.socket(socket.AF_UNIX)
    # Keep the socket path short enough for macOS sockaddr_un.
    socket_dir = tempfile.TemporaryDirectory(prefix='at-', dir='/private/tmp' if sys.platform == 'darwin' else '/tmp')
    session = Path(socket_dir.name)
    tui.bind(str(session / 'herdr-client.sock'))
    tui.listen()
    (root / 'sessions.json').write_text(json.dumps({'sessions': [
        {'name': 'local-work', 'running': True, 'session_dir': str(session)}
    ]}))
    script(bindir / 'herdr', '''
case "${1-}" in
  --version) printf 'herdr 3.2.1\\n';;
  session) /bin/cat "$FIXTURE_ROOT/sessions.json";;
  client)
    printf '%s' "$HERDR_CLIENT_SOCKET_PATH" > "$FIXTURE_ROOT/attached-local"
    exit "$CLIENT_EXIT";;
  *) exit 19;;
esac
''')
    script(bindir / 'fzf', '''
/bin/cat > "$FIXTURE_ROOT/candidates"
if [ "$PICKER_EXIT" != 0 ]; then exit "$PICKER_EXIT"; fi
/usr/bin/head -n 1 "$FIXTURE_ROOT/candidates"
''')
    env = {
        'HOME': str(home), 'PATH': str(bindir) + ':/usr/bin:/bin',
        'TMPDIR': str(root), 'XDG_RUNTIME_DIR': str(root / 'runtime'),
        'TERM': 'xterm', 'FIXTURE_ROOT': str(root),
        'CLIENT_EXIT': '23' if scenario == 'client-exit' else '0',
        'PICKER_EXIT': {'no-match': '1', 'cancel': '130', 'picker-error': '2'}.get(scenario, '0'),
    }

    def run():
        master, slave = os.openpty()
        args = [binary, 'attach', '--herdr-bin', str(bindir / 'herdr')]
        child = subprocess.Popen(args, stdin=slave, stdout=slave, stderr=slave,
                                 env=env, start_new_session=True)
        os.close(slave)
        output = bytearray()
        deadline = time.monotonic() + 15
        try:
            while True:
                assert time.monotonic() < deadline, 'CLI did not terminate: ' + repr(output)
                ready, _, _ = select.select([master], [], [], 0.1)
                if ready:
                    try:
                        chunk = os.read(master, 8192)
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
                        break
                    if not chunk:
                        break
                    output.extend(chunk)
                    assert len(output) < 128 * 1024, 'excessive fixture output'
                elif child.poll() is not None:
                    break
            return child.wait(timeout=5), output.decode(errors='replace')
        finally:
            # Clean the whole process group, including descendants of an exited CLI.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait(timeout=5)
            os.close(master)

    code, output = run()
    expected = {'client-exit': 23, 'picker-error': 1}.get(scenario, 0)
    assert code == expected, (code, output)
    assert 'local-work' in (root / 'candidates').read_text()
    if scenario in {'select', 'client-exit'}:
        assert (root / 'attached-local').read_text() == str(session / 'herdr-client.sock')
    else:
        assert not (root / 'attached-local').exists(), 'cancelled/failed picker launched Herdr'
    if scenario == 'picker-error':
        assert 'fzf exited with status' in output, output
    tui.close()
    socket_dir.cleanup()
