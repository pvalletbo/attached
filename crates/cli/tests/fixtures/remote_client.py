# Fake Herdr only; Attached itself is the production compiled binary.
import os
from pathlib import Path
import socket
import time

root = Path(os.environ['FIXTURE_ROOT'])
path = os.environ['HERDR_CLIENT_SOCKET_PATH']
(root / 'herdr-pid').write_text(str(os.getpid()))
(root / 'proxy-socket').write_text(path)
payload = bytes(range(256)) * 2048
with socket.socket(socket.AF_UNIX) as client:
    client.settimeout(15)
    client.connect(path)
    client.sendall(payload)
    client.shutdown(socket.SHUT_WR)
    received = bytearray()
    while chunk := client.recv(8192):
        received.extend(chunk)
    assert received == payload, 'tunnel corrupted the payload'
(root / 'received').write_text(str(len(received)))
if os.environ['FIXTURE_MODE'] == 'drop':
    # A protocol handshake, not a sleep, tells the test when it can drop Iroh.
    with socket.socket(socket.AF_UNIX) as ready:
        ready.settimeout(15)
        ready.connect(path)
        ready.sendall(b'ready')
        ready.shutdown(socket.SHUT_WR)
        # Stay alive even after proxy EOF: Attached must terminate/reap us.
        while True:
            time.sleep(1)
raise SystemExit(23)
