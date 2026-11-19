#!/bin/sh
set -eu
binary=${1:?provide the path to the Marco binary}
python3 - "$binary" <<'PY'
import json
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix="marco-smoke-") as work:
    root = pathlib.Path(work)
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    configuration = {
        "node": "smoke",
        "dataDir": "data",
        "initialConfig": "desired.json",
        "listDirectory": ".",
        "listInterval": "1s",
        "dns": {"listen": [f"127.0.0.1:{port}"], "allow": ["127.0.0.1/32"]},
    }
    desired = {
        "version": 1,
        "zones": [{"name": "home.arpa.", "private": True}],
        "records": [{"name": "welcome.home.arpa.", "type": "A", "value": "192.0.2.10"}],
        "subscriptions": {"smoke": {"file": "filter.txt", "enabled": True}},
    }
    (root / "filter.txt").write_text("||ads.demo.test^\n")
    deployment = root / "deployment.json"
    deployment.write_text(json.dumps(configuration))
    (root / "desired.json").write_text(json.dumps(desired))
    subprocess.run([binary, "validate", "--config", deployment], check=True)
    with subprocess.Popen([binary, "run", "--config", deployment]) as server:
        try:
            query = (
                struct.pack("!6H", 42, 0x100, 1, 0, 0, 0)
                + b"\x07welcome\x04home\x04arpa\x00\x00\x01\x00\x01"
            )
            address = ("127.0.0.1", port)
            deadline = time.monotonic() + 5
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(0.2)
                while True:
                    sock.sendto(query, address)
                    try:
                        udp, _ = sock.recvfrom(512)
                        break
                    except TimeoutError:
                        if time.monotonic() >= deadline or server.poll() is not None:
                            raise
            with socket.create_connection(address, timeout=1) as sock, sock.makefile("rb") as source:
                sock.sendall(struct.pack("!H", len(query)) + query)
                size = struct.unpack("!H", source.read(2))[0]
                tcp = source.read(size)
            assert len(udp) >= 12 and udp == tcp and udp.endswith(socket.inet_aton("192.0.2.10"))
            blocked_query = (
                struct.pack("!6H", 43, 0x100, 1, 0, 0, 0)
                + b"\x03ads\x04demo\x04test\x00\x00\x01\x00\x01"
            )
            deadline = time.monotonic() + 5
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                while time.monotonic() < deadline:
                    sock.sendto(blocked_query, address)
                    response = sock.recv(512)
                    if struct.unpack_from("!H", response, 2)[0] & 0xF == 3:
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("Bundled subscription did not block its configured name")
        finally:
            if server.poll() is None:
                server.send_signal(signal.SIGTERM)
            if server.wait(timeout=10):
                raise SystemExit("Marco failed to shut down cleanly")
    subprocess.run([binary, "backup", "--config", deployment, "--output", root / "backup"], check=True)
    assert (root / "backup" / "history.db").is_file()
PY
