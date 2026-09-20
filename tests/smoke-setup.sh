#!/usr/bin/env bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
test_root=$(mktemp -d)
server_pid=''
cleanup() {
  if [[ -n "$server_pid" ]]; then kill "$server_pid" 2>/dev/null || true; fi
  rm -rf -- "$test_root"
}
trap cleanup EXIT

bash "$project_root/scripts/setup-server.sh" --yes --no-systemd \
  --server-binary "$project_root/target/release/twokitties-server" \
  --install-dir "$test_root/install" \
  --data-dir "$test_root/data" \
  --config-dir "$test_root/config" \
  --listen-addr 127.0.0.1:19443 >/dev/null

set -a
. "$test_root/config/server.env"
set +a
"$test_root/install/twokitties-server" >"$test_root/server.log" 2>&1 &
server_pid=$!

python3 - "$test_root/data/tls/server.crt" <<'PY'
import socket
import ssl
import sys
import time

context = ssl.create_default_context(cafile=sys.argv[1])
context.check_hostname = False
for _ in range(50):
    try:
        with socket.create_connection(("127.0.0.1", 19443), timeout=1) as raw:
            with context.wrap_socket(raw, server_hostname="twokitties-self-hosted") as client:
                client.sendall(b"HELLO 1\n")
                response = b""
                while not response.endswith(b"\n"):
                    response += client.recv(128)
                response = response.decode()
                assert response == "READY 1\n", response
                print("deployed TLS smoke test passed")
                break
    except (ConnectionRefusedError, TimeoutError, OSError):
        time.sleep(0.1)
else:
    raise SystemExit("server did not accept TLS connection")
PY
