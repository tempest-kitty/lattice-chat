#!/usr/bin/env bash
set -euo pipefail

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
setup_script="$project_root/scripts/setup-server.sh"
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT

fake_binary="$test_root/lattice-server"
printf '#!/bin/sh\nexit 0\n' > "$fake_binary"
chmod 700 "$fake_binary"

bash "$setup_script" \
  --yes \
  --no-systemd \
  --server-binary "$fake_binary" \
  --install-dir "$test_root/install" \
  --data-dir "$test_root/data" \
  --config-dir "$test_root/config" \
  --listen-addr '127.0.0.1:9443'

test -x "$test_root/install/lattice-server"
test -f "$test_root/config/server.env"
test -f "$test_root/config/lattice-chat.service"
test -f "$test_root/data/lattice-chat.db"
test -f "$test_root/data/tls/server.crt"
test -f "$test_root/data/tls/server.key"
grep -F 'LISTEN_ADDR=127.0.0.1:9443' "$test_root/config/server.env" >/dev/null
grep -F "ExecStart=$test_root/install/lattice-server" "$test_root/config/lattice-chat.service" >/dev/null

python3 - "$test_root/data/lattice-chat.db" <<'PY'
import sqlite3
import sys
connection = sqlite3.connect(sys.argv[1])
assert connection.execute("select name from sqlite_master where type='table' and name='accounts'").fetchone()
PY

if bash "$setup_script" --yes --no-systemd \
  --server-binary "$fake_binary" \
  --install-dir "$test_root/install" \
  --data-dir "$test_root/data" \
  --config-dir "$test_root/config"; then
  echo 'setup unexpectedly overwrote an existing installation' >&2
  exit 1
fi

printf 'setup-server test passed\n'
