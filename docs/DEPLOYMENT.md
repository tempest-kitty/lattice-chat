# Self-hosting TwoKitties

The current Linux setup path installs the server binary, initializes SQLite, generates local TLS material, writes an environment file, and generates a systemd unit.

## Build and install

From the repository root:

```text
cargo build --release -p twokitties-server
sudo scripts/setup-server.sh --yes \
  --server-binary target/release/twokitties-server
```

For a non-root dry installation or test directory:

```text
scripts/setup-server.sh --yes --no-systemd \
  --server-binary target/release/twokitties-server \
  --install-dir ./run/install \
  --data-dir ./run/data \
  --config-dir ./run/config
```

The script refuses to overwrite an existing installation unless `--force` is supplied with explicit paths.

## Generated files

- Binary: `/opt/twokitties/twokitties-server`
- Environment: `/etc/twokitties/server.env`
- SQLite database: `/var/lib/twokitties/twokitties.db`
- TLS certificate/key: `/var/lib/twokitties/tls/`
- Service unit: `/etc/twokitties/twokitties.service` before installation into systemd

The service reads `LISTEN_ADDR`, `DATABASE_PATH`, `TLS_CERT_PATH`, and `TLS_KEY_PATH` from the generated environment file.

## TLS warning

The setup script creates a self-signed certificate for initial testing. Replace it with a trusted certificate before exposing the server publicly. Certificate automation and reverse-proxy integration remain planned work.

## Service management

When run as root with systemd available, the installer enables the service. Start it with:

```text
sudo systemctl start twokitties
sudo systemctl status twokitties
sudo journalctl -u twokitties -f
```

The service uses a dedicated `twokitties` account when that account is available. Review the generated unit and filesystem ownership before production use.
