# Self-hosting Lattice Chat

The current Linux setup path installs the server binary, initializes SQLite, generates local TLS material, writes an environment file, and generates a systemd unit.

## Build and install

From the repository root:

```text
cargo build --release -p lattice-server
sudo scripts/setup-server.sh --yes \
  --server-binary target/release/lattice-server
```

For a non-root dry installation or test directory:

```text
scripts/setup-server.sh --yes --no-systemd \
  --server-binary target/release/lattice-server \
  --install-dir ./run/install \
  --data-dir ./run/data \
  --config-dir ./run/config
```

The script refuses to overwrite an existing installation unless `--force` is supplied with explicit paths.

## Generated files

- Binary: `/opt/lattice-chat/lattice-server`
- Environment: `/etc/lattice-chat/server.env`
- SQLite database: `/var/lib/lattice-chat/lattice-chat.db`
- TLS certificate/key: `/var/lib/lattice-chat/tls/`
- Service unit: `/etc/lattice-chat/lattice-chat.service` before installation into systemd

The service reads `LISTEN_ADDR`, `DATABASE_PATH`, `TLS_CERT_PATH`, and `TLS_KEY_PATH` from the generated environment file.

## TLS warning

The setup script creates a self-signed certificate for initial testing. Replace it with a trusted certificate before exposing the server publicly. Certificate automation and reverse-proxy integration remain planned work.

## Service management

When run as root with systemd available, the installer enables the service. Start it with:

```text
sudo systemctl start lattice-chat
sudo systemctl status lattice-chat
sudo journalctl -u lattice-chat -f
```

The service uses a dedicated `lattice-chat` account when that account is available. Review the generated unit and filesystem ownership before production use.
