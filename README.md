# TwoKitties

Produced by Kitty Dynamics.

A cross-platform chat system planned as:

- `twokitties-client`: Linux and Windows desktop client.
- `twokitties-server`: Linux-hosted server for accounts, communities, message history, media, and federation.
- `twokitties-protocol`: versioned shared protocol/domain types.

Status: desktop client foundation complete. The Linux/Windows-oriented eframe client has a TLS connection screen and tested protocol negotiation against a TwoKitties server. Linux builds pass; Windows cross-compilation still needs a MinGW linker on this host.

## Build and test

Install Rust through rustup, then run from this directory:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo build --workspace
```

Build outputs, including compiled binaries, stay under this project's `target/` directory.

## Self-hosting

The tested Linux setup path is documented in [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md). Run `cargo build --release -p twokitties-server`, then use `scripts/setup-server.sh --yes` to install the binary, initialize SQLite, generate initial TLS material, and create a systemd unit. The desktop client workflow is documented in [`docs/CLIENT.md`](docs/CLIENT.md). The current client includes secure login and embeds the Kitty Dynamics TwoKitties icon from `assets/twokittiesico.png`.

The generated self-signed certificate is for initial testing only.
## Planned milestones

1. Foundation and repository policy — workspace, CI-quality local checks, architecture decisions.
2. Protocol and transport — versioned API over TLS-capable transport; health check and compatibility tests.
3. Identity and authentication — email/username/password signup, Argon2id password verification, sessions, rate limits, account recovery boundaries.
4. Persistent server storage — SQLite first for single-server deployment, migrations, durable users/channels/messages, history pagination and backups.
5. Core chat — servers, channels, memberships, direct messages, presence, reconnect/resume, authorization tests.
6. End-to-end encryption — device keys, authenticated key exchange, encrypted message envelopes, key rotation/revocation, metadata limitations documented.
7. Rich media — upload/download authorization, quotas, thumbnails, MIME validation, malware-scanning integration point, encrypted media keys.
8. Federation — server identity, signed server-to-server protocol, trust policy, replay protection, replication/conflict tests.
9. Desktop client — Linux/Windows UI, account flow, chat/history/media UX, secure local key storage.
10. Self-hosting and deployment — one-command setup, generated configuration, database initialization, service management, firewall/TLS certificate guidance, upgrades, backups, and uninstall/rollback tests.
11. Packaging and release — reproducible builds, Linux packages, Windows installer/portable build, upgrade/migration tests, security review checklist.

Each milestone must have a failing test before implementation, passing automated tests after implementation, and a documented verification result.

## Security boundary

Transport encryption and end-to-end encryption are different requirements. TLS will protect connections; E2EE will protect message contents from servers where the protocol permits it. Passwords must never be stored directly. The current signup slice intentionally defers password hashing to the authentication milestone and is not production authentication.
