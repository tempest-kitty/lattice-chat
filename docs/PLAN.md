# Lattice Chat plan

## Confirmed scope

- New project root: `/home/tempest/Projects/lattice-chat/`.
- Client targets Linux and Windows.
- Server target Linux.
- Servers can federate into a network.
- Client/server communication must be encrypted.
- Rich media sharing is required.
- Server stores message history.
- Signup requires email address, username, and password.
- Compiled artifacts remain inside the project root under `target/`.

## Architecture direction

Use a Rust workspace so protocol/domain code is shared without duplicating security-sensitive rules. Keep the server and client as separate crates. Start with a server-side domain slice, then add transport and persistence behind tested interfaces. Use established cryptographic libraries rather than designing cryptography from primitives.

Initial storage choice: SQLite for the first deployable server, with a storage trait to leave room for PostgreSQL later. Federation is deferred until single-server behavior and authorization are stable.

## Milestones and gates

1. Foundation: workspace builds; signup validation tests pass.
2. Protocol/transport: loopback integration test and protocol version negotiation pass; TLS configuration is explicit.
3. Authentication: password hashing/verification, duplicate identity handling, session expiry, and abuse controls pass tests.
4. Storage/history: migrations, restart durability, pagination, and authorization pass tests.
5. Chat: channel/message flows, reconnect, ordering, and membership checks pass tests.
6. E2EE: key lifecycle and encrypted envelope tests pass; no plaintext message content required by server.
7. Media: authorized upload/download, limits, and encrypted media-key handling pass tests.
8. Federation: signed peer authentication, replay protection, and replication consistency pass tests.
9. Client: Linux and Windows builds, UI smoke tests, and secure key storage checks pass.
10. Self-hosting/deployment: one-command setup, generated config, database initialization, service management, TLS certificate guidance, backups, upgrades, and rollback tests pass.
11. Release: packaging, upgrade, backup/restore, uninstall, and security checklist pass.

## Open decisions

- Desktop UI toolkit: Tauri versus a Rust-native toolkit.
- Federation topology and trust model.
- Whether server-side search/moderation requires an explicit opt-in capability that is incompatible with strict E2EE.
- Initial media object storage: local filesystem versus S3-compatible backend.
- Account email verification and password reset provider.

## Current status

Self-hosting setup milestone complete. The Linux server binary reads generated environment configuration, initializes SQLite, serves TLS, and is installable through the tested setup script and systemd unit generation path. Trusted certificate automation, persistent sessions, and public service hardening remain.
