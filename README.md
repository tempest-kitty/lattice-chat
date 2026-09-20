# Lattice Chat

A cross-platform chat system planned as:

- `lattice-client`: Linux and Windows desktop client.
- `lattice-server`: Linux-hosted server for accounts, communities, message history, media, and federation.
- `lattice-protocol`: versioned shared protocol/domain types.

Status: foundation milestone complete. The repository is a Rust workspace with a tested account-signup validation slice. Network transport, persistent storage, authentication, encryption, federation, media, and desktop UI are not implemented yet.

## Build and test

Install Rust through rustup, then run from this directory:

```text
cargo fmt --all -- --check
cargo test --workspace
cargo build --workspace
```

Build outputs, including compiled binaries, stay under this project's `target/` directory.

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
10. Packaging and release — reproducible builds, Linux packages, Windows installer/portable build, upgrade/migration tests, security review checklist.

Each milestone must have a failing test before implementation, passing automated tests after implementation, and a documented verification result.

## Security boundary

Transport encryption and end-to-end encryption are different requirements. TLS will protect connections; E2EE will protect message contents from servers where the protocol permits it. Passwords must never be stored directly. The current signup slice intentionally defers password hashing to the authentication milestone and is not production authentication.
