# TwoKitties build log

## 2026-09-20

### Verified

- Created Rust workspace at `/home/tempest/Projects/twokitties/`.
- Added `twokitties-protocol`, `twokitties-server`, and `twokitties-client` crates.
- Added initial server-side signup validation domain slice.
- Followed RED-GREEN cycle: signup test initially failed because the domain types were absent; implementation was then added.
- `cargo fmt --all` completed.
- `cargo test --workspace` passed: 3 server tests plus empty crate/doc test suites.
- `cargo build --workspace` passed.
- Added protocol version 1 negotiation types and unsupported-version rejection.
- Added server loopback TCP handshake handling.
- Added loopback tests for accepted and rejected protocol versions.
- Added Argon2id password hashing and verification.
- Added in-memory duplicate email/username protection and credential authentication tests.
- Added SQLite account schema initialization and durable account storage.
- Added restart persistence and SQLite duplicate/credential tests.
- Added opaque session tokens with configurable expiry and revocation.
- Added authenticated request authorization checks for valid sessions.
- Added AUTH request handling against SQLite credentials.
- Added valid-login session issuance and invalid-login rejection tests.
- Added TLS PEM certificate/key loading and client trust configuration.
- Added encrypted loopback handshake and authenticated-login integration test.
- Added tested Linux self-hosting setup script with generated config, SQLite initialization, TLS material, systemd unit, dedicated service-account handling, and overwrite protection.
- Added deployment documentation and isolated setup-script test.
- Wired the server binary to generated environment configuration and TLS/SQLite paths.
- Added release-binary deployment smoke test covering startup and TLS protocol negotiation.
- Full workspace verification passed: 20 Rust tests plus setup-script, deployment-smoke, and doc/empty-crate checks.
- Compiled outputs remain under `/home/tempest/Projects/twokitties/target/`.
- Created public GitHub repository: `https://github.com/tempest-kitty/twokitties`.
- Configured `origin`, committed the foundation as `a359d46c4727`, pushed `main`, and verified the remote `main` commit through GitHub's API.

- Configured persistent GitHub authentication through `/home/tempest/.local/bin/git-credential-github-secret`, backed by the Linux Secret Service keyring.
- Verified the keyring entry exists and `git ls-remote origin HEAD` succeeds without an interactive prompt.

### Not implemented yet

Network transport, TLS, password hashing, persistent storage, chat history, E2EE, media, federation, desktop UI, packaging, and CI.

### Security note

The current account object deliberately does not retain the supplied password. Its verifier is a placeholder enum and must be replaced with Argon2id-based storage before any authentication endpoint is exposed.
