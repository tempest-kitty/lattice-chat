# TwoKitties build log

Produced by Kitty Dynamics.

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
- Added eframe desktop client foundation with server address, TLS server name, trusted certificate, and secure connect workflow.
- Added client TLS loopback integration tests against the TwoKitties server.
- Linux workspace tests and client build passed; Windows cross-check is blocked by missing `x86_64-w64-mingw32-gcc` on this host.
- Added client TLS authentication and session-token retention in the desktop client.
- Embedded the supplied `assets/twokittiesico.png` icon in the native application window.
- Added client TLS account creation with server-side validation and duplicate-identity errors.
- Added desktop signup mode with email, username, and password fields.
- Added client/server TLS signup integration test.
- Added persistent SQLite message storage with sender, content, ID, and timestamp.
- Added authenticated `SEND` and `HISTORY` requests on the TLS listener.
- Added desktop post-login chat view with history refresh, message sending, and logout.
- Added named channel storage and channel-scoped history queries, with migration support for existing message tables.
- Updated authenticated `SEND` and `HISTORY` requests to include a channel.
- Added a desktop channel selector for post-login chat.
- Full workspace verification passed: 25 Rust tests.
- Compiled outputs remain under `/home/tempest/Projects/twokitties/target/`.
- Created public GitHub repository: `https://github.com/tempest-kitty/twokitties`.
- Renamed the product from Lattice Chat to TwoKitties and attributed it to Kitty Dynamics.
- Renamed Rust crates, binaries, setup paths, and deployment files to `twokitties-*` naming.
- Configured `origin`, committed the foundation as `a359d46c4727`, pushed `main`, and verified the remote `main` commit through GitHub's API.

- Configured persistent GitHub authentication through `/home/tempest/.local/bin/git-credential-github-secret`, backed by the Linux Secret Service keyring.
- Verified the keyring entry exists and `git ls-remote origin HEAD` succeeds without an interactive prompt.

### Remaining work

Chat history, E2EE, media, federation, desktop UI, trusted certificate automation, packaging, public service hardening, and CI remain.

### Persistent authenticated chat connection milestone

- Added a persistent TLS chat handler that authenticates once and accepts repeated `SEND`, `HISTORY`, and `QUIT` commands.
- Added `SESSION <token>` connection resumption for existing authenticated client operations.
- Added clean handling for normal TLS peer disconnects.
- Updated the production server listener and client chat helpers to use the persistent framing.
- Added an integration test covering one connection handling multiple authenticated commands.
- Workspace verification passed: 26 tests; release build passed.

### Desktop live chat connection milestone

- Added a client `PersistentChatConnection` that authenticates once and reuses one TLS stream for multiple sends, history reads, and quit.
- Added a background chat worker to the eframe client so network I/O does not block the UI thread.
- Added two-second channel-history polling and UI-safe message/error events.
- Logout now requests a clean persistent connection shutdown.
- Added a RED-GREEN integration test covering two sends and history retrieval over one authenticated TLS connection.
- Workspace verification passed: 27 tests; release workspace build passed.

### Security note

Passwords use Argon2id hashes. The generated setup certificate is self-signed for initial testing only and must be replaced before public deployment.
