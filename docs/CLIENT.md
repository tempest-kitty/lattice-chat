# TwoKitties desktop client

Produced by Kitty Dynamics.

The client performs secure login and account creation after protocol negotiation, then provides a text chat view with named-channel selection, message sending, and channel-scoped history refresh. It embeds the supplied Kitty Dynamics icon from `assets/twokittiesico.png`.

The desktop client uses Rust/eframe and is intended to build on Linux and Windows. The current client slice provides a connection screen with:

- Server address
- TLS server name
- Trusted certificate path
- Secure connect action
- Protocol connection status

The client establishes TLS, trusts the configured certificate, negotiates protocol version 1, and reports the server response.

## Linux test

Start a configured TwoKitties server, then run:

```text
cargo run -p twokitties-client
```

Use the server address, `localhost` as the TLS server name for the generated certificate, and the server certificate path.

## Windows build

The source is platform-neutral. A Windows build requires the Rust Windows target and a Windows-compatible linker/toolchain. On Linux, install a MinGW toolchain before cross-compiling:

```text
rustup target add x86_64-pc-windows-gnu
cargo build -p twokitties-client --target x86_64-pc-windows-gnu
```

The current development host has the Rust target but does not have `x86_64-w64-mingw32-gcc`; the Windows cross-check therefore stops at the native TLS dependency build. This is an environment limitation, not a client source failure.

The generated self-signed server certificate is for local testing only. Public deployments must use a trusted certificate and provide that certificate to the client through a secure provisioning flow.
