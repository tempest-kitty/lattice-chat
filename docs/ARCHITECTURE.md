# Lattice Chat architecture

## Components

`lattice-client` is the user-facing Linux/Windows application. It owns presentation, local session state, device keys, encrypted local cache, and media UX.

`lattice-server` is the Linux service. It owns account records, authorization, channels, encrypted message envelopes, history persistence, media metadata/object access, and federation connections.

`lattice-protocol` is the shared versioned contract. It must contain serializable wire types and capability/version negotiation, not UI or database code.

## Security model

- TLS protects client-server and server-server transport.
- Passwords are stored only as slow password verifiers, never plaintext.
- E2EE message payloads are encrypted on clients; servers persist ciphertext and required routing metadata.
- Device identity keys are separate from account credentials.
- Every server-to-server operation is authenticated, authorized, versioned, and replay-resistant.
- Media uses separately authorized objects and encrypted media keys.

- Self-hosting is a first-class requirement: setup must be easy for non-developers, repeatable, documented, and tested on a clean Linux machine.
- Deployment must generate explicit configuration, initialize storage safely, support service management, explain TLS certificates, and provide backup/upgrade/rollback paths.

## Delivery order

Implement one vertical slice at a time: test, minimal implementation, integration test, documentation. Do not add federation or media before single-server identity, authorization, and durable history are reliable.

