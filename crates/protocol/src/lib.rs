pub const PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u16,
}

impl ClientHello {
    pub const fn new(version: u16) -> Self {
        Self { version }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u16,
    pub accepted: bool,
}

impl ServerHello {
    pub const fn ready(version: u16) -> Self {
        Self {
            version,
            accepted: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeError {
    UnsupportedVersion(u16),
}

pub fn negotiate(client: ClientHello) -> Result<ServerHello, HandshakeError> {
    if client.version == PROTOCOL_VERSION {
        Ok(ServerHello::ready(PROTOCOL_VERSION))
    } else {
        Err(HandshakeError::UnsupportedVersion(client.version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compatible_client_version_produces_ready_response() {
        let hello = ClientHello::new(PROTOCOL_VERSION);

        assert_eq!(negotiate(hello), Ok(ServerHello::ready(PROTOCOL_VERSION)));
    }

    #[test]
    fn unsupported_client_version_is_rejected() {
        let hello = ClientHello::new(PROTOCOL_VERSION + 1);

        assert_eq!(
            negotiate(hello),
            Err(HandshakeError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );
    }
}
