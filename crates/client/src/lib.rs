use rustls::{ClientConfig, RootCertStore, StreamOwned, pki_types::ServerName};
use rustls_pemfile::certs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

pub fn build_client_config(certificate_pem: &[u8]) -> Result<ClientConfig, String> {
    let mut reader = BufReader::new(certificate_pem);
    let certificates = certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid certificate PEM: {error}"))?;
    if certificates.is_empty() {
        return Err("certificate PEM contained no certificates".to_owned());
    }

    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| format!("invalid root certificate: {error}"))?;
    }

    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

pub fn connect_tls_and_handshake(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
) -> Result<String, String> {
    let config = Arc::new(build_client_config(certificate_pem)?);
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| format!("invalid server name: {error}"))?;
    let connection = rustls::ClientConnection::new(config, name)
        .map_err(|error| format!("TLS client setup failed: {error}"))?;
    let stream =
        TcpStream::connect(address).map_err(|error| format!("connection failed: {error}"))?;
    let mut tls = StreamOwned::new(connection, stream);
    writeln!(tls, "HELLO {}", twokitties_protocol::PROTOCOL_VERSION)
        .map_err(|error| format!("sending handshake failed: {error}"))?;

    let mut response = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut response)
        .map_err(|error| format!("reading handshake failed: {error}"))?;
    let response = response.trim_end().to_owned();
    if response != format!("READY {}", twokitties_protocol::PROTOCOL_VERSION) {
        return Err(format!("server rejected protocol: {response}"));
    }
    Ok(response)
}

pub fn connect_tls_and_authenticate(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
    username: &str,
    password: &str,
) -> Result<String, String> {
    let config = Arc::new(build_client_config(certificate_pem)?);
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| format!("invalid server name: {error}"))?;
    let connection = rustls::ClientConnection::new(config, name)
        .map_err(|error| format!("TLS client setup failed: {error}"))?;
    let stream =
        TcpStream::connect(address).map_err(|error| format!("connection failed: {error}"))?;
    let mut tls = StreamOwned::new(connection, stream);

    writeln!(tls, "HELLO {}", twokitties_protocol::PROTOCOL_VERSION)
        .map_err(|error| format!("sending handshake failed: {error}"))?;
    let mut handshake_response = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut handshake_response)
        .map_err(|error| format!("reading handshake failed: {error}"))?;
    let expected = format!("READY {}", twokitties_protocol::PROTOCOL_VERSION);
    if handshake_response.trim_end() != expected {
        return Err(format!(
            "server rejected protocol: {}",
            handshake_response.trim_end()
        ));
    }

    writeln!(tls, "AUTH {username} {password}")
        .map_err(|error| format!("sending authentication failed: {error}"))?;
    let mut authentication_response = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut authentication_response)
        .map_err(|error| format!("reading authentication failed: {error}"))?;
    let response = authentication_response.trim_end().to_owned();
    if !response.starts_with("SESSION ") {
        return Err(format!("authentication failed: {response}"));
    }
    Ok(response)
}
pub fn register_tls_account(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
    email: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let config = Arc::new(build_client_config(certificate_pem)?);
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|error| format!("invalid server name: {error}"))?;
    let connection = rustls::ClientConnection::new(config, name)
        .map_err(|error| format!("TLS client setup failed: {error}"))?;
    let stream =
        TcpStream::connect(address).map_err(|error| format!("connection failed: {error}"))?;
    let mut tls = StreamOwned::new(connection, stream);

    writeln!(tls, "HELLO {}", twokitties_protocol::PROTOCOL_VERSION)
        .map_err(|error| format!("sending handshake failed: {error}"))?;
    let mut response = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut response)
        .map_err(|error| format!("reading handshake failed: {error}"))?;
    let expected = format!("READY {}", twokitties_protocol::PROTOCOL_VERSION);
    if response.trim_end() != expected {
        return Err(format!("server rejected protocol: {}", response.trim_end()));
    }

    writeln!(tls, "SIGNUP {email} {username} {password}")
        .map_err(|error| format!("sending signup failed: {error}"))?;
    response.clear();
    BufReader::new(&mut tls)
        .read_line(&mut response)
        .map_err(|error| format!("reading signup response failed: {error}"))?;
    let response = response.trim_end().to_owned();
    if !response.starts_with("REGISTERED ") {
        return Err(format!("signup failed: {response}"));
    }
    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use twokitties_protocol::PROTOCOL_VERSION;

    #[test]
    fn client_connects_to_tls_server_and_negotiates_protocol() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();
        let server_config = Arc::new(
            twokitties_server::build_tls_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
                .expect("build server config"),
        );
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let connection =
                rustls::ServerConnection::new(server_config).expect("create server TLS connection");
            let mut tls = rustls::StreamOwned::new(connection, stream);
            twokitties_server::handle_handshake(&mut tls).expect("complete handshake");
        });

        let response = connect_tls_and_handshake(address, "localhost", cert_pem.as_bytes())
            .expect("client should connect");
        assert_eq!(response, format!("READY {PROTOCOL_VERSION}"));
        server.join().expect("server thread should finish");
    }

    #[test]
    fn client_registers_account_over_tls() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();
        let server_config = Arc::new(
            twokitties_server::build_tls_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
                .expect("build server config"),
        );
        let database_path = std::env::temp_dir().join(format!(
            "twokitties-client-signup-{}.db",
            std::process::id()
        ));
        let mut store = twokitties_server::SqliteAccountStore::open(&database_path)
            .expect("open test database");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let connection =
                rustls::ServerConnection::new(server_config).expect("create server TLS connection");
            let mut tls = rustls::StreamOwned::new(connection, stream);
            twokitties_server::handle_handshake(&mut tls).expect("complete handshake");
            let mut sessions =
                twokitties_server::SessionManager::with_ttl(std::time::Duration::from_secs(60));
            twokitties_server::handle_account_request(&mut tls, &mut store, &mut sessions)
                .expect("complete signup");
            assert!(store.authenticate("tempest", "correct horse battery staple"));
        });

        let response = register_tls_account(
            address,
            "localhost",
            cert_pem.as_bytes(),
            "tempest@example.com",
            "tempest",
            "correct horse battery staple",
        )
        .expect("client should register");
        assert_eq!(response, "REGISTERED tempest");
        server.join().expect("server thread should finish");
        std::fs::remove_file(database_path).expect("remove test database");
    }

    #[test]
    fn client_authenticates_over_the_negotiated_tls_connection() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();
        let server_config = Arc::new(
            twokitties_server::build_tls_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
                .expect("build server config"),
        );
        let database_path =
            std::env::temp_dir().join(format!("twokitties-client-auth-{}.db", std::process::id()));
        let mut store = twokitties_server::SqliteAccountStore::open(&database_path)
            .expect("open test database");
        store
            .register(
                "tempest@example.com",
                "tempest",
                "correct horse battery staple",
            )
            .expect("register test account");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let connection =
                rustls::ServerConnection::new(server_config).expect("create server TLS connection");
            let mut tls = rustls::StreamOwned::new(connection, stream);
            twokitties_server::handle_handshake(&mut tls).expect("complete handshake");
            let mut sessions =
                twokitties_server::SessionManager::with_ttl(std::time::Duration::from_secs(60));
            twokitties_server::handle_auth_request(&mut tls, &store, &mut sessions)
                .expect("complete authentication");
        });

        let response = connect_tls_and_authenticate(
            address,
            "localhost",
            cert_pem.as_bytes(),
            "tempest",
            "correct horse battery staple",
        )
        .expect("client should authenticate");
        assert!(response.starts_with("SESSION "));
        server.join().expect("server thread should finish");
        std::fs::remove_file(database_path).expect("remove test database");
    }
}
