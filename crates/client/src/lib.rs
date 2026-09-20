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
    fn client_rejects_invalid_trust_certificate() {
        let result = build_client_config(b"not a certificate");
        assert!(result.is_err());
    }
}
