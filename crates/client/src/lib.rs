use rustls::{ClientConfig, RootCertStore, StreamOwned, pki_types::ServerName};
use rustls_pemfile::certs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub id: i64,
    pub username: String,
    pub created_at: String,
    pub content: String,
}

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

fn connect_tls(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
) -> Result<StreamOwned<rustls::ClientConnection, TcpStream>, String> {
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
    Ok(tls)
}

pub fn send_message_tls(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
    session_token: &str,
    content: &str,
) -> Result<i64, String> {
    let mut tls = connect_tls(address, server_name, certificate_pem)?;
    writeln!(tls, "SEND {session_token} {content}")
        .map_err(|error| format!("sending message failed: {error}"))?;
    let mut response = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut response)
        .map_err(|error| format!("reading send response failed: {error}"))?;
    let response = response.trim_end();
    let Some(id) = response.strip_prefix("SENT ") else {
        return Err(format!("message failed: {response}"));
    };
    id.parse::<i64>()
        .map_err(|error| format!("invalid message id: {error}"))
}

pub fn fetch_history_tls(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
    session_token: &str,
    limit: u32,
) -> Result<Vec<ChatMessage>, String> {
    let mut tls = connect_tls(address, server_name, certificate_pem)?;
    writeln!(tls, "HISTORY {session_token} {limit}")
        .map_err(|error| format!("requesting history failed: {error}"))?;
    let mut reader = BufReader::new(&mut tls);
    let mut messages = Vec::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|error| format!("reading history failed: {error}"))?;
        let line = line.trim_end();
        if line == "END" {
            return Ok(messages);
        }
        if let Some(rest) = line.strip_prefix("ERROR ") {
            return Err(format!("history failed: {rest}"));
        }
        let parts: Vec<_> = line.splitn(6, ' ').collect();
        if parts.len() != 6 || parts[0] != "MESSAGE" {
            return Err(format!("malformed history response: {line}"));
        }
        messages.push(ChatMessage {
            id: parts[1]
                .parse()
                .map_err(|error| format!("invalid message id: {error}"))?,
            username: parts[2].to_owned(),
            created_at: format!("{} {}", parts[3], parts[4]),
            content: parts[5].to_owned(),
        });
    }
}

pub fn connect_tls_and_handshake(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
) -> Result<String, String> {
    let mut tls = connect_tls(address, server_name, certificate_pem)?;
    let mut response = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut response)
        .map_err(|error| format!("reading handshake failed: {error}"))?;
    Ok(response.trim_end().to_owned())
}

pub fn connect_tls_and_authenticate(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
    username: &str,
    password: &str,
) -> Result<String, String> {
    let mut tls = connect_tls(address, server_name, certificate_pem)?;
    writeln!(tls, "AUTH {username} {password}")
        .map_err(|error| format!("sending authentication failed: {error}"))?;
    let mut response = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut response)
        .map_err(|error| format!("reading authentication failed: {error}"))?;
    let response = response.trim_end().to_owned();
    if !response.starts_with("SESSION ") {
        return Err(format!("authentication failed: {response}"));
    }
    Ok(response.trim_start_matches("SESSION ").to_owned())
}

pub fn register_tls_account(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
    email: &str,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let mut tls = connect_tls(address, server_name, certificate_pem)?;
    writeln!(tls, "SIGNUP {email} {username} {password}")
        .map_err(|error| format!("sending signup failed: {error}"))?;
    let mut response = String::new();
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
    use std::sync::Arc;
    use std::thread;

    #[test]
    fn client_sends_and_fetches_authenticated_chat_history() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();
        let server_config = Arc::new(
            twokitties_server::build_tls_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
                .expect("build server config"),
        );
        let database_path =
            std::env::temp_dir().join(format!("twokitties-client-chat-{}.db", std::process::id()));
        let mut store = twokitties_server::SqliteAccountStore::open(&database_path)
            .expect("open test database");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let mut sessions =
            twokitties_server::SessionManager::with_ttl(std::time::Duration::from_secs(60));
        let token = sessions.issue("tempest");
        let client_token = token.clone();
        let server = thread::spawn(move || {
            for request in 0..2 {
                let (stream, _) = listener.accept().expect("accept client");
                let connection = rustls::ServerConnection::new(Arc::clone(&server_config))
                    .expect("create server TLS connection");
                let mut tls = rustls::StreamOwned::new(connection, stream);
                twokitties_server::handle_handshake(&mut tls).expect("complete handshake");
                twokitties_server::handle_chat_request(&mut tls, &mut store, &mut sessions)
                    .expect("complete chat request");
                if request == 0 {
                    assert_eq!(store.message_history(10).unwrap().len(), 1);
                }
            }
        });

        let sent_id = send_message_tls(
            address,
            "localhost",
            cert_pem.as_bytes(),
            &client_token,
            "hello from the client",
        )
        .expect("send message");
        assert_eq!(sent_id, 1);
        let history =
            fetch_history_tls(address, "localhost", cert_pem.as_bytes(), &client_token, 10)
                .expect("fetch history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "hello from the client");
        server.join().expect("server thread should finish");
        std::fs::remove_file(database_path).expect("remove test database");
    }

    #[test]
    fn parses_history_message_with_timestamp_and_spaces() {
        let line = "MESSAGE 7 tempest 2026-09-20 19:30:00 hello there";
        let parts: Vec<_> = line.splitn(6, ' ').collect();
        assert_eq!(parts.len(), 6);
        assert_eq!(parts[1], "7");
        assert_eq!(format!("{} {}", parts[3], parts[4]), "2026-09-20 19:30:00");
        assert_eq!(parts[5], "hello there");
    }
}
