use rustls::{ClientConfig, RootCertStore, StreamOwned, pki_types::ServerName};
use rustls_pemfile::certs;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatMessage {
    pub id: i64,
    pub channel: String,
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

pub struct PersistentChatConnection {
    reader: BufReader<StreamOwned<rustls::ClientConnection, TcpStream>>,
}

impl PersistentChatConnection {
    pub fn connect_and_authenticate(
        address: SocketAddr,
        server_name: &str,
        certificate_pem: &[u8],
        username: &str,
        password: &str,
    ) -> Result<Self, String> {
        let mut tls = connect_tls(address, server_name, certificate_pem)?;
        writeln!(tls, "AUTH {username} {password}")
            .map_err(|error| format!("sending authentication failed: {error}"))?;
        let mut reader = BufReader::new(tls);
        let mut response = String::new();
        reader
            .read_line(&mut response)
            .map_err(|error| format!("reading authentication failed: {error}"))?;
        let response = response.trim_end();
        if !response.starts_with("SESSION ") {
            return Err(format!("authentication failed: {response}"));
        }
        Ok(Self { reader })
    }

    pub fn send(&mut self, channel: &str, content: &str) -> Result<i64, String> {
        writeln!(self.reader.get_mut(), "SEND {channel} {content}")
            .map_err(|error| format!("sending message failed: {error}"))?;
        let mut response = String::new();
        self.reader
            .read_line(&mut response)
            .map_err(|error| format!("reading send response failed: {error}"))?;
        let response = response.trim_end();
        let Some(id) = response.strip_prefix("SENT ") else {
            return Err(format!("message failed: {response}"));
        };
        id.parse::<i64>()
            .map_err(|error| format!("invalid message id: {error}"))
    }

    pub fn history(&mut self, channel: &str, limit: u32) -> Result<Vec<ChatMessage>, String> {
        writeln!(self.reader.get_mut(), "HISTORY {channel} {limit}")
            .map_err(|error| format!("requesting history failed: {error}"))?;
        let mut messages = Vec::new();
        loop {
            let mut line = String::new();
            self.reader
                .read_line(&mut line)
                .map_err(|error| format!("reading history failed: {error}"))?;
            let line = line.trim_end();
            if line == "END" {
                return Ok(messages);
            }
            if let Some(rest) = line.strip_prefix("ERROR ") {
                return Err(format!("history failed: {rest}"));
            }
            let parts: Vec<_> = line.splitn(7, ' ').collect();
            if parts.len() != 7 || parts[0] != "MESSAGE" {
                return Err(format!("malformed history response: {line}"));
            }
            messages.push(ChatMessage {
                id: parts[1]
                    .parse()
                    .map_err(|error| format!("invalid message id: {error}"))?,
                channel: parts[2].to_owned(),
                username: parts[3].to_owned(),
                created_at: format!("{} {}", parts[4], parts[5]),
                content: parts[6].to_owned(),
            });
        }
    }

    pub fn quit(&mut self) -> Result<(), String> {
        writeln!(self.reader.get_mut(), "QUIT")
            .map_err(|error| format!("sending quit failed: {error}"))?;
        let mut response = String::new();
        self.reader
            .read_line(&mut response)
            .map_err(|error| format!("reading quit response failed: {error}"))?;
        if response.trim_end() == "BYE" {
            Ok(())
        } else {
            Err(format!("quit failed: {}", response.trim_end()))
        }
    }
}

pub fn send_message_tls(
    address: SocketAddr,
    server_name: &str,
    certificate_pem: &[u8],
    session_token: &str,
    channel: &str,
    content: &str,
) -> Result<i64, String> {
    let mut tls = connect_tls(address, server_name, certificate_pem)?;
    writeln!(tls, "SESSION {session_token}")
        .map_err(|error| format!("starting session failed: {error}"))?;
    let mut ready = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut ready)
        .map_err(|error| format!("reading session response failed: {error}"))?;
    if ready.trim_end() != "SESSION_OK" {
        return Err(format!("session failed: {}", ready.trim_end()));
    }
    writeln!(tls, "SEND {channel} {content}")
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
    channel: &str,
    limit: u32,
) -> Result<Vec<ChatMessage>, String> {
    let mut tls = connect_tls(address, server_name, certificate_pem)?;
    writeln!(tls, "SESSION {session_token}")
        .map_err(|error| format!("starting session failed: {error}"))?;
    let mut ready = String::new();
    BufReader::new(&mut tls)
        .read_line(&mut ready)
        .map_err(|error| format!("reading session response failed: {error}"))?;
    if ready.trim_end() != "SESSION_OK" {
        return Err(format!("session failed: {}", ready.trim_end()));
    }
    writeln!(tls, "HISTORY {channel} {limit}")
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
        let parts: Vec<_> = line.splitn(7, ' ').collect();
        if parts.len() != 7 || parts[0] != "MESSAGE" {
            return Err(format!("malformed history response: {line}"));
        }
        messages.push(ChatMessage {
            id: parts[1]
                .parse()
                .map_err(|error| format!("invalid message id: {error}"))?,
            channel: parts[2].to_owned(),
            username: parts[3].to_owned(),
            created_at: format!("{} {}", parts[4], parts[5]),
            content: parts[6].to_owned(),
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
                twokitties_server::handle_persistent_chat_connection(
                    &mut tls,
                    &mut store,
                    &mut sessions,
                )
                .expect("complete chat request");
                if request == 0 {
                    assert_eq!(store.message_history("general", 10).unwrap().len(), 1);
                }
            }
        });

        let sent_id = send_message_tls(
            address,
            "localhost",
            cert_pem.as_bytes(),
            &client_token,
            "general",
            "hello from the client",
        )
        .expect("send message");
        assert_eq!(sent_id, 1);
        let history = fetch_history_tls(
            address,
            "localhost",
            cert_pem.as_bytes(),
            &client_token,
            "general",
            10,
        )
        .expect("fetch history");
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].content, "hello from the client");
        server.join().expect("server thread should finish");
        std::fs::remove_file(database_path).expect("remove test database");
    }

    #[test]
    fn persistent_chat_connection_reuses_one_authenticated_tls_stream() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();
        let server_config = Arc::new(
            twokitties_server::build_tls_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
                .expect("build server config"),
        );
        let database_path = std::env::temp_dir().join(format!(
            "twokitties-persistent-client-{}.db",
            std::process::id()
        ));
        let mut store = twokitties_server::SqliteAccountStore::open(&database_path)
            .expect("open test database");
        store
            .register(
                "tempest@example.com",
                "tempest",
                "correct horse battery staple",
            )
            .expect("register account");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let mut sessions =
                twokitties_server::SessionManager::with_ttl(std::time::Duration::from_secs(60));
            twokitties_server::handle_persistent_tls_connection(
                stream,
                server_config,
                &mut store,
                &mut sessions,
            )
            .expect("persistent server connection");
        });

        let mut connection = PersistentChatConnection::connect_and_authenticate(
            address,
            "localhost",
            cert_pem.as_bytes(),
            "tempest",
            "correct horse battery staple",
        )
        .expect("connect and authenticate");
        assert_eq!(connection.send("general", "hello once").expect("send"), 1);
        assert_eq!(connection.send("general", "hello twice").expect("send"), 2);
        assert_eq!(connection.history("general", 10).expect("history").len(), 2);
        connection.quit().expect("quit");
        server.join().expect("server thread should finish");
        std::fs::remove_file(database_path).expect("remove test database");
    }

    #[test]
    fn parses_history_message_with_timestamp_and_spaces() {
        let line = "MESSAGE 7 general tempest 2026-09-20 19:30:00 hello there";
        let parts: Vec<_> = line.splitn(7, ' ').collect();
        assert_eq!(parts.len(), 7);
        assert_eq!(parts[1], "7");
        assert_eq!(parts[2], "general");
        assert_eq!(format!("{} {}", parts[4], parts[5]), "2026-09-20 19:30:00");
        assert_eq!(parts[6], "hello there");
    }
}
