#[derive(Debug, PartialEq, Eq)]
pub struct Account {
    pub email: String,
    pub username: String,
    password_verifier: PasswordVerifier,
}

#[derive(Debug, PartialEq, Eq)]
enum PasswordVerifier {
    DeferredToAuthenticationMilestone,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignupError {
    InvalidEmail,
    InvalidUsername,
    InvalidPassword,
}

impl Account {
    pub fn signup(email: &str, username: &str, password: &str) -> Result<Self, SignupError> {
        let email = email.trim();
        let username = username.trim();

        if !email.contains('@') || email.starts_with('@') || email.ends_with('@') {
            return Err(SignupError::InvalidEmail);
        }
        if username.len() < 3 || username.len() > 32 {
            return Err(SignupError::InvalidUsername);
        }
        if password.chars().count() < 12 {
            return Err(SignupError::InvalidPassword);
        }

        Ok(Self {
            email: email.to_owned(),
            username: username.to_owned(),
            password_verifier: PasswordVerifier::DeferredToAuthenticationMilestone,
        })
    }
}

use lattice_protocol::{ClientHello, HandshakeError, negotiate};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;

pub fn handle_handshake(stream: &mut TcpStream) -> io::Result<()> {
    let mut line = String::new();
    BufReader::new(stream.try_clone()?).read_line(&mut line)?;
    let mut fields = line.split_whitespace();

    let version = match (
        fields.next(),
        fields.next().and_then(|value| value.parse().ok()),
    ) {
        (Some("HELLO"), Some(version)) => version,
        _ => {
            writeln!(stream, "ERROR malformed_hello")?;
            return Ok(());
        }
    };

    match negotiate(ClientHello::new(version)) {
        Ok(server_hello) => writeln!(stream, "READY {}", server_hello.version),
        Err(HandshakeError::UnsupportedVersion(version)) => {
            writeln!(stream, "ERROR unsupported_version {version}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lattice_protocol::PROTOCOL_VERSION;
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    #[test]
    fn signup_accepts_valid_account_details() {
        let account = Account::signup(
            "person@example.com",
            "tempest",
            "a sufficiently long password",
        )
        .expect("valid signup should succeed");

        assert_eq!(account.email, "person@example.com");
        assert_eq!(account.username, "tempest");
    }

    #[test]
    fn signup_rejects_invalid_email() {
        let result = Account::signup("not-an-email", "tempest", "a sufficiently long password");
        assert_eq!(result, Err(SignupError::InvalidEmail));
    }

    #[test]
    fn signup_rejects_short_password_without_storing_it() {
        let result = Account::signup("person@example.com", "tempest", "short");
        assert_eq!(result, Err(SignupError::InvalidPassword));
    }

    #[test]
    fn loopback_handshake_accepts_supported_version() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            handle_handshake(&mut stream).expect("complete handshake")
        });

        let mut client = TcpStream::connect(address).expect("connect to server");
        writeln!(client, "HELLO {PROTOCOL_VERSION}").expect("send hello");
        let mut response = String::new();
        BufReader::new(client)
            .read_line(&mut response)
            .expect("read response");

        assert_eq!(response, format!("READY {PROTOCOL_VERSION}\n"));
        server.join().expect("server thread should finish");
    }

    #[test]
    fn loopback_handshake_rejects_unsupported_version() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
        let address = listener.local_addr().expect("read listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            handle_handshake(&mut stream).expect("complete rejection")
        });

        let mut client = TcpStream::connect(address).expect("connect to server");
        writeln!(client, "HELLO {}", PROTOCOL_VERSION + 1).expect("send hello");
        let mut response = String::new();
        BufReader::new(client)
            .read_line(&mut response)
            .expect("read response");

        assert_eq!(
            response,
            format!("ERROR unsupported_version {}\n", PROTOCOL_VERSION + 1)
        );
        server.join().expect("server thread should finish");
    }
}
