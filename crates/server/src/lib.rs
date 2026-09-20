use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use lattice_protocol::{ClientHello, HandshakeError, negotiate};
use rand_core::OsRng;
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Write};
use std::net::TcpStream;

#[derive(Debug, PartialEq, Eq)]
pub struct Account {
    pub email: String,
    pub username: String,
    password_hash: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SignupError {
    InvalidEmail,
    InvalidUsername,
    InvalidPassword,
    PasswordHashingFailed,
}

impl Account {
    pub fn signup(email: &str, username: &str, password: &str) -> Result<Self, SignupError> {
        let email = email.trim().to_lowercase();
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

        let salt = SaltString::generate(&mut OsRng);
        let password_hash = Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map_err(|_| SignupError::PasswordHashingFailed)?
            .to_string();

        Ok(Self {
            email,
            username: username.to_owned(),
            password_hash,
        })
    }

    pub fn verify_password(&self, password: &str) -> bool {
        let Ok(hash) = PasswordHash::new(&self.password_hash) else {
            return false;
        };
        Argon2::default()
            .verify_password(password.as_bytes(), &hash)
            .is_ok()
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum RegistrationError {
    EmailAlreadyRegistered,
    UsernameAlreadyRegistered,
    Signup(SignupError),
}

pub struct AccountRegistry {
    accounts_by_username: HashMap<String, Account>,
    registered_emails: HashSet<String>,
}

impl AccountRegistry {
    pub fn new() -> Self {
        Self {
            accounts_by_username: HashMap::new(),
            registered_emails: HashSet::new(),
        }
    }

    pub fn register(
        &mut self,
        email: &str,
        username: &str,
        password: &str,
    ) -> Result<(), RegistrationError> {
        let normalized_email = email.trim().to_lowercase();
        let normalized_username = username.trim().to_owned();
        if self.registered_emails.contains(&normalized_email) {
            return Err(RegistrationError::EmailAlreadyRegistered);
        }
        if self.accounts_by_username.contains_key(&normalized_username) {
            return Err(RegistrationError::UsernameAlreadyRegistered);
        }

        let account =
            Account::signup(email, username, password).map_err(RegistrationError::Signup)?;
        self.registered_emails.insert(account.email.clone());
        self.accounts_by_username
            .insert(account.username.clone(), account);
        Ok(())
    }

    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        self.accounts_by_username
            .get(username.trim())
            .is_some_and(|account| account.verify_password(password))
    }
}

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
    fn signup_password_can_be_verified_without_exposing_the_hash() {
        let account = Account::signup(
            "person@example.com",
            "tempest",
            "a sufficiently long password",
        )
        .expect("valid signup should succeed");

        assert!(account.verify_password("a sufficiently long password"));
        assert!(!account.verify_password("the wrong password"));
    }

    #[test]
    fn account_registry_rejects_duplicate_email_and_username() {
        let mut registry = AccountRegistry::new();
        registry
            .register(
                "person@example.com",
                "tempest",
                "a sufficiently long password",
            )
            .expect("first account should register");

        assert_eq!(
            registry.register("person@example.com", "another", "another long password"),
            Err(RegistrationError::EmailAlreadyRegistered)
        );
        assert_eq!(
            registry.register("other@example.com", "tempest", "another long password"),
            Err(RegistrationError::UsernameAlreadyRegistered)
        );
    }

    #[test]
    fn account_registry_authenticates_valid_credentials() {
        let mut registry = AccountRegistry::new();
        registry
            .register(
                "person@example.com",
                "tempest",
                "a sufficiently long password",
            )
            .expect("account should register");

        assert!(registry.authenticate("tempest", "a sufficiently long password"));
        assert!(!registry.authenticate("tempest", "wrong password"));
        assert!(!registry.authenticate("missing", "a sufficiently long password"));
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
