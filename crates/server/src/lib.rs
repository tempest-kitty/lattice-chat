use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use lattice_protocol::{ClientHello, HandshakeError, negotiate};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension};
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
    Storage(String),
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

pub struct SqliteAccountStore {
    connection: Connection,
}

impl SqliteAccountStore {
    pub fn open(path: impl AsRef<std::path::Path>) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;
        connection.execute_batch(
            "CREATE TABLE IF NOT EXISTS accounts (
                id INTEGER PRIMARY KEY,
                email TEXT NOT NULL UNIQUE,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );",
        )?;
        Ok(Self { connection })
    }

    pub fn register(
        &mut self,
        email: &str,
        username: &str,
        password: &str,
    ) -> Result<(), RegistrationError> {
        let normalized_email = email.trim().to_lowercase();
        let normalized_username = username.trim();
        let email_exists: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE email = ?1)",
                [&normalized_email],
                |row| row.get(0),
            )
            .map_err(|error| RegistrationError::Storage(error.to_string()))?;
        if email_exists {
            return Err(RegistrationError::EmailAlreadyRegistered);
        }

        let username_exists: bool = self
            .connection
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM accounts WHERE username = ?1)",
                [normalized_username],
                |row| row.get(0),
            )
            .map_err(|error| RegistrationError::Storage(error.to_string()))?;
        if username_exists {
            return Err(RegistrationError::UsernameAlreadyRegistered);
        }

        let account =
            Account::signup(email, username, password).map_err(RegistrationError::Signup)?;
        self.connection
            .execute(
                "INSERT INTO accounts (email, username, password_hash) VALUES (?1, ?2, ?3)",
                (&account.email, &account.username, &account.password_hash),
            )
            .map_err(|error| RegistrationError::Storage(error.to_string()))?;
        Ok(())
    }

    pub fn authenticate(&self, username: &str, password: &str) -> bool {
        let hash = self
            .connection
            .query_row(
                "SELECT password_hash FROM accounts WHERE username = ?1",
                [username.trim()],
                |row| row.get::<_, String>(0),
            )
            .optional();
        match hash {
            Ok(Some(hash)) => Account {
                email: String::new(),
                username: username.trim().to_owned(),
                password_hash: hash,
            }
            .verify_password(password),
            _ => false,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct AuthenticatedRequest {
    pub username: String,
    pub command: String,
}

struct Session {
    username: String,
    expires_at: std::time::Instant,
}

pub struct SessionManager {
    sessions: HashMap<String, Session>,
    ttl: std::time::Duration,
}

impl SessionManager {
    pub fn with_ttl(ttl: std::time::Duration) -> Self {
        Self {
            sessions: HashMap::new(),
            ttl,
        }
    }

    pub fn issue(&mut self, username: &str) -> String {
        loop {
            let mut bytes = [0_u8; 32];
            OsRng.fill_bytes(&mut bytes);
            let token: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
            if !self.sessions.contains_key(&token) {
                self.sessions.insert(
                    token.clone(),
                    Session {
                        username: username.to_owned(),
                        expires_at: std::time::Instant::now() + self.ttl,
                    },
                );
                return token;
            }
        }
    }

    pub fn validate(&mut self, token: &str) -> Option<String> {
        self.validate_at(token, std::time::Instant::now())
    }

    pub fn validate_at(&mut self, token: &str, now: std::time::Instant) -> Option<String> {
        let session = self.sessions.get(token)?;
        if now >= session.expires_at {
            self.sessions.remove(token);
            return None;
        }
        Some(session.username.clone())
    }

    pub fn revoke(&mut self, token: &str) {
        self.sessions.remove(token);
    }
}

pub fn authorize_request(
    sessions: &mut SessionManager,
    token: &str,
    command: &str,
    now: std::time::Instant,
) -> Option<AuthenticatedRequest> {
    if command.trim().is_empty() {
        return None;
    }
    sessions
        .validate_at(token, now)
        .map(|username| AuthenticatedRequest {
            username,
            command: command.to_owned(),
        })
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
    fn sqlite_accounts_survive_reopening_the_database() {
        let path = test_database_path("reopen");
        {
            let mut store = SqliteAccountStore::open(&path).expect("open database");
            store
                .register(
                    "person@example.com",
                    "tempest",
                    "a sufficiently long password",
                )
                .expect("register account");
        }

        let reopened = SqliteAccountStore::open(&path).expect("reopen database");
        assert!(reopened.authenticate("tempest", "a sufficiently long password"));
        assert!(!reopened.authenticate("tempest", "wrong password"));
        remove_test_database(&path);
    }

    #[test]
    fn sqlite_accounts_reject_duplicate_email_and_username() {
        let path = test_database_path("duplicates");
        let mut store = SqliteAccountStore::open(&path).expect("open database");
        store
            .register(
                "person@example.com",
                "tempest",
                "a sufficiently long password",
            )
            .expect("register account");

        assert_eq!(
            store.register("person@example.com", "another", "another long password"),
            Err(RegistrationError::EmailAlreadyRegistered)
        );
        assert_eq!(
            store.register("other@example.com", "tempest", "another long password"),
            Err(RegistrationError::UsernameAlreadyRegistered)
        );
        remove_test_database(&path);
    }

    fn test_database_path(label: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("lattice-chat-{label}-{}.db", std::process::id()))
    }

    fn remove_test_database(path: &std::path::Path) {
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sessions_validate_before_expiry_and_expire_after_ttl() {
        let start = std::time::Instant::now();
        let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
        let token = sessions.issue("tempest");

        assert_eq!(
            sessions.validate_at(&token, start),
            Some("tempest".to_owned())
        );
        assert_eq!(
            sessions.validate_at(&token, start + std::time::Duration::from_secs(61)),
            None
        );
    }

    #[test]
    fn revoked_sessions_cannot_authorize_requests() {
        let start = std::time::Instant::now();
        let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
        let token = sessions.issue("tempest");
        sessions.revoke(&token);

        assert_eq!(
            authorize_request(&mut sessions, &token, "LIST_CHANNELS", start),
            None
        );
    }

    #[test]
    fn valid_session_authorizes_request_for_its_user() {
        let start = std::time::Instant::now();
        let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
        let token = sessions.issue("tempest");

        assert_eq!(
            authorize_request(&mut sessions, &token, "LIST_CHANNELS", start),
            Some(AuthenticatedRequest {
                username: "tempest".to_owned(),
                command: "LIST_CHANNELS".to_owned(),
            })
        );
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
