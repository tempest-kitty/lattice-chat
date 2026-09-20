use argon2::Argon2;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use rand_core::{OsRng, RngCore};
use rusqlite::{Connection, OptionalExtension};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::PrivateKeyDer,
};
use rustls_pemfile::{certs, private_key};
use std::collections::{HashMap, HashSet};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use twokitties_protocol::{ClientHello, HandshakeError, negotiate};

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

pub struct MessageRecord {
    pub id: i64,
    pub username: String,
    pub content: String,
    pub created_at: String,
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
            );
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
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

    pub fn store_message(&mut self, username: &str, content: &str) -> Result<i64, String> {
        let content = content.trim();
        if content.is_empty() {
            return Err("message_empty".to_owned());
        }
        if content.chars().count() > 4_000 {
            return Err("message_too_long".to_owned());
        }
        self.connection
            .execute(
                "INSERT INTO messages (username, content) VALUES (?1, ?2)",
                [username.trim(), content],
            )
            .map_err(|error| error.to_string())?;
        Ok(self.connection.last_insert_rowid())
    }

    pub fn message_history(&self, limit: u32) -> rusqlite::Result<Vec<MessageRecord>> {
        let mut statement = self.connection.prepare(
            "SELECT id, username, content, created_at FROM messages ORDER BY id ASC LIMIT ?1",
        )?;
        let rows = statement.query_map([limit], |row| {
            Ok(MessageRecord {
                id: row.get(0)?,
                username: row.get(1)?,
                content: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        rows.collect()
    }
}

pub fn build_tls_server_config(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
) -> Result<ServerConfig, String> {
    let mut certificate_reader = std::io::BufReader::new(certificate_pem);
    let certificates = certs(&mut certificate_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("invalid certificate PEM: {error}"))?;
    if certificates.is_empty() {
        return Err("certificate PEM contained no certificates".to_owned());
    }

    let mut key_reader = std::io::BufReader::new(private_key_pem);
    let key = private_key(&mut key_reader)
        .map_err(|error| format!("invalid private key PEM: {error}"))?
        .ok_or_else(|| "private key PEM contained no private key".to_owned())?;
    let key = PrivateKeyDer::from(key);

    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|error| format!("invalid TLS certificate/key pair: {error}"))
}

pub fn build_tls_client_config(certificate_pem: &[u8]) -> Result<ClientConfig, String> {
    let mut certificate_reader = std::io::BufReader::new(certificate_pem);
    let certificates = certs(&mut certificate_reader)
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

pub fn handle_tls_connection(
    stream: TcpStream,
    config: std::sync::Arc<ServerConfig>,
    store: &mut SqliteAccountStore,
    sessions: &mut SessionManager,
) -> io::Result<()> {
    let connection = ServerConnection::new(config).map_err(io::Error::other)?;
    let mut tls = StreamOwned::new(connection, stream);
    handle_handshake(&mut tls)?;
    handle_account_request(&mut tls, store, sessions)
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

/// Handles an AUTH request on a transport that is already confidential.
/// Do not expose this handler on an unencrypted public socket.
pub fn handle_auth_request<S: Read + Write>(
    stream: &mut S,
    store: &SqliteAccountStore,
    sessions: &mut SessionManager,
) -> io::Result<()> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut *stream);
        reader.read_line(&mut line)?;
    }
    let mut fields = line.trim_end_matches(['\r', '\n']).splitn(3, ' ');
    let (Some("AUTH"), Some(username), Some(password)) =
        (fields.next(), fields.next(), fields.next())
    else {
        writeln!(stream, "ERROR malformed_auth")?;
        return Ok(());
    };

    if !store.authenticate(username, password) {
        writeln!(stream, "ERROR unauthorized")?;
        return Ok(());
    }

    let token = sessions.issue(username);
    writeln!(stream, "SESSION {token}")
}

pub fn handle_account_request<S: Read + Write>(
    stream: &mut S,
    store: &mut SqliteAccountStore,
    sessions: &mut SessionManager,
) -> io::Result<()> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut *stream);
        reader.read_line(&mut line)?;
    }
    if line.starts_with("SEND ") || line.starts_with("HISTORY ") {
        return handle_chat_line(stream, store, sessions, &line);
    }
    if line.starts_with("SIGNUP ") {
        let mut fields = line.trim_end_matches(['\r', '\n']).splitn(4, ' ');
        let (Some("SIGNUP"), Some(email), Some(username), Some(password)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            writeln!(stream, "ERROR malformed_signup")?;
            return Ok(());
        };
        return match store.register(email, username, password) {
            Ok(()) => writeln!(stream, "REGISTERED {}", username.trim()),
            Err(error) => writeln!(stream, "ERROR {}", registration_error_code(&error)),
        };
    }

    let mut fields = line.trim_end_matches(['\r', '\n']).splitn(3, ' ');
    let (Some("AUTH"), Some(username), Some(password)) =
        (fields.next(), fields.next(), fields.next())
    else {
        writeln!(stream, "ERROR malformed_auth")?;
        return Ok(());
    };
    if !store.authenticate(username, password) {
        writeln!(stream, "ERROR unauthorized")?;
        return Ok(());
    }
    let token = sessions.issue(username);
    writeln!(stream, "SESSION {token}")
}

fn registration_error_code(error: &RegistrationError) -> &'static str {
    match error {
        RegistrationError::EmailAlreadyRegistered => "email_registered",
        RegistrationError::UsernameAlreadyRegistered => "username_registered",
        RegistrationError::Signup(SignupError::InvalidEmail) => "invalid_email",
        RegistrationError::Signup(SignupError::InvalidUsername) => "invalid_username",
        RegistrationError::Signup(SignupError::InvalidPassword) => "invalid_password",
        RegistrationError::Signup(SignupError::PasswordHashingFailed) => "signup_failed",
        RegistrationError::Storage(_) => "signup_failed",
    }
}

pub fn handle_signup_request<S: Read + Write>(
    stream: &mut S,
    store: &mut SqliteAccountStore,
    sessions: &mut SessionManager,
) -> io::Result<()> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut *stream);
        reader.read_line(&mut line)?;
    }
    let mut fields = line.trim_end_matches(['\r', '\n']).splitn(4, ' ');
    let (Some("SIGNUP"), Some(email), Some(username), Some(password)) =
        (fields.next(), fields.next(), fields.next(), fields.next())
    else {
        writeln!(stream, "ERROR malformed_signup")?;
        return Ok(());
    };
    let _ = sessions;
    match store.register(email, username, password) {
        Ok(()) => writeln!(stream, "REGISTERED {}", username.trim()),
        Err(error) => writeln!(stream, "ERROR {}", registration_error_code(&error)),
    }
}

pub fn handle_chat_request<S: Read + Write>(
    stream: &mut S,
    store: &mut SqliteAccountStore,
    sessions: &mut SessionManager,
) -> io::Result<()> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut *stream);
        reader.read_line(&mut line)?;
    }
    handle_chat_line(stream, store, sessions, &line)
}

fn handle_chat_line<S: Read + Write>(
    stream: &mut S,
    store: &mut SqliteAccountStore,
    sessions: &mut SessionManager,
    line: &str,
) -> io::Result<()> {
    let line = line.trim_end_matches(['\r', '\n']);
    let mut fields = line.splitn(3, ' ');
    match (fields.next(), fields.next()) {
        (Some("SEND"), Some(token)) => {
            let Some(username) = sessions.validate(token) else {
                writeln!(stream, "ERROR unauthorized")?;
                return Ok(());
            };
            let Some(content) = fields.next() else {
                writeln!(stream, "ERROR malformed_message")?;
                return Ok(());
            };
            match store.store_message(&username, content) {
                Ok(id) => writeln!(stream, "SENT {id}"),
                Err(error) => writeln!(stream, "ERROR {error}"),
            }
        }
        (Some("HISTORY"), Some(token)) => {
            let Some(_username) = sessions.validate(token) else {
                writeln!(stream, "ERROR unauthorized")?;
                return Ok(());
            };
            let limit = fields
                .next()
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(50)
                .clamp(1, 100);
            for message in store.message_history(limit).map_err(io::Error::other)? {
                writeln!(
                    stream,
                    "MESSAGE {} {} {} {}",
                    message.id, message.username, message.created_at, message.content
                )?;
            }
            writeln!(stream, "END")
        }
        _ => writeln!(stream, "ERROR malformed_chat"),
    }
}

pub fn handle_handshake<S: Read + Write>(stream: &mut S) -> io::Result<()> {
    let mut line = String::new();
    {
        let mut reader = BufReader::new(&mut *stream);
        reader.read_line(&mut line)?;
    }
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
    use std::io::{BufRead, BufReader, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use twokitties_protocol::PROTOCOL_VERSION;

    #[test]
    fn authenticated_chat_requests_store_and_return_history() {
        let database_path =
            std::env::temp_dir().join(format!("twokitties-chat-request-{}.db", std::process::id()));
        let mut store = SqliteAccountStore::open(&database_path).expect("open database");
        let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
        let token = sessions.issue("tempest");
        let mut send = std::io::Cursor::new(format!("SEND {token} hello chat\n").into_bytes());
        handle_chat_request(&mut send, &mut store, &mut sessions).expect("send message");
        assert!(
            String::from_utf8(send.into_inner())
                .unwrap()
                .ends_with("SENT 1\n")
        );

        let mut history = std::io::Cursor::new(format!("HISTORY {token} 10\n").into_bytes());
        handle_chat_request(&mut history, &mut store, &mut sessions).expect("read history");
        let response = String::from_utf8(history.into_inner()).unwrap();
        assert!(response.contains("MESSAGE 1 tempest "));
        assert!(response.contains(" hello chat\n"));
        assert!(response.ends_with("END\n"));
        std::fs::remove_file(database_path).expect("remove database");
    }

    #[test]
    fn sqlite_store_persists_message_history() {
        let database_path = std::env::temp_dir().join(format!(
            "twokitties-message-history-{}.db",
            std::process::id()
        ));
        let mut store = SqliteAccountStore::open(&database_path).expect("open database");
        let first_id = store
            .store_message("tempest", "hello world")
            .expect("store first message");
        store
            .store_message("other", "reply")
            .expect("store second message");

        let history = store.message_history(10).expect("read history");
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].id, first_id);
        assert_eq!(history[0].username, "tempest");
        assert_eq!(history[0].content, "hello world");
        assert!(!history[0].created_at.is_empty());
        std::fs::remove_file(database_path).expect("remove database");
    }

    #[test]
    fn signup_request_registers_account_and_returns_confirmation() {
        let database_path = std::env::temp_dir().join(format!(
            "twokitties-signup-request-{}.db",
            std::process::id()
        ));
        let mut store = SqliteAccountStore::open(&database_path).expect("open database");
        let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
        let mut stream = std::io::Cursor::new(
            b"SIGNUP tempest@example.com tempest correct horse battery staple\n".to_vec(),
        );

        handle_signup_request(&mut stream, &mut store, &mut sessions).expect("signup request");
        assert!(
            String::from_utf8(stream.into_inner())
                .unwrap()
                .ends_with("REGISTERED tempest\n")
        );
        assert!(store.authenticate("tempest", "correct horse battery staple"));
        std::fs::remove_file(database_path).expect("remove database");
    }

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
        std::env::temp_dir().join(format!("twokitties-{label}-{}.db", std::process::id()))
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
    fn tls_server_config_accepts_generated_certificate() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();

        let config = build_tls_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
            .expect("valid certificate should build TLS config");
        assert_eq!(config.alpn_protocols, Vec::<Vec<u8>>::new());
    }

    #[test]
    fn tls_server_config_rejects_invalid_certificate() {
        assert!(build_tls_server_config(b"not a certificate", b"not a key").is_err());
    }
    #[test]
    fn tls_connection_can_complete_handshake_and_authenticate() {
        let generated = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("generate certificate");
        let cert_pem = generated.cert.pem();
        let key_pem = generated.key_pair.serialize_pem();
        let server_config = std::sync::Arc::new(
            build_tls_server_config(cert_pem.as_bytes(), key_pem.as_bytes())
                .expect("build server config"),
        );
        let client_config = std::sync::Arc::new(
            build_tls_client_config(cert_pem.as_bytes()).expect("build client config"),
        );
        let path = test_database_path("tls-auth");
        let mut store = SqliteAccountStore::open(&path).expect("open database");
        store
            .register(
                "person@example.com",
                "tempest",
                "a sufficiently long password",
            )
            .expect("register account");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept client");
            let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
            handle_tls_connection(stream, server_config, &mut store, &mut sessions)
                .expect("complete TLS auth");
        });

        let stream = TcpStream::connect(address).expect("connect client");
        let server_name =
            rustls::pki_types::ServerName::try_from("localhost").expect("valid server name");
        let connection = rustls::ClientConnection::new(client_config, server_name)
            .expect("create client TLS connection");
        let mut tls = rustls::StreamOwned::new(connection, stream);
        writeln!(tls, "HELLO {PROTOCOL_VERSION}").expect("send hello");
        let mut response = String::new();
        BufReader::new(&mut tls)
            .read_line(&mut response)
            .expect("read hello response");
        assert_eq!(response, format!("READY {PROTOCOL_VERSION}\n"));
        writeln!(tls, "AUTH tempest a sufficiently long password").expect("send auth");
        response.clear();
        BufReader::new(&mut tls)
            .read_line(&mut response)
            .expect("read auth response");
        assert!(response.starts_with("SESSION "));

        server.join().expect("server thread should finish");
        remove_test_database(&path);
    }
    #[test]
    fn auth_request_returns_session_token_for_valid_credentials() {
        let path = test_database_path("auth-valid");
        let mut store = SqliteAccountStore::open(&path).expect("open database");
        store
            .register(
                "person@example.com",
                "tempest",
                "a sufficiently long password",
            )
            .expect("register account");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
            handle_auth_request(&mut stream, &store, &mut sessions).expect("handle auth");
        });

        let mut client = TcpStream::connect(address).expect("connect client");
        writeln!(client, "AUTH tempest a sufficiently long password").expect("send auth");
        let mut response = String::new();
        BufReader::new(client)
            .read_line(&mut response)
            .expect("read auth response");

        assert!(response.starts_with("SESSION "));
        assert_eq!(response.trim_end().len(), "SESSION ".len() + 64);
        server.join().expect("server thread should finish");
        remove_test_database(&path);
    }

    #[test]
    fn auth_request_rejects_invalid_credentials() {
        let path = test_database_path("auth-invalid");
        let mut store = SqliteAccountStore::open(&path).expect("open database");
        store
            .register(
                "person@example.com",
                "tempest",
                "a sufficiently long password",
            )
            .expect("register account");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let address = listener.local_addr().expect("listener address");
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept client");
            let mut sessions = SessionManager::with_ttl(std::time::Duration::from_secs(60));
            handle_auth_request(&mut stream, &store, &mut sessions).expect("handle auth");
        });

        let mut client = TcpStream::connect(address).expect("connect client");
        writeln!(client, "AUTH tempest wrong password").expect("send auth");
        let mut response = String::new();
        BufReader::new(client)
            .read_line(&mut response)
            .expect("read auth response");

        assert_eq!(response, "ERROR unauthorized\n");
        server.join().expect("server thread should finish");
        remove_test_database(&path);
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
