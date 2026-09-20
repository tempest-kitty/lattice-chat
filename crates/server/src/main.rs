use std::fs;
use std::net::TcpListener;
use std::sync::Arc;
use std::time::Duration;
use twokitties_server::{
    SessionManager, SqliteAccountStore, build_tls_server_config, handle_tls_connection,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listen_addr = std::env::var("LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:9443".to_owned());
    let database_path =
        std::env::var("DATABASE_PATH").unwrap_or_else(|_| "./twokitties.db".to_owned());
    let certificate_path =
        std::env::var("TLS_CERT_PATH").unwrap_or_else(|_| "./server.crt".to_owned());
    let private_key_path =
        std::env::var("TLS_KEY_PATH").unwrap_or_else(|_| "./server.key".to_owned());

    let store = SqliteAccountStore::open(&database_path)?;
    let certificate = fs::read(&certificate_path)?;
    let private_key = fs::read(&private_key_path)?;
    let tls_config = Arc::new(build_tls_server_config(&certificate, &private_key)?);
    let listener = TcpListener::bind(&listen_addr)?;
    let mut sessions = SessionManager::with_ttl(Duration::from_secs(86_400));

    eprintln!("twokitties-server listening on {listen_addr}");
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                if let Err(error) =
                    handle_tls_connection(stream, Arc::clone(&tls_config), &store, &mut sessions)
                {
                    eprintln!("connection failed: {error}");
                }
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }

    Ok(())
}
