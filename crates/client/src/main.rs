use eframe::egui;
use std::fs;
use std::net::SocketAddr;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;
use twokitties_client::{ChatMessage, PersistentChatConnection, register_tls_account};

enum ChatCommand {
    Refresh(String),
    Send(String, String),
    Stop,
}

enum ChatEvent {
    Messages(Vec<ChatMessage>),
    Sent(i64),
    Error(String),
    Disconnected,
}

struct ChatWorker {
    commands: Sender<ChatCommand>,
    events: Receiver<ChatEvent>,
}

impl ChatWorker {
    fn start(mut connection: PersistentChatConnection, channel: String) -> Self {
        let (commands, command_rx) = mpsc::channel();
        let (event_tx, events) = mpsc::channel();
        thread::spawn(move || {
            let mut current_channel = channel;
            if let Err(error) = Self::refresh(&mut connection, &current_channel, &event_tx) {
                let _ = event_tx.send(ChatEvent::Error(error));
            }
            loop {
                match command_rx.recv_timeout(Duration::from_secs(2)) {
                    Ok(ChatCommand::Refresh(channel)) => {
                        current_channel = channel;
                        if let Err(error) =
                            Self::refresh(&mut connection, &current_channel, &event_tx)
                        {
                            let _ = event_tx.send(ChatEvent::Error(error));
                            break;
                        }
                    }
                    Ok(ChatCommand::Send(channel, content)) => {
                        match connection.send(&channel, &content) {
                            Ok(id) => {
                                let _ = event_tx.send(ChatEvent::Sent(id));
                                if let Err(error) =
                                    Self::refresh(&mut connection, &current_channel, &event_tx)
                                {
                                    let _ = event_tx.send(ChatEvent::Error(error));
                                    break;
                                }
                            }
                            Err(error) => {
                                let _ = event_tx.send(ChatEvent::Error(error));
                                break;
                            }
                        }
                    }
                    Ok(ChatCommand::Stop) => {
                        let _ = connection.quit();
                        break;
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        if let Err(error) =
                            Self::refresh(&mut connection, &current_channel, &event_tx)
                        {
                            let _ = event_tx.send(ChatEvent::Error(error));
                            break;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                }
            }
            let _ = event_tx.send(ChatEvent::Disconnected);
        });
        Self { commands, events }
    }

    fn refresh(
        connection: &mut PersistentChatConnection,
        channel: &str,
        events: &Sender<ChatEvent>,
    ) -> Result<(), String> {
        let messages = connection.history(channel, 100)?;
        events
            .send(ChatEvent::Messages(messages))
            .map_err(|_| "chat UI closed".to_owned())
    }
}

struct TwoKittiesApp {
    server_address: String,
    server_name: String,
    certificate_path: String,
    username: String,
    email: String,
    password: String,
    signup_mode: bool,
    session_token: Option<String>,
    worker: Option<ChatWorker>,
    channel: String,
    messages: Vec<ChatMessage>,
    message_input: String,
    status: String,
}

impl Default for TwoKittiesApp {
    fn default() -> Self {
        Self {
            server_address: "127.0.0.1:9443".to_owned(),
            server_name: "localhost".to_owned(),
            certificate_path: "server.crt".to_owned(),
            username: String::new(),
            email: String::new(),
            password: String::new(),
            signup_mode: false,
            session_token: None,
            worker: None,
            channel: "general".to_owned(),
            messages: Vec::new(),
            message_input: String::new(),
            status: "Not authenticated".to_owned(),
        }
    }
}

impl TwoKittiesApp {
    fn connection_details(&self) -> Result<(SocketAddr, Vec<u8>), String> {
        let address = self
            .server_address
            .trim()
            .parse()
            .map_err(|error| format!("Invalid server address: {error}"))?;
        let certificate = fs::read(self.certificate_path.trim())
            .map_err(|error| format!("Could not read trusted certificate: {error}"))?;
        Ok((address, certificate))
    }

    fn authenticate(&mut self) {
        let Ok((address, certificate)) = self.connection_details() else {
            self.status = self.connection_details().unwrap_err();
            return;
        };
        match PersistentChatConnection::connect_and_authenticate(
            address,
            self.server_name.trim(),
            &certificate,
            self.username.trim(),
            &self.password,
        ) {
            Ok(connection) => {
                self.session_token = Some("persistent".to_owned());
                self.worker = Some(ChatWorker::start(connection, self.channel.clone()));
                self.status = format!("Authenticated as {}", self.username.trim());
            }
            Err(error) => {
                self.session_token = None;
                self.status = format!("Authentication failed: {error}");
            }
        }
    }

    fn signup(&mut self) {
        let Ok((address, certificate)) = self.connection_details() else {
            self.status = self.connection_details().unwrap_err();
            return;
        };
        match register_tls_account(
            address,
            self.server_name.trim(),
            &certificate,
            self.email.trim(),
            self.username.trim(),
            &self.password,
        ) {
            Ok(response) => {
                self.status = format!("{response}; you can now log in");
                self.signup_mode = false;
            }
            Err(error) => {
                self.status = format!("Signup failed: {error}");
            }
        }
    }

    fn refresh_history(&mut self) {
        let Some(worker) = self.worker.as_ref() else {
            return;
        };
        if let Err(error) = worker
            .commands
            .send(ChatCommand::Refresh(self.channel.trim().to_owned()))
        {
            self.status = format!("Refresh failed: {error}");
        }
    }

    fn send_message(&mut self) {
        if self.message_input.trim().is_empty() {
            self.status = "Message cannot be empty".to_owned();
            return;
        }
        let Some(worker) = self.worker.as_ref() else {
            return;
        };
        if let Err(error) = worker.commands.send(ChatCommand::Send(
            self.channel.trim().to_owned(),
            self.message_input.clone(),
        )) {
            self.status = format!("Send failed: {error}");
        } else {
            self.message_input.clear();
            self.status = "Sending message".to_owned();
        }
    }

    fn poll_chat_events(&mut self) {
        let mut disconnected = false;
        if let Some(worker) = self.worker.as_ref() {
            while let Ok(event) = worker.events.try_recv() {
                match event {
                    ChatEvent::Messages(messages) => {
                        self.messages = messages;
                        self.status = format!("Loaded {} messages", self.messages.len());
                    }
                    ChatEvent::Sent(id) => {
                        self.status = format!("Message {id} sent");
                    }
                    ChatEvent::Error(error) => {
                        self.status = format!("Chat connection failed: {error}");
                        disconnected = true;
                    }
                    ChatEvent::Disconnected => disconnected = true,
                }
            }
        }
        if disconnected {
            self.worker = None;
            self.session_token = None;
            self.status = "Chat connection closed".to_owned();
        }
    }

    fn show_chat(&mut self, ui: &mut egui::Ui) {
        ui.heading("Chat");
        ui.horizontal(|ui| {
            ui.label("Channel");
            ui.text_edit_singleline(&mut self.channel);
        });
        if ui.button("Refresh history").clicked() {
            self.refresh_history();
        }
        egui::ScrollArea::vertical()
            .max_height(300.0)
            .show(ui, |ui| {
                for message in &self.messages {
                    ui.label(format!(
                        "{} [{}] {}: {}",
                        message.created_at, message.id, message.username, message.content
                    ));
                }
            });
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.message_input);
            if ui.button("Send").clicked() {
                self.send_message();
            }
        });
        if ui.button("Log out").clicked() {
            if let Some(worker) = self.worker.take() {
                let _ = worker.commands.send(ChatCommand::Stop);
            }
            self.session_token = None;
            self.messages.clear();
            self.status = "Logged out".to_owned();
        }
    }
}

impl eframe::App for TwoKittiesApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_chat_events();
        context.request_repaint_after(Duration::from_millis(100));
        egui::CentralPanel::default().show(context, |ui| {
            ui.heading("TwoKitties");
            ui.label("Kitty Dynamics");
            ui.separator();
            if self.session_token.is_some() {
                self.show_chat(ui);
            } else {
                ui.heading(if self.signup_mode {
                    "Create an account"
                } else {
                    "Secure sign in"
                });
                ui.horizontal(|ui| {
                    ui.label("Server address");
                    ui.text_edit_singleline(&mut self.server_address);
                });
                ui.horizontal(|ui| {
                    ui.label("TLS server name");
                    ui.text_edit_singleline(&mut self.server_name);
                });
                ui.horizontal(|ui| {
                    ui.label("Trusted certificate");
                    ui.text_edit_singleline(&mut self.certificate_path);
                });
                if self.signup_mode {
                    ui.horizontal(|ui| {
                        ui.label("Email");
                        ui.text_edit_singleline(&mut self.email);
                    });
                }
                ui.horizontal(|ui| {
                    ui.label("Username");
                    ui.text_edit_singleline(&mut self.username);
                });
                ui.horizontal(|ui| {
                    ui.label("Password");
                    ui.add(egui::TextEdit::singleline(&mut self.password).password(true));
                });
                if self.signup_mode {
                    if ui.button("Create account securely").clicked() {
                        self.signup();
                    }
                    if ui.button("Back to sign in").clicked() {
                        self.signup_mode = false;
                    }
                } else {
                    if ui.button("Log in securely").clicked() {
                        self.authenticate();
                    }
                    if ui.button("Create a new account").clicked() {
                        self.signup_mode = true;
                        self.status = "Ready to create an account".to_owned();
                    }
                }
            }
            ui.separator();
            ui.label(&self.status);
        });
    }
}

fn app_icon() -> egui::IconData {
    let image = image::load_from_memory(include_bytes!("../../../assets/twokittiesico.png"))
        .expect("embedded TwoKitties icon must be a valid PNG")
        .to_rgba8();
    let (width, height) = image.dimensions();
    egui::IconData {
        rgba: image.into_raw(),
        width,
        height,
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("TwoKitties — Kitty Dynamics")
            .with_icon(app_icon()),
        ..Default::default()
    };
    eframe::run_native(
        "TwoKitties — Kitty Dynamics",
        options,
        Box::new(|_creation_context| Ok(Box::new(TwoKittiesApp::default()))),
    )
}
