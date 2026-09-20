use eframe::egui;
use std::fs;
use std::net::SocketAddr;
use twokitties_client::{connect_tls_and_authenticate, register_tls_account};

struct TwoKittiesApp {
    server_address: String,
    server_name: String,
    certificate_path: String,
    username: String,
    email: String,
    password: String,
    signup_mode: bool,
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
            status: "Not authenticated".to_owned(),
        }
    }
}

impl TwoKittiesApp {
    fn authenticate(&mut self) {
        let address: SocketAddr = match self.server_address.trim().parse() {
            Ok(address) => address,
            Err(error) => {
                self.status = format!("Invalid server address: {error}");
                return;
            }
        };
        let certificate = match fs::read(self.certificate_path.trim()) {
            Ok(certificate) => certificate,
            Err(error) => {
                self.status = format!("Could not read trusted certificate: {error}");
                return;
            }
        };
        match connect_tls_and_authenticate(
            address,
            self.server_name.trim(),
            &certificate,
            self.username.trim(),
            &self.password,
        ) {
            Ok(_session) => {
                self.status = format!("Authenticated as {}", self.username.trim());
            }
            Err(error) => {
                self.status = format!("Authentication failed: {error}");
            }
        }
    }

    fn signup(&mut self) {
        let address: SocketAddr = match self.server_address.trim().parse() {
            Ok(address) => address,
            Err(error) => {
                self.status = format!("Invalid server address: {error}");
                return;
            }
        };
        let certificate = match fs::read(self.certificate_path.trim()) {
            Ok(certificate) => certificate,
            Err(error) => {
                self.status = format!("Could not read trusted certificate: {error}");
                return;
            }
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
}

impl eframe::App for TwoKittiesApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(context, |ui| {
            ui.heading("TwoKitties");
            ui.label("Kitty Dynamics");
            ui.separator();
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
