use eframe::egui;
use std::fs;
use std::net::SocketAddr;
use twokitties_client::connect_tls_and_handshake;

struct TwoKittiesApp {
    server_address: String,
    server_name: String,
    certificate_path: String,
    status: String,
}

impl Default for TwoKittiesApp {
    fn default() -> Self {
        Self {
            server_address: "127.0.0.1:9443".to_owned(),
            server_name: "localhost".to_owned(),
            certificate_path: "server.crt".to_owned(),
            status: "Not connected".to_owned(),
        }
    }
}

impl TwoKittiesApp {
    fn connect(&mut self) {
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
        self.status =
            match connect_tls_and_handshake(address, self.server_name.trim(), &certificate) {
                Ok(response) => format!("Connected: {response}"),
                Err(error) => format!("Connection failed: {error}"),
            };
    }
}

impl eframe::App for TwoKittiesApp {
    fn update(&mut self, context: &egui::Context, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(context, |ui| {
            ui.heading("TwoKitties");
            ui.label("Kitty Dynamics");
            ui.separator();
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
            if ui.button("Connect securely").clicked() {
                self.connect();
            }
            ui.separator();
            ui.label(&self.status);
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "TwoKitties — Kitty Dynamics",
        options,
        Box::new(|_creation_context| Ok(Box::new(TwoKittiesApp::default()))),
    )
}
