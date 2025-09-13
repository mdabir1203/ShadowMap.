#![cfg(feature = "gui")]

use eframe::egui;
use shadowmap::{run, Args};
use std::sync::mpsc::{self, Receiver};
use std::thread;

struct App {
    domain: String,
    status: String,
    worker: Option<Receiver<String>>,
}

impl Default for App {
    fn default() -> Self {
        Self {
            domain: String::new(),
            status: "Ready".to_string(),
            worker: None,
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(rx) = &self.worker {
            if let Ok(msg) = rx.try_recv() {
                self.status = msg;
                self.worker = None;
            } else {
                ctx.request_repaint();
            }
        }

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("ShadowMap");
            ui.horizontal(|ui| {
                ui.label("Domain:");
                ui.text_edit_singleline(&mut self.domain);
            });
            if ui.button("Run Scan").clicked() && self.worker.is_none() {
                let domain = self.domain.clone();
                let (tx, rx) = mpsc::channel();
                thread::spawn(move || {
                    let rt = tokio::runtime::Runtime::new().unwrap();
                    let args = Args {
                        domain,
                        concurrency: 100,
                        timeout: 10,
                        retries: 2,
                    };
                    let msg = match rt.block_on(run(args)) {
                        Ok(out) => format!("Scan complete. Output at {out}"),
                        Err(e) => format!("Scan failed: {e}"),
                    };
                    let _ = tx.send(msg);
                });
                self.status = "Scanning...".to_string();
                self.worker = Some(rx);
            }
            ui.separator();
            ui.label(&self.status);
        });
    }
}

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "ShadowMap",
        options,
        Box::new(|_cc| Box::new(App::default())),
    )
}
