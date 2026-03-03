use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::process::Stdio;

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "type")]
pub enum DaemonEvent {
    #[serde(rename = "response")]
    Response {
        success: bool,
        error: Option<String>,
        data: Option<serde_json::Value>,
    },
    #[serde(rename = "state_changed")]
    StateChanged {
        state: String,
        error: Option<String>,
    },
    #[serde(rename = "stats")]
    Stats {
        tx_bytes: u64,
        rx_bytes: u64,
        tx_packets: u64,
        rx_packets: u64,
    },
    #[serde(rename = "deploy_progress")]
    DeployProgress {
        step: u32,
        total: u32,
        message: String,
    },
}

pub struct DaemonManager {
    child: Option<Child>,
    stdin_tx: Option<mpsc::Sender<String>>,
}

impl DaemonManager {
    pub fn new() -> Self {
        Self {
            child: None,
            stdin_tx: None,
        }
    }

    pub fn start(&mut self, app: &AppHandle) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(());
        }

        let current_exe = std::env::current_exe()
            .map_err(|e| format!("Failed to get current exe: {e}"))?;
        let exe_dir = current_exe.parent().ok_or("No parent dir")?;

        let daemon_path = if exe_dir.join("resonance-daemon").exists() {
            exe_dir.join("resonance-daemon")
        } else {
            let mut path = exe_dir.to_path_buf();
            while path.pop() {
                let candidate = path.join("target/release/resonance-daemon");
                if candidate.exists() {
                    break;
                }
            }
            path.join("target/release/resonance-daemon")
        };

        let daemon_str = daemon_path.to_string_lossy().to_string();

        let askpass_path = std::env::temp_dir().join("resonance-askpass.sh");
        {
            let mut f = std::fs::File::create(&askpass_path)
                .map_err(|e| format!("Failed to create askpass script: {e}"))?;
            f.write_all(b"#!/bin/sh\nzenity --password --title='Resonance VPN' 2>/dev/null\n")
                .map_err(|e| format!("Failed to write askpass script: {e}"))?;
        }
        std::fs::set_permissions(&askpass_path, PermissionsExt::from_mode(0o755))
            .map_err(|e| format!("Failed to chmod askpass script: {e}"))?;

        log::info!("Starting daemon via sudo: {daemon_str}");

        let mut child = Command::new("sudo")
            .env("SUDO_ASKPASS", &askpass_path)
            .arg("-A")
            .arg(&daemon_str)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("Failed to spawn daemon: {e}"))?;

        let stdout = child.stdout.take().ok_or("No stdout")?;
        let stderr = child.stderr.take().ok_or("No stderr")?;
        let stdin = child.stdin.take().ok_or("No stdin")?;

        self.child = Some(child);

        let (tx, mut rx) = mpsc::channel::<String>(64);
        self.stdin_tx = Some(tx);

        tauri::async_runtime::spawn(async move {
            let mut stdin = stdin;
            while let Some(msg) = rx.recv().await {
                if stdin.write_all(msg.as_bytes()).await.is_err() {
                    break;
                }
                if stdin.flush().await.is_err() {
                    break;
                }
            }
        });

        let app_handle = app.clone();
        tauri::async_runtime::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let line = line.trim().to_string();
                if line.is_empty() {
                    continue;
                }
                match serde_json::from_str::<DaemonEvent>(&line) {
                    Ok(daemon_event) => {
                        log::info!("[daemon->gui] {:?}", daemon_event);
                        let _ = app_handle.emit("daemon-event", &daemon_event);
                    }
                    Err(e) => {
                        log::warn!("[daemon stdout] parse error: {e} | raw: {line}");
                    }
                }
            }
            let _ = app_handle.emit("daemon-event", &DaemonEvent::StateChanged {
                state: "disconnected".into(),
                error: None,
            });
        });

        tauri::async_runtime::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                log::info!("[daemon] {}", line.trim());
            }
        });

        Ok(())
    }

    pub fn send(&mut self, json: &str) -> Result<(), String> {
        if let Some(ref tx) = self.stdin_tx {
            tx.try_send(format!("{json}\n"))
                .map_err(|e| format!("Failed to send to daemon: {e}"))?;
            Ok(())
        } else {
            Err("Daemon not running".into())
        }
    }

    pub fn stop(&mut self) {
        self.stdin_tx = None;
        if let Some(mut child) = self.child.take() {
            let _ = child.start_kill();
        }
    }
}
