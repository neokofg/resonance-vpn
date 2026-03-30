mod daemon;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use daemon::DaemonManager;
use serde::{Deserialize, Serialize};
use tauri::Manager;
use tokio::sync::Mutex;

type DaemonState = Arc<Mutex<DaemonManager>>;

#[derive(Default)]
pub struct StatsState {
    pub tx_bytes: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_packets: AtomicU64,
}

type SharedStats = Arc<StatsState>;

#[tauri::command]
async fn connect_vpn(
    server: String,
    psk: String,
    dns: Vec<String>,
    state: tauri::State<'_, DaemonState>,
) -> Result<(), String> {
    let mut daemon = state.lock().await;
    let request = serde_json::json!({
        "method": "connect",
        "params": { "server": server, "psk": psk, "dns": dns }
    });
    daemon.send(&request.to_string())
}

#[tauri::command]
async fn disconnect_vpn(state: tauri::State<'_, DaemonState>) -> Result<(), String> {
    let mut daemon = state.lock().await;
    let request = serde_json::json!({ "method": "disconnect" });
    daemon.send(&request.to_string())
}

#[tauri::command]
async fn get_vpn_status(state: tauri::State<'_, DaemonState>) -> Result<(), String> {
    let mut daemon = state.lock().await;
    let request = serde_json::json!({ "method": "status" });
    daemon.send(&request.to_string())
}

#[derive(Serialize)]
struct StatsResponse {
    tx_bytes: u64,
    rx_bytes: u64,
    tx_packets: u64,
    rx_packets: u64,
}

#[tauri::command]
fn get_stats(stats: tauri::State<'_, SharedStats>) -> StatsResponse {
    StatsResponse {
        tx_bytes: stats.tx_bytes.load(Ordering::Relaxed),
        rx_bytes: stats.rx_bytes.load(Ordering::Relaxed),
        tx_packets: stats.tx_packets.load(Ordering::Relaxed),
        rx_packets: stats.rx_packets.load(Ordering::Relaxed),
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeployRequest {
    host: String,
    user: String,
    ssh_key: Option<String>,
    password: Option<String>,
    ssh_port: u16,
    domain: Option<String>,
    port: u16,
    subnet: String,
}

#[tauri::command]
async fn deploy_server(
    params: DeployRequest,
    state: tauri::State<'_, DaemonState>,
) -> Result<(), String> {
    let mut daemon = state.lock().await;
    let request = serde_json::json!({
        "method": "deploy",
        "params": {
            "host": params.host,
            "user": params.user,
            "ssh_key": params.ssh_key,
            "password": params.password,
            "ssh_port": params.ssh_port,
            "domain": params.domain,
            "port": params.port,
            "subnet": params.subnet,
        }
    });
    daemon.send(&request.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_store::Builder::default().build())
        .plugin(tauri_plugin_opener::init())
        .manage(Arc::new(Mutex::new(DaemonManager::new())) as DaemonState)
        .manage(Arc::new(StatsState::default()) as SharedStats)
        .setup(|app| {
            let state = app.state::<DaemonState>().inner().clone();
            let stats = app.state::<SharedStats>().inner().clone();
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let mut daemon = state.lock().await;
                if let Err(e) = daemon.start(&handle, stats) {
                    log::error!("Failed to start daemon: {e}");
                }
            });

            setup_tray(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect_vpn,
            disconnect_vpn,
            get_vpn_status,
            get_stats,
            deploy_server,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn setup_tray(app: &tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let show = MenuItem::with_id(app, "show", "Show", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    TrayIconBuilder::new()
        .menu(&menu)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            "quit" => {
                let state = app.state::<DaemonState>().inner().clone();
                tauri::async_runtime::spawn(async move {
                    let mut daemon = state.lock().await;
                    daemon.stop();
                });
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}
