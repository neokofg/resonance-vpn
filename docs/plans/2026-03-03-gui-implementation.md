# Resonance VPN GUI — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Tauri v2 + Svelte 5 desktop GUI for resonance-vpn with connect/deploy/settings/profiles, backed by a privileged daemon sidecar.

**Architecture:** Split-privilege model. The Tauri GUI runs unprivileged. A `resonance-daemon` sidecar binary handles TUN creation, routing, and tunnel forwarding with root/admin privileges. Communication uses JSON-RPC over stdin/stdout (Tauri's native sidecar streaming). VPN logic is extracted into `resonance-vpn-lib` shared by both CLI and daemon.

**Tech Stack:** Tauri v2, Svelte 5 (SvelteKit), TypeScript, Phosphor Icons, Rust (tokio, serde_json), JSON-RPC over stdio

---

## Phase 1: Project Scaffolding

### Task 1: Create resonance-vpn-lib crate

**Files:**
- Create: `crates/resonance-vpn-lib/Cargo.toml`
- Create: `crates/resonance-vpn-lib/src/lib.rs`
- Modify: `Cargo.toml` (workspace root)

**Step 1: Create the crate directory and Cargo.toml**

```toml
# crates/resonance-vpn-lib/Cargo.toml
[package]
name = "resonance-vpn-lib"
version = "0.1.0"
edition = "2024"

[dependencies]
resonance-proto = { path = "../resonance-proto" }
resonance-tun = { path = "../resonance-tun" }
tokio = { workspace = true }
blake3 = { workspace = true }
bytes = { workspace = true }
prost = { workspace = true }
log = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
toml = { workspace = true }
anyhow = { workspace = true }
getrandom = { workspace = true }
russh = { workspace = true }
boring = "5"
tokio-boring = "5"
tokio-tungstenite = "0.26"
futures-util = "0.3"
h2 = "0.4"
http = "1"
```

```rust
// crates/resonance-vpn-lib/src/lib.rs
pub mod config;
pub mod deploy;
pub mod routing;
pub mod tls;
pub mod tunnel;

pub fn dirs_home() -> String {
    #[cfg(windows)]
    {
        std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string())
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
    }
}
```

**Step 2: Add to workspace**

Add `"crates/resonance-vpn-lib"` to `[workspace] members` in root `Cargo.toml`.

**Step 3: Run `cargo check -p resonance-vpn-lib`**

Expected: Fail (modules don't exist yet). This is expected — we'll populate them in Task 2.

**Step 4: Commit**

```
feat: scaffold resonance-vpn-lib crate
```

---

### Task 2: Extract modules from resonance-client into resonance-vpn-lib

**Files:**
- Copy: `crates/resonance-client/src/tunnel.rs` → `crates/resonance-vpn-lib/src/tunnel.rs`
- Copy: `crates/resonance-client/src/tls.rs` → `crates/resonance-vpn-lib/src/tls.rs`
- Copy: `crates/resonance-client/src/config.rs` → `crates/resonance-vpn-lib/src/config.rs`
- Copy: `crates/resonance-client/src/deploy.rs` → `crates/resonance-vpn-lib/src/deploy.rs`
- Copy: `crates/resonance-client/src/routing/` → `crates/resonance-vpn-lib/src/routing/`
- Modify: all copied files — change `crate::dirs_home()` → `crate::dirs_home()`  (same path, no change needed since it's in lib.rs)
- Modify: `crates/resonance-client/src/main.rs` — use `resonance_vpn_lib::` instead of local modules
- Modify: `crates/resonance-client/Cargo.toml` — add dep on `resonance-vpn-lib`, remove deps that moved

**Step 1: Copy all source files**

Copy `tunnel.rs`, `tls.rs`, `config.rs`, `deploy.rs`, and `routing/` directory from `resonance-client/src/` to `resonance-vpn-lib/src/`.

**Step 2: Update resonance-client to depend on vpn-lib**

```toml
# crates/resonance-client/Cargo.toml
[dependencies]
resonance-vpn-lib = { path = "../resonance-vpn-lib" }
resonance-tun = { path = "../resonance-tun" }
tokio = { workspace = true }
log = { workspace = true }
env_logger = { workspace = true }
anyhow = { workspace = true }
clap = { version = "4", features = ["derive"] }
```

**Step 3: Update resonance-client main.rs**

Remove `mod config; mod deploy; mod routing; mod tls; mod tunnel;` declarations. Replace with imports from `resonance_vpn_lib`:

```rust
use resonance_vpn_lib::{config, deploy, routing, tunnel};
use resonance_vpn_lib::dirs_home;
```

Keep the rest of main.rs as-is — the function signatures are the same.

**Step 4: Verify**

Run: `cargo check --workspace`
Run: `cargo clippy --workspace -- -D warnings -A dead-code`

**Step 5: Commit**

```
refactor: extract VPN logic into resonance-vpn-lib crate
```

---

### Task 3: Create resonance-daemon crate

**Files:**
- Create: `crates/resonance-daemon/Cargo.toml`
- Create: `crates/resonance-daemon/src/main.rs`
- Create: `crates/resonance-daemon/src/ipc.rs`
- Modify: `Cargo.toml` (workspace root — add member)

**Step 1: Create Cargo.toml**

```toml
# crates/resonance-daemon/Cargo.toml
[package]
name = "resonance-daemon"
version = "0.1.0"
edition = "2024"

[[bin]]
name = "resonance-daemon"
path = "src/main.rs"

[dependencies]
resonance-vpn-lib = { path = "../resonance-vpn-lib" }
resonance-tun = { path = "../resonance-tun" }
tokio = { workspace = true }
serde = { workspace = true }
serde_json = "1"
log = { workspace = true }
env_logger = { workspace = true }
anyhow = { workspace = true }
```

Add `serde_json = "1"` to `[workspace.dependencies]` in root Cargo.toml.

**Step 2: Create IPC protocol types**

```rust
// crates/resonance-daemon/src/ipc.rs
use serde::{Deserialize, Serialize};

// === Requests (GUI → Daemon via stdin) ===

#[derive(Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Request {
    #[serde(rename = "connect")]
    Connect(ConnectParams),
    #[serde(rename = "disconnect")]
    Disconnect,
    #[serde(rename = "status")]
    Status,
    #[serde(rename = "deploy")]
    Deploy(DeployParams),
}

#[derive(Deserialize)]
pub struct ConnectParams {
    pub server: String,
    pub psk: String,
    pub dns: Vec<String>,
}

#[derive(Deserialize)]
pub struct DeployParams {
    pub host: String,
    pub user: String,
    pub ssh_key: Option<String>,
    pub password: Option<String>,
    pub ssh_port: u16,
    pub domain: Option<String>,
    pub port: u16,
    pub subnet: String,
}

// === Responses / Events (Daemon → GUI via stdout) ===

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "response")]
    Response(Response),
    #[serde(rename = "state_changed")]
    StateChanged { state: VpnState, error: Option<String> },
    #[serde(rename = "stats")]
    Stats(Stats),
    #[serde(rename = "deploy_progress")]
    DeployProgress { step: u32, total: u32, message: String },
}

#[derive(Serialize)]
pub struct Response {
    pub success: bool,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<ResponseData>,
}

#[derive(Serialize)]
#[serde(untagged)]
pub enum ResponseData {
    Connected { assigned_ip: String, session_id: String },
    Status { state: VpnState, assigned_ip: Option<String>, uptime_secs: u64 },
    DeployComplete { server: String, psk: String },
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VpnState {
    Disconnected,
    Connecting,
    Connected,
    Disconnecting,
    Error,
}
```

**Step 3: Create daemon main loop**

```rust
// crates/resonance-daemon/src/main.rs
mod ipc;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{watch, Mutex};

use resonance_tun::{TunConfig, TunDevice};
use resonance_vpn_lib::{deploy, routing, tunnel};

use crate::ipc::*;

struct DaemonState {
    vpn_state: VpnState,
    shutdown_tx: Option<watch::Sender<bool>>,
    assigned_ip: Option<String>,
    connected_since: Option<Instant>,
}

impl DaemonState {
    fn new() -> Self {
        Self {
            vpn_state: VpnState::Disconnected,
            shutdown_tx: None,
            assigned_ip: None,
            connected_since: None,
        }
    }
}

fn emit(event: &Event) {
    if let Ok(json) = serde_json::to_string(event) {
        println!("{json}");
    }
}

fn emit_state(state: VpnState, error: Option<String>) {
    emit(&Event::StateChanged { state, error });
}

fn respond(success: bool, error: Option<String>, data: Option<ResponseData>) {
    emit(&Event::Response(Response { success, error, data }));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    )
    .target(env_logger::Target::Stderr) // logs to stderr, JSON to stdout
    .init();

    let state = Arc::new(Mutex::new(DaemonState::new()));
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    while let Ok(Some(line)) = lines.next_line().await {
        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                respond(false, Some(format!("Invalid request: {e}")), None);
                continue;
            }
        };

        match request {
            Request::Connect(params) => {
                handle_connect(state.clone(), params).await;
            }
            Request::Disconnect => {
                handle_disconnect(state.clone()).await;
            }
            Request::Status => {
                handle_status(state.clone()).await;
            }
            Request::Deploy(params) => {
                handle_deploy(params).await;
            }
        }
    }

    Ok(())
}

async fn handle_connect(state: Arc<Mutex<DaemonState>>, params: ConnectParams) {
    {
        let mut s = state.lock().await;
        if s.vpn_state == VpnState::Connected || s.vpn_state == VpnState::Connecting {
            respond(false, Some("Already connected or connecting".into()), None);
            return;
        }
        s.vpn_state = VpnState::Connecting;
    }
    emit_state(VpnState::Connecting, None);

    let state_clone = state.clone();
    tokio::spawn(async move {
        match do_connect(&params).await {
            Ok((handshake, tun, routing_state, shutdown_tx, shutdown_rx)) => {
                let assigned_ip = handshake.assigned_ip.clone();
                let session_id = handshake.session_id.clone();

                {
                    let mut s = state_clone.lock().await;
                    s.vpn_state = VpnState::Connected;
                    s.shutdown_tx = Some(shutdown_tx);
                    s.assigned_ip = Some(assigned_ip.clone());
                    s.connected_since = Some(Instant::now());
                }

                respond(true, None, Some(ResponseData::Connected {
                    assigned_ip,
                    session_id,
                }));
                emit_state(VpnState::Connected, None);

                // Block on forwarding
                if let Err(e) = tunnel::run_forwarding(handshake, tun, shutdown_rx).await {
                    log::error!("Forwarding error: {e}");
                }

                // Cleanup
                drop(routing_state);
                {
                    let mut s = state_clone.lock().await;
                    s.vpn_state = VpnState::Disconnected;
                    s.shutdown_tx = None;
                    s.assigned_ip = None;
                    s.connected_since = None;
                }
                emit_state(VpnState::Disconnected, None);
            }
            Err(e) => {
                let mut s = state_clone.lock().await;
                s.vpn_state = VpnState::Error;
                respond(false, Some(format!("{e}")), None);
                emit_state(VpnState::Error, Some(format!("{e}")));
                s.vpn_state = VpnState::Disconnected;
                emit_state(VpnState::Disconnected, None);
            }
        }
    });
}

async fn do_connect(
    params: &ConnectParams,
) -> anyhow::Result<(
    tunnel::HandshakeResult,
    Arc<TunDevice>,
    routing::RoutingState,
    watch::Sender<bool>,
    watch::Receiver<bool>,
)> {
    let handshake = tunnel::handshake(&params.server, &params.psk).await?;
    let assigned_ip: Ipv4Addr = handshake.assigned_ip.parse()?;
    let tun_name = "rvpn0";
    let tun = Arc::new(TunDevice::create(&TunConfig {
        name: tun_name.to_string(),
        address: assigned_ip,
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1280,
    })?);
    let routing_state = routing::RoutingState::setup(
        &params.server,
        &handshake.assigned_ip,
        tun_name,
        &params.dns.iter().map(|s| s.as_str()).collect::<Vec<_>>()
            .iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    )?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    Ok((handshake, tun, routing_state, shutdown_tx, shutdown_rx))
}

async fn handle_disconnect(state: Arc<Mutex<DaemonState>>) {
    let mut s = state.lock().await;
    if let Some(tx) = s.shutdown_tx.take() {
        s.vpn_state = VpnState::Disconnecting;
        emit_state(VpnState::Disconnecting, None);
        let _ = tx.send(true);
        respond(true, None, None);
    } else {
        respond(false, Some("Not connected".into()), None);
    }
}

async fn handle_status(state: Arc<Mutex<DaemonState>>) {
    let s = state.lock().await;
    let uptime = s.connected_since
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);
    respond(true, None, Some(ResponseData::Status {
        state: s.vpn_state,
        assigned_ip: s.assigned_ip.clone(),
        uptime_secs: uptime,
    }));
}

async fn handle_deploy(params: DeployParams) {
    let opts = deploy::DeployOpts {
        host: params.host,
        user: params.user,
        ssh_key: params.ssh_key,
        password: params.password,
        ssh_port: params.ssh_port,
        domain: params.domain,
        port: params.port,
        subnet: params.subnet,
    };

    match deploy::run(opts).await {
        Ok(()) => {
            respond(true, None, None);
        }
        Err(e) => {
            respond(false, Some(format!("{e}")), None);
        }
    }
}
```

**Step 4: Add to workspace, verify**

Run: `cargo check -p resonance-daemon`

**Step 5: Commit**

```
feat: add resonance-daemon with JSON-RPC stdio IPC
```

---

### Task 4: Scaffold Tauri v2 + Svelte project

**Files:**
- Create: `gui/` directory (entire Tauri + Svelte project)

**Step 1: Create Tauri project**

```bash
cd /home/neoko/Projects/resonance-vpn
pnpm create tauri-app gui --template svelte-ts --manager pnpm
```

If interactive, select: TypeScript, pnpm, Svelte, TypeScript flavor.

**Step 2: Install dependencies**

```bash
cd gui
pnpm install
pnpm add -D phosphor-icons-svelte
```

**Step 3: Configure Tauri for our project**

Update `gui/src-tauri/tauri.conf.json`:
- Set `identifier` to `"com.resonance.vpn"`
- Set `productName` to `"Resonance VPN"`
- Set `app.windows[0].title` to `"Resonance VPN"`
- Set `app.windows[0].width` to `380`
- Set `app.windows[0].height` to `640`
- Set `app.windows[0].resizable` to `false`
- Set `app.windows[0].decorations` to `false` (we'll use custom titlebar)
- Set `app.windows[0].transparent` to `true`
- Add trayIcon config:

```json
{
  "app": {
    "trayIcon": {
      "iconPath": "icons/tray-icon.png",
      "tooltip": "Resonance VPN"
    }
  }
}
```

**Step 4: Add Tauri plugins**

```bash
cd gui
pnpm tauri add shell
pnpm tauri add store
```

The `store` plugin handles persistent JSON storage (for profiles). The `shell` plugin handles sidecar management.

**Step 5: Configure sidecar in tauri.conf.json**

```json
{
  "bundle": {
    "externalBin": ["../target/release/resonance-daemon"]
  }
}
```

**Step 6: Configure capabilities**

Update `gui/src-tauri/capabilities/default.json`:

```json
{
  "$schema": "../gen/schemas/desktop-schema.json",
  "identifier": "main-capability",
  "windows": ["main"],
  "permissions": [
    "core:default",
    "store:default",
    {
      "identifier": "shell:allow-execute",
      "allow": [
        {
          "name": "../target/release/resonance-daemon",
          "sidecar": true,
          "args": true
        }
      ]
    }
  ]
}
```

**Step 7: Verify**

```bash
cd gui && pnpm tauri dev
```

Expected: Empty Tauri window opens.

**Step 8: Commit**

```
feat: scaffold Tauri v2 + Svelte GUI project
```

---

## Phase 2: Tauri Rust Backend

### Task 5: Tauri backend — daemon management and commands

**Files:**
- Modify: `gui/src-tauri/src/lib.rs`
- Create: `gui/src-tauri/src/daemon.rs`

**Step 1: Create daemon manager**

```rust
// gui/src-tauri/src/daemon.rs
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use tauri_plugin_shell::ShellExt;
use tauri_plugin_shell::process::{CommandChild, CommandEvent};
use tokio::sync::Mutex;

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
    child: Option<CommandChild>,
}

impl DaemonManager {
    pub fn new() -> Self {
        Self { child: None }
    }

    pub fn start(&mut self, app: &AppHandle) -> Result<(), String> {
        if self.child.is_some() {
            return Ok(()); // already running
        }

        let sidecar = app.shell()
            .sidecar("resonance-daemon")
            .map_err(|e| format!("Failed to create sidecar: {e}"))?;

        let (mut rx, child) = sidecar
            .spawn()
            .map_err(|e| format!("Failed to spawn daemon: {e}"))?;

        self.child = Some(child);

        let app_handle = app.clone();
        tauri::async_runtime::spawn(async move {
            while let Some(event) = rx.recv().await {
                match event {
                    CommandEvent::Stdout(line) => {
                        let line = String::from_utf8_lossy(&line);
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        if let Ok(daemon_event) = serde_json::from_str::<DaemonEvent>(line) {
                            let _ = app_handle.emit("daemon-event", &daemon_event);
                        }
                    }
                    CommandEvent::Stderr(line) => {
                        let line = String::from_utf8_lossy(&line);
                        log::info!("[daemon] {}", line.trim());
                    }
                    CommandEvent::Terminated(status) => {
                        log::info!("Daemon terminated: {:?}", status);
                        let _ = app_handle.emit("daemon-event", &DaemonEvent::StateChanged {
                            state: "disconnected".into(),
                            error: None,
                        });
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }

    pub fn send(&self, json: &str) -> Result<(), String> {
        if let Some(ref child) = self.child {
            child.write(format!("{json}\n").as_bytes())
                .map_err(|e| format!("Failed to write to daemon: {e}"))?;
            Ok(())
        } else {
            Err("Daemon not running".into())
        }
    }

    pub fn stop(&mut self) {
        if let Some(child) = self.child.take() {
            let _ = child.kill();
        }
    }
}
```

**Step 2: Create Tauri commands**

```rust
// gui/src-tauri/src/lib.rs
mod daemon;

use std::sync::Arc;
use daemon::DaemonManager;
use serde::Deserialize;
use tauri::Manager;
use tokio::sync::Mutex;

type DaemonState = Arc<Mutex<DaemonManager>>;

#[tauri::command]
async fn connect_vpn(
    server: String,
    psk: String,
    dns: Vec<String>,
    state: tauri::State<'_, DaemonState>,
) -> Result<(), String> {
    let daemon = state.lock().await;
    let request = serde_json::json!({
        "method": "connect",
        "params": { "server": server, "psk": psk, "dns": dns }
    });
    daemon.send(&request.to_string())
}

#[tauri::command]
async fn disconnect_vpn(state: tauri::State<'_, DaemonState>) -> Result<(), String> {
    let daemon = state.lock().await;
    let request = serde_json::json!({ "method": "disconnect" });
    daemon.send(&request.to_string())
}

#[tauri::command]
async fn get_vpn_status(state: tauri::State<'_, DaemonState>) -> Result<(), String> {
    let daemon = state.lock().await;
    let request = serde_json::json!({ "method": "status" });
    daemon.send(&request.to_string())
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
    let daemon = state.lock().await;
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
        .manage(Arc::new(Mutex::new(DaemonManager::new())) as DaemonState)
        .setup(|app| {
            // Start daemon on launch
            let state: tauri::State<DaemonState> = app.state();
            let mut daemon = tauri::async_runtime::block_on(state.lock());
            daemon.start(app.handle())?;

            // System tray
            setup_tray(app)?;

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            connect_vpn,
            disconnect_vpn,
            get_vpn_status,
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
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;

    Ok(())
}
```

**Step 3: Update Cargo.toml for src-tauri**

Ensure `gui/src-tauri/Cargo.toml` has:
```toml
[dependencies]
tauri = { version = "2", features = [] }
tauri-plugin-shell = "2"
tauri-plugin-store = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
tokio = { version = "1", features = ["sync"] }
log = "0.4"
```

**Step 4: Verify**

```bash
cd gui && pnpm tauri build --debug
```

**Step 5: Commit**

```
feat: add Tauri backend with daemon IPC and system tray
```

---

## Phase 3: Svelte Frontend

### Task 6: Global styles and layout

**Files:**
- Create: `gui/src/app.css`
- Modify: `gui/src/routes/+layout.svelte`
- Create: `gui/src/lib/components/Titlebar.svelte`

**Step 1: Create global CSS with theme tokens**

```css
/* gui/src/app.css */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

:root {
  --bg: #0a0a0f;
  --surface: rgba(255, 255, 255, 0.04);
  --surface-hover: rgba(255, 255, 255, 0.07);
  --surface-border: rgba(255, 255, 255, 0.06);
  --surface-border-hover: rgba(255, 255, 255, 0.10);
  --accent: #6366f1;
  --accent-glow: rgba(99, 102, 241, 0.3);
  --success: #22c55e;
  --success-glow: rgba(34, 197, 94, 0.3);
  --error: #ef4444;
  --error-glow: rgba(239, 68, 68, 0.3);
  --warning: #f59e0b;
  --text-primary: #e2e8f0;
  --text-secondary: #64748b;
  --text-tertiary: #475569;
  --radius-sm: 8px;
  --radius-md: 12px;
  --radius-lg: 20px;
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html, body {
  height: 100%;
  background: var(--bg);
  color: var(--text-primary);
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, system-ui, sans-serif;
  font-size: 14px;
  -webkit-font-smoothing: antialiased;
  overflow: hidden;
  user-select: none;
}

::-webkit-scrollbar {
  width: 6px;
}

::-webkit-scrollbar-track {
  background: transparent;
}

::-webkit-scrollbar-thumb {
  background: rgba(255, 255, 255, 0.1);
  border-radius: 3px;
}
```

**Step 2: Create custom titlebar**

```svelte
<!-- gui/src/lib/components/Titlebar.svelte -->
<script lang="ts">
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import IconMinusRegular from 'phosphor-icons-svelte/IconMinusRegular.svelte';
  import IconXRegular from 'phosphor-icons-svelte/IconXRegular.svelte';

  const appWindow = getCurrentWindow();
</script>

<div class="titlebar" data-tauri-drag-region>
  <span class="title" data-tauri-drag-region>Resonance VPN</span>
  <div class="controls">
    <button onclick={() => appWindow.minimize()} aria-label="Minimize">
      <IconMinusRegular />
    </button>
    <button class="close" onclick={() => appWindow.hide()} aria-label="Close">
      <IconXRegular />
    </button>
  </div>
</div>

<style>
  .titlebar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 40px;
    padding: 0 12px;
    background: rgba(255, 255, 255, 0.02);
    border-bottom: 1px solid var(--surface-border);
  }

  .title {
    font-size: 12px;
    font-weight: 600;
    color: var(--text-secondary);
    letter-spacing: 0.02em;
  }

  .controls {
    display: flex;
    gap: 4px;
  }

  .controls button {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border: none;
    background: transparent;
    color: var(--text-secondary);
    border-radius: 6px;
    cursor: pointer;
    font-size: 16px;
    transition: all 150ms ease;
  }

  .controls button:hover {
    background: var(--surface-hover);
    color: var(--text-primary);
  }

  .controls .close:hover {
    background: rgba(239, 68, 68, 0.15);
    color: var(--error);
  }
</style>
```

**Step 3: Create root layout**

```svelte
<!-- gui/src/routes/+layout.svelte -->
<script lang="ts">
  import '../app.css';
  import Titlebar from '$lib/components/Titlebar.svelte';

  let { children } = $props();
</script>

<div class="app">
  <Titlebar />
  <main>
    {@render children()}
  </main>
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: var(--bg);
  }

  main {
    flex: 1;
    overflow-y: auto;
  }
</style>
```

**Step 4: Commit**

```
feat: add global styles, custom titlebar, and root layout
```

---

### Task 7: State management — stores

**Files:**
- Create: `gui/src/lib/stores/vpn.svelte.ts`
- Create: `gui/src/lib/stores/profiles.svelte.ts`
- Create: `gui/src/lib/ipc/daemon.ts`

**Step 1: Create daemon IPC client**

```typescript
// gui/src/lib/ipc/daemon.ts
import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export type VpnState = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error';

export interface DaemonEvent {
  type: 'response' | 'state_changed' | 'stats' | 'deploy_progress';
  // response fields
  success?: boolean;
  error?: string | null;
  data?: Record<string, unknown>;
  // state_changed fields
  state?: VpnState;
  // stats fields
  tx_bytes?: number;
  rx_bytes?: number;
  tx_packets?: number;
  rx_packets?: number;
  // deploy_progress fields
  step?: number;
  total?: number;
  message?: string;
}

export type DaemonEventHandler = (event: DaemonEvent) => void;

let unlistenFn: UnlistenFn | null = null;
const handlers: Set<DaemonEventHandler> = new Set();

export async function initDaemonListener() {
  if (unlistenFn) return;
  unlistenFn = await listen<DaemonEvent>('daemon-event', (event) => {
    for (const handler of handlers) {
      handler(event.payload);
    }
  });
}

export function onDaemonEvent(handler: DaemonEventHandler): () => void {
  handlers.add(handler);
  return () => handlers.delete(handler);
}

export async function connectVpn(server: string, psk: string, dns: string[]) {
  return invoke('connect_vpn', { server, psk, dns });
}

export async function disconnectVpn() {
  return invoke('disconnect_vpn');
}

export async function getVpnStatus() {
  return invoke('get_vpn_status');
}

export interface DeployParams {
  host: string;
  user: string;
  sshKey?: string;
  password?: string;
  sshPort: number;
  domain?: string;
  port: number;
  subnet: string;
}

export async function deployServer(params: DeployParams) {
  return invoke('deploy_server', { params });
}
```

**Step 2: Create VPN state store**

```typescript
// gui/src/lib/stores/vpn.svelte.ts
import { onDaemonEvent, initDaemonListener, type VpnState, type DaemonEvent } from '$lib/ipc/daemon';

class VpnStore {
  state = $state<VpnState>('disconnected');
  assignedIp = $state<string | null>(null);
  sessionId = $state<string | null>(null);
  uptimeSecs = $state(0);
  error = $state<string | null>(null);
  txBytes = $state(0);
  rxBytes = $state(0);

  private uptimeInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    initDaemonListener();
    onDaemonEvent((event) => this.handleEvent(event));
  }

  private handleEvent(event: DaemonEvent) {
    if (event.type === 'state_changed') {
      this.state = event.state ?? 'disconnected';
      this.error = event.error ?? null;

      if (this.state === 'connected') {
        this.startUptimeCounter();
      } else if (this.state === 'disconnected') {
        this.stopUptimeCounter();
        this.assignedIp = null;
        this.sessionId = null;
        this.uptimeSecs = 0;
        this.txBytes = 0;
        this.rxBytes = 0;
      }
    }

    if (event.type === 'response' && event.success && event.data) {
      if ('assigned_ip' in event.data) {
        this.assignedIp = event.data.assigned_ip as string;
        this.sessionId = event.data.session_id as string;
      }
    }

    if (event.type === 'stats') {
      this.txBytes = event.tx_bytes ?? 0;
      this.rxBytes = event.rx_bytes ?? 0;
    }
  }

  private startUptimeCounter() {
    this.uptimeSecs = 0;
    this.uptimeInterval = setInterval(() => {
      this.uptimeSecs++;
    }, 1000);
  }

  private stopUptimeCounter() {
    if (this.uptimeInterval) {
      clearInterval(this.uptimeInterval);
      this.uptimeInterval = null;
    }
  }

  get isConnected() {
    return this.state === 'connected';
  }

  get isTransitioning() {
    return this.state === 'connecting' || this.state === 'disconnecting';
  }

  get formattedUptime() {
    const h = Math.floor(this.uptimeSecs / 3600);
    const m = Math.floor((this.uptimeSecs % 3600) / 60);
    const s = this.uptimeSecs % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }
}

export const vpnStore = new VpnStore();
```

**Step 3: Create profiles store**

```typescript
// gui/src/lib/stores/profiles.svelte.ts
import { Store } from '@tauri-apps/plugin-store';

export interface ServerProfile {
  id: string;
  name: string;
  server: string;
  psk: string;
  dns: string[];
  lastConnected?: number;
}

class ProfilesStore {
  profiles = $state<ServerProfile[]>([]);
  activeProfileId = $state<string | null>(null);
  private store: Store | null = null;

  get activeProfile(): ServerProfile | undefined {
    return this.profiles.find(p => p.id === this.activeProfileId);
  }

  async init() {
    this.store = await Store.load('profiles.json');
    const saved = await this.store.get<ServerProfile[]>('profiles');
    if (saved) this.profiles = saved;
    const activeId = await this.store.get<string>('activeProfileId');
    if (activeId) this.activeProfileId = activeId;
  }

  private async save() {
    if (!this.store) return;
    await this.store.set('profiles', this.profiles);
    await this.store.set('activeProfileId', this.activeProfileId);
    await this.store.save();
  }

  async addProfile(profile: Omit<ServerProfile, 'id'>) {
    const id = crypto.randomUUID();
    this.profiles = [...this.profiles, { ...profile, id }];
    if (!this.activeProfileId) this.activeProfileId = id;
    await this.save();
    return id;
  }

  async updateProfile(id: string, updates: Partial<ServerProfile>) {
    this.profiles = this.profiles.map(p =>
      p.id === id ? { ...p, ...updates } : p
    );
    await this.save();
  }

  async deleteProfile(id: string) {
    this.profiles = this.profiles.filter(p => p.id !== id);
    if (this.activeProfileId === id) {
      this.activeProfileId = this.profiles[0]?.id ?? null;
    }
    await this.save();
  }

  async setActive(id: string) {
    this.activeProfileId = id;
    await this.save();
  }

  async touchLastConnected(id: string) {
    await this.updateProfile(id, { lastConnected: Date.now() });
  }
}

export const profilesStore = new ProfilesStore();
```

**Step 4: Commit**

```
feat: add VPN state store, profiles store, and daemon IPC client
```

---

### Task 8: Main connection screen

**Files:**
- Create: `gui/src/lib/components/ConnectButton.svelte`
- Create: `gui/src/lib/components/ConnectionStats.svelte`
- Create: `gui/src/lib/components/ServerSelector.svelte`
- Modify: `gui/src/routes/+page.svelte`

**Step 1: Create connect button component**

```svelte
<!-- gui/src/lib/components/ConnectButton.svelte -->
<script lang="ts">
  import { vpnStore } from '$lib/stores/vpn.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { connectVpn, disconnectVpn } from '$lib/ipc/daemon';
  import IconPowerBold from 'phosphor-icons-svelte/IconPowerBold.svelte';

  async function toggle() {
    if (vpnStore.isTransitioning) return;

    if (vpnStore.isConnected) {
      await disconnectVpn();
    } else {
      const profile = profilesStore.activeProfile;
      if (!profile) return;
      await profilesStore.touchLastConnected(profile.id);
      await connectVpn(profile.server, profile.psk, profile.dns);
    }
  }

  let buttonClass = $derived(
    vpnStore.isConnected ? 'connected' :
    vpnStore.state === 'connecting' ? 'connecting' :
    vpnStore.state === 'error' ? 'error' : 'idle'
  );
</script>

<button
  class="connect-btn {buttonClass}"
  onclick={toggle}
  disabled={vpnStore.isTransitioning || !profilesStore.activeProfile}
  aria-label={vpnStore.isConnected ? 'Disconnect' : 'Connect'}
>
  <div class="glow"></div>
  <div class="ring"></div>
  <div class="icon">
    <IconPowerBold />
  </div>
</button>

<p class="status-text">
  {#if vpnStore.state === 'connected'}
    Connected
  {:else if vpnStore.state === 'connecting'}
    Connecting...
  {:else if vpnStore.state === 'disconnecting'}
    Disconnecting...
  {:else if vpnStore.state === 'error'}
    Connection failed
  {:else if !profilesStore.activeProfile}
    No server configured
  {:else}
    Disconnected
  {/if}
</p>

<style>
  .connect-btn {
    position: relative;
    width: 120px;
    height: 120px;
    border-radius: 50%;
    border: 2px solid var(--surface-border);
    background: var(--surface);
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 300ms ease;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .connect-btn:not(:disabled):hover {
    border-color: var(--surface-border-hover);
    background: var(--surface-hover);
  }

  .connect-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .icon {
    position: relative;
    z-index: 1;
    font-size: 32px;
    transition: color 300ms ease;
  }

  .glow {
    position: absolute;
    inset: -8px;
    border-radius: 50%;
    opacity: 0;
    transition: opacity 500ms ease;
  }

  .ring {
    position: absolute;
    inset: -4px;
    border-radius: 50%;
    border: 2px solid transparent;
  }

  /* Connected state */
  .connected {
    border-color: var(--success);
    color: var(--success);
  }

  .connected .glow {
    background: var(--success-glow);
    opacity: 1;
    animation: pulse 3s ease-in-out infinite;
  }

  /* Connecting state */
  .connecting .ring {
    border-color: var(--accent);
    border-top-color: transparent;
    animation: spin 1s linear infinite;
  }

  .connecting {
    border-color: var(--accent);
    color: var(--accent);
  }

  /* Error state */
  .error {
    border-color: var(--error);
    color: var(--error);
  }

  .status-text {
    margin-top: 16px;
    font-size: 13px;
    font-weight: 500;
    color: var(--text-secondary);
    text-align: center;
  }

  @keyframes pulse {
    0%, 100% { opacity: 0.3; }
    50% { opacity: 0.6; }
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
```

**Step 2: Create connection stats component**

```svelte
<!-- gui/src/lib/components/ConnectionStats.svelte -->
<script lang="ts">
  import { vpnStore } from '$lib/stores/vpn.svelte';
  import IconClockRegular from 'phosphor-icons-svelte/IconClockRegular.svelte';
  import IconArrowUpRegular from 'phosphor-icons-svelte/IconArrowUpRegular.svelte';
  import IconArrowDownRegular from 'phosphor-icons-svelte/IconArrowDownRegular.svelte';
  import IconGlobeRegular from 'phosphor-icons-svelte/IconGlobeRegular.svelte';

  function formatBytes(bytes: number): string {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
  }
</script>

{#if vpnStore.isConnected}
  <div class="stats">
    <div class="stat">
      <div class="stat-icon"><IconGlobeRegular /></div>
      <div class="stat-content">
        <span class="stat-label">IP Address</span>
        <span class="stat-value">{vpnStore.assignedIp}</span>
      </div>
    </div>
    <div class="stat">
      <div class="stat-icon"><IconClockRegular /></div>
      <div class="stat-content">
        <span class="stat-label">Uptime</span>
        <span class="stat-value">{vpnStore.formattedUptime}</span>
      </div>
    </div>
    <div class="stat">
      <div class="stat-icon upload"><IconArrowUpRegular /></div>
      <div class="stat-content">
        <span class="stat-label">Upload</span>
        <span class="stat-value">{formatBytes(vpnStore.txBytes)}</span>
      </div>
    </div>
    <div class="stat">
      <div class="stat-icon download"><IconArrowDownRegular /></div>
      <div class="stat-content">
        <span class="stat-label">Download</span>
        <span class="stat-value">{formatBytes(vpnStore.rxBytes)}</span>
      </div>
    </div>
  </div>
{/if}

<style>
  .stats {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    width: 100%;
    padding: 0 24px;
  }

  .stat {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 12px;
    background: var(--surface);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-sm);
    backdrop-filter: blur(20px);
  }

  .stat-icon {
    font-size: 18px;
    color: var(--text-tertiary);
  }

  .stat-icon.upload { color: var(--accent); }
  .stat-icon.download { color: var(--success); }

  .stat-content {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .stat-label {
    font-size: 11px;
    color: var(--text-tertiary);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  .stat-value {
    font-size: 13px;
    font-weight: 600;
    color: var(--text-primary);
  }
</style>
```

**Step 3: Create server selector component**

```svelte
<!-- gui/src/lib/components/ServerSelector.svelte -->
<script lang="ts">
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import IconCaretDownRegular from 'phosphor-icons-svelte/IconCaretDownRegular.svelte';
  import IconShieldCheckFill from 'phosphor-icons-svelte/IconShieldCheckFill.svelte';

  let open = $state(false);

  function select(id: string) {
    profilesStore.setActive(id);
    open = false;
  }
</script>

<div class="selector">
  <button class="selected" onclick={() => open = !open}>
    <div class="server-info">
      <IconShieldCheckFill />
      {#if profilesStore.activeProfile}
        <span class="name">{profilesStore.activeProfile.name}</span>
        <span class="address">{profilesStore.activeProfile.server}</span>
      {:else}
        <span class="name">No server</span>
        <span class="address">Add a server profile</span>
      {/if}
    </div>
    <IconCaretDownRegular />
  </button>

  {#if open && profilesStore.profiles.length > 1}
    <div class="dropdown">
      {#each profilesStore.profiles as profile (profile.id)}
        <button
          class="option"
          class:active={profile.id === profilesStore.activeProfileId}
          onclick={() => select(profile.id)}
        >
          <span class="name">{profile.name}</span>
          <span class="address">{profile.server}</span>
        </button>
      {/each}
    </div>
  {/if}
</div>

<style>
  .selector {
    position: relative;
    width: 100%;
    padding: 0 24px;
  }

  .selected {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    background: var(--surface);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-md);
    color: var(--text-primary);
    cursor: pointer;
    transition: all 150ms ease;
    backdrop-filter: blur(20px);
  }

  .selected:hover {
    border-color: var(--surface-border-hover);
    background: var(--surface-hover);
  }

  .server-info {
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 16px;
    color: var(--accent);
  }

  .name {
    font-weight: 600;
    font-size: 14px;
    color: var(--text-primary);
  }

  .address {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .dropdown {
    position: absolute;
    top: calc(100% + 4px);
    left: 24px;
    right: 24px;
    background: #14141f;
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-sm);
    z-index: 10;
    overflow: hidden;
  }

  .option {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 10px 16px;
    background: none;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
    transition: background 150ms ease;
  }

  .option:hover {
    background: var(--surface-hover);
  }

  .option.active {
    background: var(--surface);
  }
</style>
```

**Step 4: Create main page**

```svelte
<!-- gui/src/routes/+page.svelte -->
<script lang="ts">
  import { onMount } from 'svelte';
  import ConnectButton from '$lib/components/ConnectButton.svelte';
  import ConnectionStats from '$lib/components/ConnectionStats.svelte';
  import ServerSelector from '$lib/components/ServerSelector.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { vpnStore } from '$lib/stores/vpn.svelte';

  onMount(async () => {
    await profilesStore.init();
  });
</script>

<div class="page">
  <div class="connect-area">
    <ConnectButton />
  </div>

  <div class="bottom-area">
    <ConnectionStats />
    {#if !vpnStore.isConnected}
      <ServerSelector />
    {/if}
  </div>
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    height: 100%;
    padding: 24px 0;
  }

  .connect-area {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
  }

  .bottom-area {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding-bottom: 16px;
  }
</style>
```

**Step 5: Verify**

```bash
cd gui && pnpm tauri dev
```

Expected: App window shows connect button, server selector.

**Step 6: Commit**

```
feat: add main connection screen with button, stats, and server selector
```

---

### Task 9: Navigation and pages skeleton

**Files:**
- Create: `gui/src/lib/components/NavBar.svelte`
- Create: `gui/src/routes/profiles/+page.svelte`
- Create: `gui/src/routes/deploy/+page.svelte`
- Create: `gui/src/routes/settings/+page.svelte`
- Modify: `gui/src/routes/+layout.svelte`

**Step 1: Create bottom navigation bar**

```svelte
<!-- gui/src/lib/components/NavBar.svelte -->
<script lang="ts">
  import { page } from '$app/stores';
  import IconShieldCheckRegular from 'phosphor-icons-svelte/IconShieldCheckRegular.svelte';
  import IconShieldCheckFill from 'phosphor-icons-svelte/IconShieldCheckFill.svelte';
  import IconListRegular from 'phosphor-icons-svelte/IconListRegular.svelte';
  import IconListFill from 'phosphor-icons-svelte/IconListFill.svelte';
  import IconRocketLaunchRegular from 'phosphor-icons-svelte/IconRocketLaunchRegular.svelte';
  import IconRocketLaunchFill from 'phosphor-icons-svelte/IconRocketLaunchFill.svelte';
  import IconGearSixRegular from 'phosphor-icons-svelte/IconGearSixRegular.svelte';
  import IconGearSixFill from 'phosphor-icons-svelte/IconGearSixFill.svelte';

  const nav = [
    { href: '/', label: 'VPN', icon: IconShieldCheckRegular, activeIcon: IconShieldCheckFill },
    { href: '/profiles', label: 'Servers', icon: IconListRegular, activeIcon: IconListFill },
    { href: '/deploy', label: 'Deploy', icon: IconRocketLaunchRegular, activeIcon: IconRocketLaunchFill },
    { href: '/settings', label: 'Settings', icon: IconGearSixRegular, activeIcon: IconGearSixFill },
  ];

  let currentPath = $derived($page.url.pathname);
</script>

<nav class="navbar">
  {#each nav as item (item.href)}
    {@const active = currentPath === item.href}
    <a
      href={item.href}
      class="nav-item"
      class:active
    >
      {#if active}
        <svelte:component this={item.activeIcon} />
      {:else}
        <svelte:component this={item.icon} />
      {/if}
      <span>{item.label}</span>
    </a>
  {/each}
</nav>

<style>
  .navbar {
    display: flex;
    align-items: center;
    justify-content: space-around;
    height: 56px;
    border-top: 1px solid var(--surface-border);
    background: rgba(255, 255, 255, 0.02);
    flex-shrink: 0;
  }

  .nav-item {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding: 6px 16px;
    color: var(--text-tertiary);
    text-decoration: none;
    font-size: 18px;
    transition: color 150ms ease;
    border-radius: var(--radius-sm);
  }

  .nav-item span {
    font-size: 10px;
    font-weight: 500;
  }

  .nav-item:hover {
    color: var(--text-secondary);
  }

  .nav-item.active {
    color: var(--accent);
  }
</style>
```

**Step 2: Update layout to include navbar**

```svelte
<!-- gui/src/routes/+layout.svelte -->
<script lang="ts">
  import '../app.css';
  import Titlebar from '$lib/components/Titlebar.svelte';
  import NavBar from '$lib/components/NavBar.svelte';

  let { children } = $props();
</script>

<div class="app">
  <Titlebar />
  <main>
    {@render children()}
  </main>
  <NavBar />
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: var(--bg);
  }

  main {
    flex: 1;
    overflow-y: auto;
  }
</style>
```

**Step 3: Create stub pages**

```svelte
<!-- gui/src/routes/profiles/+page.svelte -->
<script lang="ts">
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { onMount } from 'svelte';
  import IconPlusRegular from 'phosphor-icons-svelte/IconPlusRegular.svelte';
  import IconTrashRegular from 'phosphor-icons-svelte/IconTrashRegular.svelte';
  import IconPencilSimpleRegular from 'phosphor-icons-svelte/IconPencilSimpleRegular.svelte';

  onMount(() => profilesStore.init());

  // Profile form state
  let showForm = $state(false);
  let editingId = $state<string | null>(null);
  let name = $state('');
  let server = $state('');
  let psk = $state('');
  let dns = $state('1.1.1.1');

  function openAdd() {
    editingId = null;
    name = '';
    server = '';
    psk = '';
    dns = '1.1.1.1';
    showForm = true;
  }

  function openEdit(profile: typeof profilesStore.profiles[0]) {
    editingId = profile.id;
    name = profile.name;
    server = profile.server;
    psk = profile.psk;
    dns = profile.dns.join(', ');
    showForm = true;
  }

  async function save() {
    const dnsArr = dns.split(',').map(s => s.trim()).filter(Boolean);
    if (editingId) {
      await profilesStore.updateProfile(editingId, { name, server, psk, dns: dnsArr });
    } else {
      await profilesStore.addProfile({ name, server, psk, dns: dnsArr });
    }
    showForm = false;
  }

  async function remove(id: string) {
    await profilesStore.deleteProfile(id);
  }
</script>

<div class="page">
  <div class="header">
    <h2>Server Profiles</h2>
    <button class="add-btn" onclick={openAdd}>
      <IconPlusRegular />
    </button>
  </div>

  {#if showForm}
    <div class="card form">
      <label>
        <span>Name</span>
        <input bind:value={name} placeholder="My VPN Server" />
      </label>
      <label>
        <span>Server</span>
        <input bind:value={server} placeholder="vpn.example.com:443" />
      </label>
      <label>
        <span>PSK</span>
        <input bind:value={psk} type="password" placeholder="Pre-shared key" />
      </label>
      <label>
        <span>DNS</span>
        <input bind:value={dns} placeholder="1.1.1.1, 8.8.8.8" />
      </label>
      <div class="form-actions">
        <button class="btn secondary" onclick={() => showForm = false}>Cancel</button>
        <button class="btn primary" onclick={save} disabled={!name || !server || !psk}>
          {editingId ? 'Update' : 'Add'}
        </button>
      </div>
    </div>
  {/if}

  <div class="list">
    {#each profilesStore.profiles as profile (profile.id)}
      <div class="card profile" class:active={profile.id === profilesStore.activeProfileId}>
        <button class="profile-main" onclick={() => profilesStore.setActive(profile.id)}>
          <span class="profile-name">{profile.name}</span>
          <span class="profile-server">{profile.server}</span>
        </button>
        <div class="profile-actions">
          <button onclick={() => openEdit(profile)}><IconPencilSimpleRegular /></button>
          <button onclick={() => remove(profile.id)}><IconTrashRegular /></button>
        </div>
      </div>
    {/each}

    {#if profilesStore.profiles.length === 0}
      <p class="empty">No servers configured. Add one to get started.</p>
    {/if}
  </div>
</div>

<style>
  .page {
    padding: 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  h2 {
    font-size: 16px;
    font-weight: 600;
  }

  .add-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 32px;
    height: 32px;
    border: 1px solid var(--surface-border);
    background: var(--surface);
    color: var(--text-secondary);
    border-radius: var(--radius-sm);
    cursor: pointer;
    font-size: 18px;
    transition: all 150ms ease;
  }

  .add-btn:hover {
    border-color: var(--accent);
    color: var(--accent);
  }

  .card {
    background: var(--surface);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-md);
    backdrop-filter: blur(20px);
  }

  .form {
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .form label {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form label span {
    font-size: 12px;
    color: var(--text-secondary);
    font-weight: 500;
  }

  .form input {
    padding: 8px 12px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
    outline: none;
    transition: border-color 150ms ease;
  }

  .form input:focus {
    border-color: var(--accent);
  }

  .form-actions {
    display: flex;
    gap: 8px;
    justify-content: flex-end;
    margin-top: 4px;
  }

  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    transition: all 150ms ease;
  }

  .btn.primary {
    background: var(--accent);
    color: white;
  }

  .btn.primary:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn.secondary {
    background: var(--surface);
    color: var(--text-secondary);
    border: 1px solid var(--surface-border);
  }

  .profile {
    display: flex;
    align-items: center;
    padding: 0;
    transition: border-color 150ms ease;
  }

  .profile.active {
    border-color: var(--accent);
  }

  .profile-main {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding: 12px 16px;
    background: none;
    border: none;
    color: var(--text-primary);
    cursor: pointer;
    text-align: left;
  }

  .profile-name {
    font-weight: 600;
    font-size: 14px;
  }

  .profile-server {
    font-size: 12px;
    color: var(--text-secondary);
  }

  .profile-actions {
    display: flex;
    gap: 2px;
    padding-right: 8px;
  }

  .profile-actions button {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    background: none;
    border: none;
    color: var(--text-tertiary);
    cursor: pointer;
    border-radius: 6px;
    font-size: 16px;
    transition: all 150ms ease;
  }

  .profile-actions button:hover {
    color: var(--text-primary);
    background: var(--surface-hover);
  }

  .empty {
    text-align: center;
    color: var(--text-tertiary);
    font-size: 13px;
    padding: 32px;
  }

  .list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
</style>
```

**Step 4: Create deploy page**

```svelte
<!-- gui/src/routes/deploy/+page.svelte -->
<script lang="ts">
  import { deployServer, onDaemonEvent, type DaemonEvent } from '$lib/ipc/daemon';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import IconRocketLaunchRegular from 'phosphor-icons-svelte/IconRocketLaunchRegular.svelte';
  import IconCheckCircleFill from 'phosphor-icons-svelte/IconCheckCircleFill.svelte';
  import IconWarningCircleFill from 'phosphor-icons-svelte/IconWarningCircleFill.svelte';

  let step = $state(1); // 1=form, 2=deploying, 3=done
  let host = $state('');
  let user = $state('root');
  let authMethod = $state<'key' | 'password'>('key');
  let sshKey = $state('~/.ssh/id_ed25519');
  let password = $state('');
  let sshPort = $state(22);
  let domain = $state('');
  let port = $state(443);
  let subnet = $state('10.8.0.0/24');

  let logs = $state<string[]>([]);
  let deployError = $state<string | null>(null);
  let deployedPsk = $state<string | null>(null);

  const cleanup = onDaemonEvent((event: DaemonEvent) => {
    if (event.type === 'deploy_progress') {
      logs = [...logs, `[${event.step}/${event.total}] ${event.message}`];
    }
    if (event.type === 'response' && step === 2) {
      if (event.success) {
        step = 3;
        // Auto-create profile
        if (event.data && 'psk' in event.data) {
          deployedPsk = event.data.psk as string;
          const serverAddr = port === 443 ? host : `${host}:${port}`;
          profilesStore.addProfile({
            name: domain || host,
            server: serverAddr,
            psk: deployedPsk,
            dns: ['1.1.1.1', '8.8.8.8'],
          });
        }
      } else {
        deployError = event.error ?? 'Deploy failed';
        step = 3;
      }
    }
  });

  async function startDeploy() {
    step = 2;
    logs = [];
    deployError = null;
    await deployServer({
      host,
      user,
      sshKey: authMethod === 'key' ? sshKey : undefined,
      password: authMethod === 'password' ? password : undefined,
      sshPort,
      domain: domain || undefined,
      port,
      subnet,
    });
  }
</script>

<div class="page">
  {#if step === 1}
    <h2>Deploy Server</h2>
    <p class="subtitle">Automatically provision a VPN server via SSH</p>

    <div class="form">
      <label>
        <span>Host</span>
        <input bind:value={host} placeholder="1.2.3.4 or vpn.example.com" />
      </label>
      <label>
        <span>SSH User</span>
        <input bind:value={user} />
      </label>

      <div class="auth-toggle">
        <button class:active={authMethod === 'key'} onclick={() => authMethod = 'key'}>SSH Key</button>
        <button class:active={authMethod === 'password'} onclick={() => authMethod = 'password'}>Password</button>
      </div>

      {#if authMethod === 'key'}
        <label>
          <span>SSH Key Path</span>
          <input bind:value={sshKey} />
        </label>
      {:else}
        <label>
          <span>Password</span>
          <input type="password" bind:value={password} />
        </label>
      {/if}

      <label>
        <span>SSH Port</span>
        <input type="number" bind:value={sshPort} />
      </label>
      <label>
        <span>Domain (optional, for Let's Encrypt)</span>
        <input bind:value={domain} placeholder="Leave empty for self-signed" />
      </label>
      <label>
        <span>Server Port</span>
        <input type="number" bind:value={port} />
      </label>
      <label>
        <span>VPN Subnet</span>
        <input bind:value={subnet} />
      </label>

      <button class="deploy-btn" onclick={startDeploy} disabled={!host}>
        <IconRocketLaunchRegular />
        Deploy
      </button>
    </div>

  {:else if step === 2}
    <h2>Deploying...</h2>
    <div class="log-area">
      {#each logs as line}
        <p class="log-line">{line}</p>
      {/each}
      <div class="spinner"></div>
    </div>

  {:else}
    {#if deployError}
      <div class="result error">
        <IconWarningCircleFill />
        <h2>Deploy Failed</h2>
        <p>{deployError}</p>
        <button class="btn primary" onclick={() => step = 1}>Try Again</button>
      </div>
    {:else}
      <div class="result success">
        <IconCheckCircleFill />
        <h2>Server Deployed</h2>
        <p>Server profile has been added automatically.</p>
        <button class="btn primary" onclick={() => step = 1}>Deploy Another</button>
      </div>
    {/if}
  {/if}
</div>

<style>
  .page {
    padding: 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  h2 { font-size: 16px; font-weight: 600; }

  .subtitle {
    font-size: 13px;
    color: var(--text-secondary);
  }

  .form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .form label {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form label span {
    font-size: 12px;
    color: var(--text-secondary);
    font-weight: 500;
  }

  .form input {
    padding: 8px 12px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
    outline: none;
  }

  .form input:focus { border-color: var(--accent); }

  .auth-toggle {
    display: flex;
    gap: 4px;
    background: var(--surface);
    border-radius: var(--radius-sm);
    padding: 3px;
  }

  .auth-toggle button {
    flex: 1;
    padding: 6px;
    border: none;
    background: none;
    color: var(--text-secondary);
    font-size: 13px;
    cursor: pointer;
    border-radius: 5px;
    transition: all 150ms ease;
  }

  .auth-toggle button.active {
    background: var(--accent);
    color: white;
  }

  .deploy-btn {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 10px;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: var(--radius-sm);
    font-size: 14px;
    font-weight: 500;
    cursor: pointer;
    margin-top: 4px;
  }

  .deploy-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  .log-area {
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-sm);
    padding: 12px;
    max-height: 400px;
    overflow-y: auto;
  }

  .log-line {
    font-size: 12px;
    font-family: 'JetBrains Mono', monospace;
    color: var(--text-secondary);
    padding: 2px 0;
  }

  .spinner {
    width: 16px;
    height: 16px;
    border: 2px solid var(--surface-border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-top: 8px;
  }

  @keyframes spin { to { transform: rotate(360deg); } }

  .result {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 40px 24px;
    text-align: center;
    font-size: 40px;
  }

  .result.success { color: var(--success); }
  .result.error { color: var(--error); }

  .result p {
    font-size: 13px;
    color: var(--text-secondary);
  }

  .btn {
    padding: 8px 16px;
    border: none;
    border-radius: var(--radius-sm);
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
  }

  .btn.primary {
    background: var(--accent);
    color: white;
  }
</style>
```

**Step 5: Create settings page**

```svelte
<!-- gui/src/routes/settings/+page.svelte -->
<script lang="ts">
  import IconInfoRegular from 'phosphor-icons-svelte/IconInfoRegular.svelte';

  let defaultDns = $state('1.1.1.1');
  let autoConnect = $state(false);
</script>

<div class="page">
  <h2>Settings</h2>

  <div class="section">
    <label class="setting">
      <div>
        <span class="setting-label">Default DNS</span>
        <span class="setting-desc">DNS servers for new profiles</span>
      </div>
      <input bind:value={defaultDns} placeholder="1.1.1.1" />
    </label>

    <label class="setting toggle">
      <div>
        <span class="setting-label">Auto-connect on launch</span>
        <span class="setting-desc">Connect to last used server when app starts</span>
      </div>
      <input type="checkbox" bind:checked={autoConnect} />
    </label>
  </div>

  <div class="section about">
    <IconInfoRegular />
    <div>
      <p class="about-name">Resonance VPN</p>
      <p class="about-version">v0.1.0</p>
    </div>
  </div>
</div>

<style>
  .page {
    padding: 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  h2 { font-size: 16px; font-weight: 600; }

  .section {
    display: flex;
    flex-direction: column;
    gap: 2px;
    background: var(--surface);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .setting {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    cursor: pointer;
  }

  .setting + .setting {
    border-top: 1px solid var(--surface-border);
  }

  .setting-label {
    font-size: 14px;
    font-weight: 500;
    display: block;
  }

  .setting-desc {
    font-size: 12px;
    color: var(--text-secondary);
    display: block;
    margin-top: 2px;
  }

  .setting input[type="text"],
  .setting input:not([type]) {
    width: 140px;
    padding: 6px 10px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--surface-border);
    border-radius: var(--radius-sm);
    color: var(--text-primary);
    font-size: 13px;
    font-family: inherit;
    outline: none;
    text-align: right;
  }

  .setting input:focus {
    border-color: var(--accent);
  }

  .setting input[type="checkbox"] {
    width: 40px;
    height: 22px;
    appearance: none;
    background: var(--text-tertiary);
    border-radius: 11px;
    position: relative;
    cursor: pointer;
    transition: background 200ms ease;
  }

  .setting input[type="checkbox"]::after {
    content: '';
    position: absolute;
    top: 3px;
    left: 3px;
    width: 16px;
    height: 16px;
    background: white;
    border-radius: 50%;
    transition: transform 200ms ease;
  }

  .setting input[type="checkbox"]:checked {
    background: var(--accent);
  }

  .setting input[type="checkbox"]:checked::after {
    transform: translateX(18px);
  }

  .about {
    flex-direction: row;
    align-items: center;
    gap: 12px;
    padding: 16px;
    font-size: 24px;
    color: var(--text-tertiary);
  }

  .about-name {
    font-size: 14px;
    font-weight: 600;
    color: var(--text-primary);
  }

  .about-version {
    font-size: 12px;
    color: var(--text-secondary);
  }
</style>
```

**Step 6: Commit**

```
feat: add navigation bar, profiles page, deploy wizard, and settings page
```

---

## Phase 4: Integration and Polish

### Task 10: Wire up SvelteKit routing for Tauri (static adapter)

**Files:**
- Modify: `gui/svelte.config.js`
- Modify: `gui/src/routes/+layout.ts`

**Step 1: Install static adapter**

```bash
cd gui && pnpm add -D @sveltejs/adapter-static
```

**Step 2: Configure SvelteKit for static SPA**

```javascript
// gui/svelte.config.js
import adapter from '@sveltejs/adapter-static';
import { vitePreprocess } from '@sveltejs/vite-plugin-svelte';

export default {
  preprocess: vitePreprocess(),
  kit: {
    adapter: adapter({
      fallback: 'index.html',
    }),
  },
};
```

**Step 3: Disable SSR**

```typescript
// gui/src/routes/+layout.ts
export const prerender = true;
export const ssr = false;
```

**Step 4: Verify full build**

```bash
cd gui && pnpm tauri build --debug
```

**Step 5: Commit**

```
feat: configure SvelteKit static adapter for Tauri
```

---

### Task 11: Deploy module — add progress callbacks to vpn-lib

**Files:**
- Modify: `crates/resonance-vpn-lib/src/deploy.rs`

The deploy module currently uses `log::info!` for progress. For the daemon to stream progress events to the GUI, we need a callback mechanism.

**Step 1: Add progress callback to DeployOpts**

```rust
// Add to DeployOpts:
pub struct DeployOpts {
    pub host: String,
    pub user: String,
    pub ssh_key: Option<String>,
    pub password: Option<String>,
    pub ssh_port: u16,
    pub domain: Option<String>,
    pub port: u16,
    pub subnet: String,
    pub on_progress: Option<Box<dyn Fn(u32, u32, &str) + Send>>,
}
```

**Step 2: Add progress calls in the deploy `run()` function**

Replace `log::info!` calls with both logging and progress callbacks:

```rust
fn progress(opts: &DeployOpts, step: u32, total: u32, msg: &str) {
    log::info!("[deploy {step}/{total}] {msg}");
    if let Some(ref cb) = opts.on_progress {
        cb(step, total, msg);
    }
}
```

Call `progress(&opts, 1, 10, "Connecting via SSH...")` etc. at each step.

**Step 3: Update resonance-client main.rs to pass `on_progress: None`**

**Step 4: Update daemon to pass a progress callback that emits events**

In `handle_deploy`:
```rust
let opts = deploy::DeployOpts {
    // ... other fields ...
    on_progress: Some(Box::new(|step, total, msg| {
        emit(&Event::DeployProgress {
            step,
            total,
            message: msg.to_string(),
        });
    })),
};
```

**Step 5: Update deploy::run to return the PSK**

Change return type from `Result<()>` to `Result<DeployResult>`:

```rust
pub struct DeployResult {
    pub server_addr: String,
    pub psk: String,
}
```

This lets the daemon send the PSK back to the GUI for auto-profile creation.

**Step 6: Verify**

```bash
cargo check --workspace
```

**Step 7: Commit**

```
feat: add progress callbacks and deploy result to deploy module
```

---

### Task 12: Final integration — build and test

**Step 1: Build daemon binary**

```bash
cargo build --release -p resonance-daemon
```

**Step 2: Build Tauri app**

```bash
cd gui && pnpm tauri build
```

**Step 3: Test manually**

1. Launch the built app
2. Add a server profile
3. Verify the daemon sidecar starts
4. Test connect/disconnect flow

**Step 4: Commit everything**

```
feat: complete Tauri GUI integration
```

---

## Summary of all crates after implementation

| Crate | Purpose | Binary |
|-------|---------|--------|
| `resonance-proto` | Crypto, frames, protobuf | - |
| `resonance-tun` | TUN device abstraction | - |
| `resonance-vpn-lib` | Shared VPN logic (tunnel, routing, deploy, TLS, config) | - |
| `resonance-client` | CLI client | `resonance-client` |
| `resonance-server` | VPN server | `resonance-server` |
| `resonance-daemon` | Privileged daemon for GUI | `resonance-daemon` |
| `gui/src-tauri` | Tauri desktop app | `resonance-vpn` (app bundle) |

## Key dependencies

| Package | Purpose |
|---------|---------|
| `phosphor-icons-svelte` | Icon library |
| `@tauri-apps/plugin-shell` | Sidecar management |
| `@tauri-apps/plugin-store` | Profile persistence |
| `@sveltejs/adapter-static` | SPA build for Tauri |
