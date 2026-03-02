use serde::{Deserialize, Serialize};

// ── Requests (GUI -> Daemon via stdin) ──────────────────────────────────────

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

// ── Events / Responses (Daemon -> GUI via stdout) ───────────────────────────

#[derive(Serialize)]
#[serde(tag = "type")]
pub enum Event {
    #[serde(rename = "response")]
    Response(Response),
    #[serde(rename = "state_changed")]
    StateChanged {
        state: VpnState,
        error: Option<String>,
    },
    #[serde(rename = "stats")]
    Stats(Stats),
    #[serde(rename = "deploy_progress")]
    DeployProgress {
        step: u32,
        total: u32,
        message: String,
    },
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
    Connected {
        assigned_ip: String,
        session_id: String,
    },
    Status {
        state: VpnState,
        assigned_ip: Option<String>,
        uptime_secs: u64,
    },
    DeployComplete {
        server: String,
        psk: String,
    },
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

#[derive(Serialize)]
pub struct Stats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub rx_packets: u64,
}
