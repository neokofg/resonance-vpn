mod ipc;

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::{Mutex, watch};

use resonance_tun::{TunConfig, TunDevice};
use resonance_vpn_lib::{deploy, routing, tunnel};

use ipc::{ConnectParams, DeployParams, Event, Request, Response, ResponseData, VpnState};

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
        use std::io::Write;
        let stdout = std::io::stdout();
        let mut handle = stdout.lock();
        let _ = writeln!(handle, "{json}");
        let _ = handle.flush();
    }
}

fn emit_state(state: VpnState, error: Option<String>) {
    emit(&Event::StateChanged { state, error });
}

fn emit_ok(data: Option<ResponseData>) {
    emit(&Event::Response(Response {
        success: true,
        error: None,
        data,
    }));
}

fn emit_err(msg: impl Into<String>) {
    emit(&Event::Response(Response {
        success: false,
        error: Some(msg.into()),
        data: None,
    }));
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .target(env_logger::Target::Stderr)
        .init();

    log::info!("resonance-daemon starting");

    let state = Arc::new(Mutex::new(DaemonState::new()));
    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: Request = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                emit_err(format!("invalid request: {e}"));
                continue;
            }
        };

        match request {
            Request::Connect(params) => {
                handle_connect(Arc::clone(&state), params).await;
            }
            Request::Disconnect => {
                handle_disconnect(Arc::clone(&state)).await;
            }
            Request::Status => {
                handle_status(Arc::clone(&state)).await;
            }
            Request::Deploy(params) => {
                handle_deploy(params).await;
            }
        }
    }

    log::info!("stdin closed, shutting down");
    Ok(())
}

async fn handle_connect(state: Arc<Mutex<DaemonState>>, params: ConnectParams) {
    {
        let s = state.lock().await;
        if s.vpn_state == VpnState::Connected || s.vpn_state == VpnState::Connecting {
            emit_err("already connected or connecting");
            return;
        }
    }

    {
        let mut s = state.lock().await;
        s.vpn_state = VpnState::Connecting;
    }
    emit_state(VpnState::Connecting, None);

    let state_clone = Arc::clone(&state);
    tokio::spawn(async move {
        if let Err(e) = do_connect(state_clone, params).await {
            log::error!("connect failed: {e:#}");
            emit_state(VpnState::Error, Some(format!("{e:#}")));
            let mut s = state.lock().await;
            s.vpn_state = VpnState::Error;
            s.shutdown_tx = None;
            s.assigned_ip = None;
            s.connected_since = None;
        }
    });
}

async fn do_connect(state: Arc<Mutex<DaemonState>>, params: ConnectParams) -> anyhow::Result<()> {
    let handshake = tunnel::handshake(&params.server, &params.psk)
        .await
        .context("handshake failed")?;

    let assigned_ip_str = handshake.assigned_ip.clone();
    let session_id = handshake.session_id.clone();

    let assigned_ip: Ipv4Addr = assigned_ip_str
        .parse()
        .context("invalid assigned IP from server")?;
    let tun_name = "rvpn0";
    let tun = Arc::new(
        TunDevice::create(&TunConfig {
            name: tun_name.to_string(),
            address: assigned_ip,
            netmask: Ipv4Addr::new(255, 255, 255, 0),
            mtu: 1280,
        })
        .context("TUN device creation failed")?,
    );

    let _routing =
        routing::RoutingState::setup(&params.server, &assigned_ip_str, tun_name, &params.dns)
            .context("routing setup failed")?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let stats = Arc::new(tunnel::TunnelStats::new());
    {
        let mut s = state.lock().await;
        s.vpn_state = VpnState::Connected;
        s.shutdown_tx = Some(shutdown_tx);
        s.assigned_ip = Some(assigned_ip_str.clone());
        s.connected_since = Some(Instant::now());
    }

    emit_state(VpnState::Connected, None);
    emit_ok(Some(ResponseData::Connected {
        assigned_ip: assigned_ip_str,
        session_id,
    }));

    let stats_reporter = {
        let stats = Arc::clone(&stats);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let tx = stats.tx_bytes.load(std::sync::atomic::Ordering::Relaxed);
                let rx = stats.rx_bytes.load(std::sync::atomic::Ordering::Relaxed);
                log::debug!("stats: tx={tx} rx={rx}");
                emit(&Event::Stats(ipc::Stats {
                    tx_bytes: tx,
                    rx_bytes: rx,
                    tx_packets: stats.tx_packets.load(std::sync::atomic::Ordering::Relaxed),
                    rx_packets: stats.rx_packets.load(std::sync::atomic::Ordering::Relaxed),
                }));
            }
        })
    };

    let result = tunnel::run_forwarding(handshake, tun, shutdown_rx, stats).await;
    stats_reporter.abort();

    {
        let mut s = state.lock().await;
        s.vpn_state = VpnState::Disconnected;
        s.shutdown_tx = None;
        s.assigned_ip = None;
        s.connected_since = None;
    }
    emit_state(VpnState::Disconnected, None);

    drop(_routing);

    result
}

async fn handle_disconnect(state: Arc<Mutex<DaemonState>>) {
    let mut s = state.lock().await;
    if let Some(tx) = s.shutdown_tx.take() {
        s.vpn_state = VpnState::Disconnecting;
        emit_state(VpnState::Disconnecting, None);
        let _ = tx.send(true);
        emit_ok(None);
    } else {
        emit_err("not connected");
    }
}

async fn handle_status(state: Arc<Mutex<DaemonState>>) {
    let s = state.lock().await;
    let uptime_secs = s
        .connected_since
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0);

    emit_ok(Some(ResponseData::Status {
        state: s.vpn_state,
        assigned_ip: s.assigned_ip.clone(),
        uptime_secs,
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
            emit_ok(None);
        }
        Err(e) => {
            emit_err(format!("{e:#}"));
        }
    }
}
