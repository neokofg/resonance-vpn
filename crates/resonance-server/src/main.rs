mod config;
mod nat;
mod tls;
mod tunnel;

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc};
use tokio_tungstenite::tungstenite::http;

use resonance_proto::crypto;
use resonance_tun::{TunConfig, TunDevice};

use crate::config::Config;
use crate::tunnel::{IpPool, SessionMap};

#[derive(Parser)]
#[command(name = "resonance-server", about = "Resonance VPN Server")]
struct Cli {
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    let (network_addr, prefix) = config.parse_subnet()?;
    let server_ip = Ipv4Addr::new(
        network_addr.octets()[0],
        network_addr.octets()[1],
        network_addr.octets()[2],
        1,
    );

    let psk_hash = crypto::hash_psk(&config.psk);

    let tun = TunDevice::create(&TunConfig {
        name: config.tun_name.clone(),
        address: server_ip,
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1280,
    })?;
    let tun = Arc::new(tun);
    log::info!("TUN device {} ready at {server_ip}", tun.name());

    nat::setup_nat(tun.name(), &config.subnet)?;

    let tls_acceptor = tls::build_tls_acceptor(&config.tls.cert, &config.tls.key)?;
    let tls_acceptor = Arc::new(tls_acceptor);

    let sessions: SessionMap = Arc::new(RwLock::new(std::collections::HashMap::new()));
    let ip_pool = Arc::new(Mutex::new(IpPool::new(network_addr, prefix)));

    let (tun_tx, mut tun_rx) = mpsc::channel::<(Ipv4Addr, Bytes)>(1024);

    let tun_write = tun.clone();
    tokio::spawn(async move {
        while let Some((_src_ip, ip_packet)) = tun_rx.recv().await {
            if let Err(e) = tun_write.write(&ip_packet).await {
                log::error!("TUN write error: {e}");
            }
            while let Ok((_src_ip, ip_packet)) = tun_rx.try_recv() {
                if let Err(e) = tun_write.write(&ip_packet).await {
                    log::error!("TUN write error: {e}");
                }
            }
        }
    });

    let tun_read = tun.clone();
    let sessions_reader = sessions.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            match tun_read.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    if n >= 20 && (buf[0] >> 4) == 4 {
                        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
                        let sessions_r = sessions_reader.read().await;
                        if let Some(session) = sessions_r.get(&dst_ip) {
                            let _ = session.tx.send(Bytes::copy_from_slice(&buf[..n])).await;
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    log::error!("TUN read error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    });

    let listener = TcpListener::bind(&config.listen).await?;
    log::info!("Listening on {}", config.listen);

    let fake_html = if let Some(ref fake_site) = config.fake_site {
        let index = fake_site.root.join("index.html");
        if index.exists() {
            std::fs::read_to_string(index).unwrap_or_else(|_| default_fake_html())
        } else {
            default_fake_html()
        }
    } else {
        default_fake_html()
    };
    let _fake_html = Arc::new(fake_html);

    let conn_limit = Arc::new(Semaphore::new(64));

    let subnet = config.subnet.clone();
    let tun_name = config.tun_name.clone();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (tcp_stream, peer_addr) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("Accept error: {e}");
                        continue;
                    }
                };

                log::debug!("New connection from {peer_addr}");

                let tls_acceptor = tls_acceptor.clone();
                let sessions = sessions.clone();
                let ip_pool = ip_pool.clone();
                let tun_tx = tun_tx.clone();
                let conn_limit = conn_limit.clone();

                tokio::spawn(async move {
                    let _permit = match conn_limit.try_acquire() {
                        Ok(p) => p,
                        Err(_) => {
                            log::warn!("Connection limit reached, rejecting {peer_addr}");
                            return;
                        }
                    };
                    let tls_stream = match tokio_boring::accept(&tls_acceptor, tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            log::debug!("TLS handshake failed from {peer_addr}: {e}");
                            return;
                        }
                    };

                    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
                    let callback = |req: &http::Request<()>, resp: http::Response<()>| -> Result<http::Response<()>, http::Response<Option<String>>> {
                        if req.uri().path() == "/ws" {
                            Ok(resp)
                        } else {
                            Err(http::Response::builder()
                                .status(200)
                                .body(Some("Not a websocket path".to_string()))
                                .unwrap())
                        }
                    };

                    match tokio_tungstenite::accept_hdr_async_with_config(
                        tls_stream,
                        callback,
                        Some(ws_config),
                    )
                    .await
                    {
                        Ok(ws_stream) => {
                            tunnel::handle_client(
                                ws_stream,
                                psk_hash,
                                sessions,
                                ip_pool,
                                tun_tx,
                            )
                            .await;
                        }
                        Err(e) => {
                            log::debug!("WebSocket handshake failed from {peer_addr}: {e}");
                        }
                    }
                });
            }
            _ = &mut shutdown => {
                log::info!("Shutting down...");
                nat::cleanup_nat(&tun_name, &subnet);
                break;
            }
        }
    }

    Ok(())
}

fn default_fake_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Welcome</title></head>
<body>
<h1>Welcome</h1>
<p>This server is running normally.</p>
</body>
</html>"#
        .to_string()
}
