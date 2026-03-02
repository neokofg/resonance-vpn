mod config;
mod routing;
mod tls;
mod tunnel;

use std::net::Ipv4Addr;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::watch;

use resonance_tun::{TunConfig, TunDevice};

#[derive(Parser)]
#[command(name = "resonance-client", about = "Resonance VPN Client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Connect to VPN server
    Connect {
        #[arg(short, long)]
        server: Option<String>,

        #[arg(short, long)]
        key: Option<String>,

        #[arg(short, long)]
        dns: Option<String>,

        #[arg(short = 'f', long, default_value = "~/.config/resonance/client.toml")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            server,
            key,
            dns,
            config: config_path,
        } => {
            let config_path = config_path.replace('~', &dirs_home());
            let file_config = config::Config::load(&config_path).ok();

            let server = server
                .or_else(|| file_config.as_ref().map(|c| c.server.clone()))
                .ok_or_else(|| {
                    anyhow::anyhow!("Server address required (--server or config file)")
                })?;

            let psk = key
                .or_else(|| file_config.as_ref().map(|c| c.psk.clone()))
                .ok_or_else(|| anyhow::anyhow!("PSK required (--key or config file)"))?;

            let dns_servers: Vec<String> = if let Some(dns_str) = dns {
                dns_str.split(',').map(|s| s.trim().to_string()).collect()
            } else if let Some(ref fc) = file_config {
                fc.dns
                    .clone()
                    .unwrap_or_else(|| vec!["1.1.1.1".to_string()])
            } else {
                vec!["1.1.1.1".to_string()]
            };

            connect(&server, &psk, &dns_servers).await?;
        }
    }

    Ok(())
}

async fn connect(server: &str, psk: &str, dns: &[String]) -> anyhow::Result<()> {
    log::info!("Connecting to {server}...");

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let tun_name = "rvpn0";
    let tun = Arc::new(TunDevice::create(&TunConfig {
        name: tun_name.to_string(),
        address: Ipv4Addr::new(10, 8, 0, 2),
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1280,
    })?);

    log::info!("TUN device {tun_name} created");

    let result = tokio::select! {
        r = tunnel::connect_and_run(server, psk, tun.clone(), shutdown_rx) => r?,
        _ = tokio::signal::ctrl_c() => {
            log::info!("Interrupted");
            let _ = shutdown_tx.send(true);
            return Ok(());
        }
    };

    log::info!("Connected! Assigned IP: {}", result.assigned_ip);

    let _routing = routing::RoutingState::setup(server, &result.assigned_ip, tun_name, dns)?;

    log::info!("VPN active. Press Ctrl+C to disconnect.");

    tokio::signal::ctrl_c().await?;
    log::info!("Disconnecting...");
    let _ = shutdown_tx.send(true);

    Ok(())
}

fn dirs_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
}
