use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use russh::client;
use russh::keys::{self, PrivateKeyWithHashAlg};
use russh::{ChannelMsg, Disconnect};

const GITHUB_REPO: &str = "neokofg/resonance-vpn";
const INSTALL_DIR: &str = "/usr/local/bin";
const CONFIG_DIR: &str = "/etc/resonance";
const SERVICE_NAME: &str = "resonance-server";

pub struct DeployOpts {
    pub host: String,
    pub user: String,
    pub ssh_key: Option<String>,
    pub password: Option<String>,
    pub ssh_port: u16,
    pub domain: Option<String>,
    pub port: u16,
    pub subnet: String,
}

struct SshHandler;

impl client::Handler for SshHandler {
    type Error = anyhow::Error;

    async fn check_server_key(
        &mut self,
        _server_public_key: &keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

struct CommandResult {
    exit_code: u32,
    stdout: String,
    stderr: String,
}

struct SshSession {
    handle: client::Handle<SshHandler>,
}

impl SshSession {
    async fn exec(&self, cmd: &str) -> anyhow::Result<CommandResult> {
        log::info!("[ssh] {cmd}");
        let mut channel = self.handle.channel_open_session().await?;
        channel.exec(true, cmd).await?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit_code: Option<u32> = None;

        loop {
            let Some(msg) = channel.wait().await else {
                break;
            };
            match msg {
                ChannelMsg::Data { ref data } => {
                    stdout.extend_from_slice(data);
                }
                ChannelMsg::ExtendedData { ref data, ext } => {
                    if ext == 1 {
                        stderr.extend_from_slice(data);
                    }
                }
                ChannelMsg::ExitStatus { exit_status } => {
                    exit_code = Some(exit_status);
                }
                _ => {}
            }
        }

        Ok(CommandResult {
            exit_code: exit_code.unwrap_or(255),
            stdout: String::from_utf8_lossy(&stdout).to_string(),
            stderr: String::from_utf8_lossy(&stderr).to_string(),
        })
    }

    async fn exec_ok(&self, cmd: &str) -> anyhow::Result<String> {
        let result = self.exec(cmd).await?;
        if result.exit_code != 0 {
            bail!(
                "Command failed (exit {}): {}\nstderr: {}",
                result.exit_code,
                cmd,
                result.stderr.trim()
            );
        }
        Ok(result.stdout)
    }

    async fn write_file(&self, remote_path: &str, contents: &[u8]) -> anyhow::Result<()> {
        log::info!("[upload] {remote_path} ({} bytes)", contents.len());
        use std::fmt::Write;
        let mut b64 = String::new();
        for byte in contents {
            write!(b64, "{byte:02x}").unwrap();
        }
        // Use printf with hex escapes to avoid shell quoting issues
        // Split into chunks to avoid arg length limits
        self.exec_ok(&format!("printf '' > {remote_path}")).await?;
        for chunk in contents.chunks(4096) {
            let hex: String = chunk.iter().map(|b| format!("\\x{b:02x}")).collect();
            self.exec_ok(&format!("printf '{hex}' >> {remote_path}"))
                .await?;
        }
        Ok(())
    }

    async fn disconnect(self) -> anyhow::Result<()> {
        self.handle
            .disconnect(Disconnect::ByApplication, "", "")
            .await?;
        Ok(())
    }
}

pub async fn run(opts: DeployOpts) -> anyhow::Result<()> {
    log::info!(
        "Connecting to {}:{} as {}...",
        opts.host,
        opts.ssh_port,
        opts.user
    );
    let session = connect_ssh(&opts).await?;
    log::info!("SSH connection established.");

    let arch = detect_arch(&session).await?;
    log::info!("Server architecture: {arch}");

    install_deps(&session, opts.domain.is_some()).await?;

    download_server_binary(&session, &arch).await?;

    let psk = generate_psk()?;
    log::info!("Generated PSK.");

    generate_tls_certs(&session, &opts).await?;

    let config_content = build_config_toml(&opts, &psk);
    session.exec_ok(&format!("mkdir -p {CONFIG_DIR}")).await?;
    session
        .write_file(&format!("{CONFIG_DIR}/config.toml"), config_content.as_bytes())
        .await?;
    session
        .exec_ok(&format!("chmod 600 {CONFIG_DIR}/config.toml"))
        .await?;
    log::info!("Server config written.");

    let service_content = build_systemd_service();
    session
        .write_file(
            &format!("/etc/systemd/system/{SERVICE_NAME}.service"),
            service_content.as_bytes(),
        )
        .await?;
    log::info!("Systemd service installed.");

    session.exec_ok("systemctl daemon-reload").await?;
    session
        .exec_ok(&format!("systemctl enable --now {SERVICE_NAME}"))
        .await?;
    log::info!("Service started.");

    let status = session
        .exec(&format!("systemctl is-active {SERVICE_NAME}"))
        .await?;
    if status.stdout.trim() != "active" {
        log::warn!(
            "Service may not have started correctly. Check: journalctl -u {SERVICE_NAME}"
        );
    }

    session.disconnect().await?;

    let server_addr = if opts.port == 443 {
        opts.host.clone()
    } else {
        format!("{}:{}", opts.host, opts.port)
    };

    println!();
    println!("=== Deployment Complete ===");
    println!();
    println!("Connect with:");
    println!("  resonance-client connect --server {server_addr} --key {psk}");
    println!();

    Ok(())
}

async fn connect_ssh(opts: &DeployOpts) -> anyhow::Result<SshSession> {
    let config = Arc::new(client::Config {
        inactivity_timeout: Some(Duration::from_secs(60)),
        ..Default::default()
    });

    let mut handle = client::connect(config, (opts.host.as_str(), opts.ssh_port), SshHandler)
        .await
        .context(format!(
            "Failed to connect to {}:{}",
            opts.host, opts.ssh_port
        ))?;

    let auth_ok = if let Some(ref password) = opts.password {
        handle
            .authenticate_password(&opts.user, password)
            .await
            .context("Password authentication failed")?
    } else {
        let key_path = if let Some(ref path) = opts.ssh_key {
            path.replace('~', &crate::dirs_home())
        } else {
            let home = crate::dirs_home();
            let ed25519 = format!("{home}/.ssh/id_ed25519");
            let rsa = format!("{home}/.ssh/id_rsa");
            if std::path::Path::new(&ed25519).exists() {
                ed25519
            } else if std::path::Path::new(&rsa).exists() {
                rsa
            } else {
                bail!("No SSH key found. Provide --ssh-key or --password");
            }
        };

        log::info!("Using SSH key: {key_path}");
        let key_pair = keys::load_secret_key(&key_path, None)
            .context(format!("Failed to load SSH key: {key_path}"))?;

        let hash_alg = handle.best_supported_rsa_hash().await?.flatten();

        handle
            .authenticate_publickey(
                &opts.user,
                PrivateKeyWithHashAlg::new(Arc::new(key_pair), hash_alg),
            )
            .await
            .context("Public key authentication failed")?
    };

    if !auth_ok.success() {
        bail!("SSH authentication rejected by server");
    }

    Ok(SshSession { handle })
}

async fn detect_arch(session: &SshSession) -> anyhow::Result<String> {
    let output = session.exec_ok("uname -m").await?;
    match output.trim() {
        "x86_64" | "amd64" => Ok("linux-amd64".to_string()),
        "aarch64" | "arm64" => Ok("linux-arm64".to_string()),
        other => bail!("Unsupported server architecture: {other}"),
    }
}

async fn install_deps(session: &SshSession, needs_certbot: bool) -> anyhow::Result<()> {
    log::info!("Installing system dependencies...");

    let check = session.exec("which apt-get").await?;
    if check.exit_code != 0 {
        bail!("Only Debian/Ubuntu (apt-based) systems are supported for auto-deploy");
    }

    session
        .exec_ok("DEBIAN_FRONTEND=noninteractive apt-get update -qq")
        .await?;

    let mut packages = "iptables openssl curl tar".to_string();
    if needs_certbot {
        packages.push_str(" certbot");
    }

    session
        .exec_ok(&format!(
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {packages}"
        ))
        .await?;

    log::info!("Dependencies installed.");
    Ok(())
}

async fn download_server_binary(session: &SshSession, arch: &str) -> anyhow::Result<()> {
    // Check if binary is already installed (e.g. uploaded manually)
    let existing = session
        .exec(&format!("test -x {INSTALL_DIR}/resonance-server"))
        .await?;
    if existing.exit_code == 0 {
        log::info!("Server binary already present at {INSTALL_DIR}/resonance-server, skipping download.");
        return Ok(());
    }

    log::info!("Downloading server binary ({arch})...");

    let asset = format!("resonance-vpn-{arch}.tar.gz");
    let url = format!("https://github.com/{GITHUB_REPO}/releases/latest/download/{asset}");

    session
        .exec_ok(&format!("curl -fsSL '{url}' -o /tmp/{asset}"))
        .await
        .context("Failed to download server binary from GitHub Releases. \
                  You can manually upload it to /usr/local/bin/resonance-server and re-run deploy.")?;

    session
        .exec_ok(&format!("tar xzf /tmp/{asset} -C /tmp/"))
        .await?;

    session
        .exec_ok(&format!(
            "install -m 755 /tmp/resonance-server {INSTALL_DIR}/resonance-server"
        ))
        .await?;

    session
        .exec_ok(&format!(
            "rm -f /tmp/{asset} /tmp/resonance-server /tmp/resonance-client /tmp/config.example.toml"
        ))
        .await?;

    log::info!("Server binary installed to {INSTALL_DIR}/resonance-server");
    Ok(())
}

fn generate_psk() -> anyhow::Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow::anyhow!("Failed to generate random PSK: {e}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

async fn generate_tls_certs(session: &SshSession, opts: &DeployOpts) -> anyhow::Result<()> {
    session.exec_ok(&format!("mkdir -p {CONFIG_DIR}")).await?;

    if let Some(ref domain) = opts.domain {
        log::info!("Requesting Let's Encrypt certificate for {domain}...");

        session
            .exec_ok(&format!(
                "certbot certonly --standalone --non-interactive --agree-tos \
                 --register-unsafely-without-email -d {domain}"
            ))
            .await
            .context("certbot failed — is port 80 open and domain pointing to this server?")?;

        session
            .exec_ok(&format!(
                "ln -sf /etc/letsencrypt/live/{domain}/fullchain.pem {CONFIG_DIR}/cert.pem"
            ))
            .await?;
        session
            .exec_ok(&format!(
                "ln -sf /etc/letsencrypt/live/{domain}/privkey.pem {CONFIG_DIR}/key.pem"
            ))
            .await?;

        log::info!("Let's Encrypt certificate installed.");
    } else {
        log::info!("Generating self-signed TLS certificate...");

        let subj = format!("/CN={}", opts.host);
        session
            .exec_ok(&format!(
                "openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
                 -keyout {CONFIG_DIR}/key.pem -out {CONFIG_DIR}/cert.pem \
                 -days 3650 -nodes -subj '{subj}'"
            ))
            .await?;

        session
            .exec_ok(&format!("chmod 600 {CONFIG_DIR}/key.pem"))
            .await?;

        log::info!("Self-signed certificate generated.");
    }

    Ok(())
}

fn build_config_toml(opts: &DeployOpts, psk: &str) -> String {
    format!(
        r#"listen = "0.0.0.0:{port}"
tun_name = "rvpn0"
subnet = "{subnet}"
dns = ["1.1.1.1", "8.8.8.8"]
psk = "{psk}"

[tls]
cert = "{config_dir}/cert.pem"
key = "{config_dir}/key.pem"
"#,
        port = opts.port,
        subnet = opts.subnet,
        psk = psk,
        config_dir = CONFIG_DIR,
    )
}

fn build_systemd_service() -> String {
    format!(
        r#"[Unit]
Description=Resonance VPN Server
After=network.target

[Service]
Type=simple
ExecStart={install_dir}/resonance-server --config {config_dir}/config.toml
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"#,
        install_dir = INSTALL_DIR,
        config_dir = CONFIG_DIR,
    )
}
