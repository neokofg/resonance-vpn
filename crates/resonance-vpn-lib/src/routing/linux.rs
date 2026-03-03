use std::net::Ipv4Addr;
use std::process::Command;

pub struct RoutingState {
    pub original_gateway: String,
    pub original_dns: Option<String>,
    pub server_ip: String,
    pub tun_name: String,
}

impl RoutingState {
    pub fn setup(
        server_host: &str,
        assigned_ip: &str,
        tun_name: &str,
        dns: &[String],
    ) -> anyhow::Result<Self> {
        let server_ip = resolve_server_ip(server_host)?;
        let original_gateway = get_default_gateway()?;

        let original_dns = std::fs::read_to_string("/etc/resolv.conf").ok();

        run_cmd(
            "ip",
            &["route", "add", &server_ip, "via", &original_gateway],
        )?;
        run_cmd("ip", &["route", "replace", "default", "dev", tun_name])?;

        if !dns.is_empty() {
            let resolv = dns
                .iter()
                .map(|d| format!("nameserver {d}"))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write("/etc/resolv.conf", format!("{resolv}\n"))?;
            log::info!("DNS set to: {}", dns.join(", "));

            let _ = run_cmd(
                "iptables",
                &[
                    "-I", "OUTPUT", "-p", "udp", "--dport", "53", "!", "-o", tun_name, "-j", "DROP",
                ],
            );
            let _ = run_cmd(
                "iptables",
                &[
                    "-I", "OUTPUT", "-p", "tcp", "--dport", "53", "!", "-o", tun_name, "-j", "DROP",
                ],
            );
        }

        let _ = assigned_ip;
        log::info!("Routing configured: all traffic -> {tun_name}");

        Ok(Self {
            original_gateway,
            original_dns,
            server_ip,
            tun_name: tun_name.to_string(),
        })
    }

    pub fn cleanup(&self) {
        let _ = run_cmd(
            "iptables",
            &[
                "-D",
                "OUTPUT",
                "-p",
                "udp",
                "--dport",
                "53",
                "!",
                "-o",
                &self.tun_name,
                "-j",
                "DROP",
            ],
        );
        let _ = run_cmd(
            "iptables",
            &[
                "-D",
                "OUTPUT",
                "-p",
                "tcp",
                "--dport",
                "53",
                "!",
                "-o",
                &self.tun_name,
                "-j",
                "DROP",
            ],
        );

        let _ = run_cmd("ip", &["route", "del", &self.server_ip]);
        let _ = run_cmd(
            "ip",
            &["route", "replace", "default", "via", &self.original_gateway],
        );

        if let Some(ref dns) = self.original_dns {
            let _ = std::fs::write("/etc/resolv.conf", dns);
        }

        log::info!("Routing restored");
    }
}

impl Drop for RoutingState {
    fn drop(&mut self) {
        self.cleanup();
    }
}

fn resolve_server_ip(host: &str) -> anyhow::Result<String> {
    let host = host.split(':').next().unwrap_or(host);
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(host.to_string());
    }
    use std::net::ToSocketAddrs;
    let addr = format!("{host}:0")
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("Could not resolve {host}"))?;
    Ok(addr.ip().to_string())
}

fn get_default_gateway() -> anyhow::Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let gw = stdout
        .split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Could not find default gateway"))?
        .to_string();
    Ok(gw)
}

fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed", cmd, args.join(" "));
    }
    Ok(())
}
