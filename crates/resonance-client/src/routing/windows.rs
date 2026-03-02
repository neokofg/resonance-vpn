use std::net::Ipv4Addr;
use std::process::Command;

pub struct RoutingState {
    pub original_gateway: String,
    pub original_interface: String,
    pub original_dns_interface: Option<String>,
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
        let (original_gateway, original_interface) = get_default_gateway()?;

        // Route VPN server traffic through the original gateway
        run_cmd("route", &["add", &server_ip, "mask", "255.255.255.255", &original_gateway])?;

        // Split-route: 0.0.0.0/1 + 128.0.0.0/1 covers all traffic without replacing default
        run_cmd("route", &["add", "0.0.0.0", "mask", "128.0.0.0", assigned_ip, "metric", "5"])?;
        run_cmd("route", &["add", "128.0.0.0", "mask", "128.0.0.0", assigned_ip, "metric", "5"])?;

        let mut original_dns_interface = None;

        if !dns.is_empty() {
            // Find the primary network interface for DNS restoration
            original_dns_interface = get_primary_dns_interface().ok();

            // Set DNS on the TUN interface
            let dns_primary = &dns[0];
            run_cmd(
                "netsh",
                &["interface", "ip", "set", "dns", tun_name, "static", dns_primary],
            )?;
            for additional_dns in dns.iter().skip(1) {
                let _ = run_cmd(
                    "netsh",
                    &["interface", "ip", "add", "dns", tun_name, additional_dns],
                );
            }
            log::info!("DNS set to: {}", dns.join(", "));

            // Block DNS outside the tunnel to prevent leaks
            let _ = run_cmd(
                "netsh",
                &[
                    "advfirewall", "firewall", "add", "rule",
                    "name=ResonanceVPN-BlockDNS-UDP",
                    "dir=out", "action=block", "protocol=UDP", "remoteport=53",
                ],
            );
            let _ = run_cmd(
                "netsh",
                &[
                    "advfirewall", "firewall", "add", "rule",
                    "name=ResonanceVPN-BlockDNS-TCP",
                    "dir=out", "action=block", "protocol=TCP", "remoteport=53",
                ],
            );
            // Allow DNS through the TUN interface
            let _ = run_cmd(
                "netsh",
                &[
                    "advfirewall", "firewall", "add", "rule",
                    "name=ResonanceVPN-AllowDNS-UDP",
                    "dir=out", "action=allow", "protocol=UDP", "remoteport=53",
                    &format!("localip={assigned_ip}"),
                ],
            );
            let _ = run_cmd(
                "netsh",
                &[
                    "advfirewall", "firewall", "add", "rule",
                    "name=ResonanceVPN-AllowDNS-TCP",
                    "dir=out", "action=allow", "protocol=TCP", "remoteport=53",
                    &format!("localip={assigned_ip}"),
                ],
            );
        }

        log::info!("Routing configured: all traffic -> {tun_name}");

        Ok(Self {
            original_gateway,
            original_interface,
            original_dns_interface,
            server_ip,
            tun_name: tun_name.to_string(),
        })
    }

    pub fn cleanup(&self) {
        // Remove firewall rules
        let _ = run_cmd(
            "netsh",
            &["advfirewall", "firewall", "delete", "rule", "name=ResonanceVPN-BlockDNS-UDP"],
        );
        let _ = run_cmd(
            "netsh",
            &["advfirewall", "firewall", "delete", "rule", "name=ResonanceVPN-BlockDNS-TCP"],
        );
        let _ = run_cmd(
            "netsh",
            &["advfirewall", "firewall", "delete", "rule", "name=ResonanceVPN-AllowDNS-UDP"],
        );
        let _ = run_cmd(
            "netsh",
            &["advfirewall", "firewall", "delete", "rule", "name=ResonanceVPN-AllowDNS-TCP"],
        );

        // Remove split routes
        let _ = run_cmd("route", &["delete", "0.0.0.0", "mask", "128.0.0.0"]);
        let _ = run_cmd("route", &["delete", "128.0.0.0", "mask", "128.0.0.0"]);

        // Remove server-specific route
        let _ = run_cmd("route", &["delete", &self.server_ip]);

        // Restore DNS to DHCP on the original interface
        if let Some(ref iface) = self.original_dns_interface {
            let _ = run_cmd("netsh", &["interface", "ip", "set", "dns", iface, "dhcp"]);
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

fn get_default_gateway() -> anyhow::Result<(String, String)> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile", "-Command",
            "(Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 | ForEach-Object { $_.NextHop + '|' + $_.InterfaceAlias })",
        ])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let parts: Vec<&str> = stdout.split('|').collect();
    if parts.len() != 2 {
        anyhow::bail!("Could not parse default gateway from: {stdout}");
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn get_primary_dns_interface() -> anyhow::Result<String> {
    let output = Command::new("powershell")
        .args([
            "-NoProfile", "-Command",
            "(Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Sort-Object InterfaceMetric | Select-Object -First 1).Name",
        ])
        .output()?;
    let name = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if name.is_empty() {
        anyhow::bail!("Could not find primary network interface");
    }
    Ok(name)
}

fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed", cmd, args.join(" "));
    }
    Ok(())
}
