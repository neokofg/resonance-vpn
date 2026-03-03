use std::net::Ipv4Addr;
use std::process::Command;

pub struct RoutingState {
    pub original_gateway: String,
    pub original_dns_service: Option<String>,
    pub original_dns: Option<Vec<String>>,
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

        run_cmd(
            "route",
            &["-n", "add", "-host", &server_ip, &original_gateway],
        )?;

        run_cmd(
            "route",
            &["-n", "add", "-net", "0.0.0.0/1", "-interface", tun_name],
        )?;
        run_cmd(
            "route",
            &["-n", "add", "-net", "128.0.0.0/1", "-interface", tun_name],
        )?;

        let mut original_dns_service = None;
        let mut original_dns_servers = None;

        if !dns.is_empty() {
            if let Ok(service) = get_primary_network_service() {
                original_dns_servers = get_dns_servers(&service).ok();
                original_dns_service = Some(service.clone());

                let mut args = vec!["networksetup", "-setdnsservers", &service];
                let dns_refs: Vec<&str> = dns.iter().map(|s| s.as_str()).collect();
                args.extend(dns_refs);
                run_cmd("networksetup", &args[1..])?;
                log::info!("DNS set to: {}", dns.join(", "));
            }
        }

        let _ = assigned_ip;
        log::info!("Routing configured: all traffic -> {tun_name}");

        Ok(Self {
            original_gateway,
            original_dns_service,
            original_dns: original_dns_servers,
            server_ip,
            tun_name: tun_name.to_string(),
        })
    }

    pub fn cleanup(&self) {
        let _ = run_cmd("route", &["-n", "delete", "-net", "0.0.0.0/1"]);
        let _ = run_cmd("route", &["-n", "delete", "-net", "128.0.0.0/1"]);

        let _ = run_cmd("route", &["-n", "delete", "-host", &self.server_ip]);

        if let Some(ref service) = self.original_dns_service {
            if let Some(ref servers) = self.original_dns {
                let mut args = vec!["-setdnsservers", service];
                let refs: Vec<&str> = servers.iter().map(|s| s.as_str()).collect();
                args.extend(refs);
                let _ = run_cmd("networksetup", &args);
            } else {
                let _ = run_cmd("networksetup", &["-setdnsservers", service, "Empty"]);
            }
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
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let gw = stdout
        .lines()
        .find(|l| l.contains("gateway:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("Could not find default gateway"))?;
    Ok(gw)
}

fn get_primary_network_service() -> anyhow::Result<String> {
    let output = Command::new("networksetup")
        .args(["-listallnetworkservices"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let service = stdout
        .lines()
        .skip(1)
        .find(|l| !l.starts_with('*'))
        .map(|l| l.trim().to_string())
        .ok_or_else(|| anyhow::anyhow!("Could not find primary network service"))?;
    Ok(service)
}

fn get_dns_servers(service: &str) -> anyhow::Result<Vec<String>> {
    let output = Command::new("networksetup")
        .args(["-getdnsservers", service])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.contains("There aren't any DNS Servers") {
        return Ok(Vec::new());
    }
    Ok(stdout.lines().map(|l| l.trim().to_string()).collect())
}

fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed", cmd, args.join(" "));
    }
    Ok(())
}
