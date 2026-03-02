use std::process::Command;

pub fn setup_nat(tun_name: &str, subnet: &str) -> anyhow::Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    log::info!("Enabled IPv4 forwarding");

    let status = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-A",
            "POSTROUTING",
            "-s",
            subnet,
            "!",
            "-o",
            tun_name,
            "-j",
            "MASQUERADE",
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to add iptables MASQUERADE rule");
    }
    log::info!("Added MASQUERADE rule for {subnet}");

    let status = Command::new("iptables")
        .args(["-A", "FORWARD", "-i", tun_name, "-j", "ACCEPT"])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to add iptables FORWARD rule");
    }

    let status = Command::new("iptables")
        .args([
            "-A",
            "FORWARD",
            "-o",
            tun_name,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .status()?;
    if !status.success() {
        anyhow::bail!("Failed to add iptables FORWARD ESTABLISHED rule");
    }

    // TCP MSS clamping to avoid fragmentation through the tunnel
    let status = Command::new("iptables")
        .args([
            "-t", "mangle", "-A", "FORWARD",
            "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-o", tun_name,
            "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])
        .status()?;
    if !status.success() {
        log::warn!("Failed to add TCP MSS clamping rule (non-fatal)");
    }

    log::info!("NAT setup complete for {tun_name}");
    Ok(())
}

pub fn cleanup_nat(tun_name: &str, subnet: &str) {
    let _ = Command::new("iptables")
        .args([
            "-t",
            "nat",
            "-D",
            "POSTROUTING",
            "-s",
            subnet,
            "!",
            "-o",
            tun_name,
            "-j",
            "MASQUERADE",
        ])
        .status();
    let _ = Command::new("iptables")
        .args(["-D", "FORWARD", "-i", tun_name, "-j", "ACCEPT"])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-D",
            "FORWARD",
            "-o",
            tun_name,
            "-m",
            "state",
            "--state",
            "RELATED,ESTABLISHED",
            "-j",
            "ACCEPT",
        ])
        .status();
    let _ = Command::new("iptables")
        .args([
            "-t", "mangle", "-D", "FORWARD",
            "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
            "-o", tun_name,
            "-j", "TCPMSS", "--clamp-mss-to-pmtu",
        ])
        .status();
    log::info!("NAT cleanup complete");
}
