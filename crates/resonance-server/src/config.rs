use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Config {
    pub listen: String,
    pub tun_name: String,
    pub subnet: String,
    #[allow(dead_code)]
    pub dns: Vec<String>,
    pub psk: String,
    pub tls: TlsConfig,
    pub fake_site: Option<FakeSiteConfig>,
}

#[derive(Deserialize)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Deserialize)]
pub struct FakeSiteConfig {
    pub root: PathBuf,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.psk.len() < 8 {
            anyhow::bail!("PSK must be at least 8 characters");
        }
        if !self.tls.cert.exists() {
            anyhow::bail!("TLS cert not found: {:?}", self.tls.cert);
        }
        if !self.tls.key.exists() {
            anyhow::bail!("TLS key not found: {:?}", self.tls.key);
        }
        let (_, prefix) = self.parse_subnet()?;
        if !(16..=30).contains(&prefix) {
            anyhow::bail!("Subnet prefix must be between /16 and /30, got /{prefix}");
        }
        Ok(())
    }

    pub fn parse_subnet(&self) -> anyhow::Result<(std::net::Ipv4Addr, u8)> {
        let parts: Vec<&str> = self.subnet.split('/').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid subnet format: {}", self.subnet);
        }
        let addr: std::net::Ipv4Addr = parts[0].parse()?;
        let prefix: u8 = parts[1].parse()?;
        Ok((addr, prefix))
    }
}
