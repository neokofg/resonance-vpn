use std::sync::Arc;

use crate::{Result, TunConfig, TunError};

pub struct TunDevice {
    session: Arc<wintun::Session>,
    name: String,
}

impl TunDevice {
    pub fn create(config: &TunConfig) -> Result<Self> {
        let wintun = unsafe { wintun::load() }.map_err(|e| TunError::Tun(e.to_string()))?;
        let adapter = wintun::Adapter::create(&wintun, &config.name, "ResonanceVPN", None)
            .map_err(|e| TunError::Tun(e.to_string()))?;

        let status = std::process::Command::new("netsh")
            .args([
                "interface",
                "ip",
                "set",
                "address",
                &config.name,
                "static",
                &config.address.to_string(),
                &config.netmask.to_string(),
            ])
            .status()
            .map_err(TunError::Io)?;
        if !status.success() {
            return Err(TunError::Tun("Failed to set address".to_string()));
        }

        let _ = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &config.name,
                &format!("mtu={}", config.mtu),
            ])
            .status();

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| TunError::Tun(e.to_string()))?;

        log::info!("TUN device {} created", config.name);

        Ok(Self {
            session: Arc::new(session),
            name: config.name.clone(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let session = self.session.clone();
        let max_len = buf.len();
        let packet: wintun::Packet =
            tokio::task::spawn_blocking(move || session.receive_blocking())
                .await
                .map_err(|e: tokio::task::JoinError| TunError::Tun(e.to_string()))?
                .map_err(|e: wintun::Error| TunError::Tun(e.to_string()))?;

        let len = packet.bytes().len().min(max_len);
        buf[..len].copy_from_slice(&packet.bytes()[..len]);
        Ok(len)
    }

    pub fn try_read(&self, buf: &mut [u8]) -> Result<usize> {
        match self.session.try_receive() {
            Ok(Some(packet)) => {
                let len = packet.bytes().len().min(buf.len());
                buf[..len].copy_from_slice(&packet.bytes()[..len]);
                Ok(len)
            }
            Ok(None) => Ok(0),
            Err(e) => Err(TunError::Tun(e.to_string())),
        }
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        let session = self.session.clone();
        let data = buf.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut packet = session
                .allocate_send_packet(data.len() as u16)
                .map_err(|e: wintun::Error| TunError::Tun(e.to_string()))?;
            packet.bytes_mut().copy_from_slice(&data);
            session.send_packet(packet);
            Ok::<usize, TunError>(data.len())
        })
        .await
        .map_err(|e: tokio::task::JoinError| TunError::Tun(e.to_string()))?
    }
}
