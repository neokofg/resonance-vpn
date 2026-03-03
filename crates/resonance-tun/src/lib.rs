#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum TunError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TUN error: {0}")]
    Tun(String),
}

pub type Result<T> = std::result::Result<T, TunError>;

pub struct TunConfig {
    pub name: String,
    pub address: std::net::Ipv4Addr,
    pub netmask: std::net::Ipv4Addr,
    pub mtu: u32,
}

#[cfg(target_os = "linux")]
pub use linux::TunDevice;
#[cfg(target_os = "macos")]
pub use macos::TunDevice;
#[cfg(target_os = "windows")]
pub use windows::TunDevice;
