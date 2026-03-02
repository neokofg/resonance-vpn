use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

use crate::{TunConfig, TunError, Result};

const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
const TUNSETIFF: libc::c_ulong = 0x400454ca;

#[repr(C)]
#[derive(Default)]
struct Ifreq {
    ifr_name: [u8; libc::IFNAMSIZ],
    ifr_flags: libc::c_short,
    _padding: [u8; 22],
}

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl TunDevice {
    pub fn create(config: &TunConfig) -> Result<Self> {
        let fd = unsafe {
            let fd = libc::open(b"/dev/net/tun\0".as_ptr() as *const _, libc::O_RDWR);
            if fd < 0 {
                return Err(TunError::Io(std::io::Error::last_os_error()));
            }
            OwnedFd::from_raw_fd(fd)
        };

        let mut req = Ifreq::default();
        let name_bytes = config.name.as_bytes();
        let copy_len = name_bytes.len().min(libc::IFNAMSIZ - 1);
        req.ifr_name[..copy_len].copy_from_slice(&name_bytes[..copy_len]);
        req.ifr_flags = IFF_TUN | IFF_NO_PI;

        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), TUNSETIFF, &req) };
        if ret < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }

        // Set non-blocking for async
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };

        let name = config.name.clone();

        // Configure interface with ip command
        configure_interface(
            &name,
            &config.address.to_string(),
            &config.netmask.to_string(),
            config.mtu,
        )?;

        let async_fd = AsyncFd::new(fd).map_err(TunError::Io)?;

        log::info!("TUN device {} created", name);

        Ok(Self {
            fd: async_fd,
            name,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.readable().await.map_err(TunError::Io)?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe {
                    libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result.map_err(TunError::Io),
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        loop {
            let mut guard = self.fd.writable().await.map_err(TunError::Io)?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe {
                    libc::write(fd, buf.as_ptr() as *const _, buf.len())
                };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(result) => return result.map_err(TunError::Io),
                Err(_would_block) => continue,
            }
        }
    }
}

fn configure_interface(name: &str, addr: &str, _netmask: &str, mtu: u32) -> Result<()> {
    let status = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{addr}/24"), "dev", name])
        .status()
        .map_err(TunError::Io)?;
    if !status.success() {
        return Err(TunError::Tun(format!("Failed to set address on {name}")));
    }

    let status = std::process::Command::new("ip")
        .args(["link", "set", name, "mtu", &mtu.to_string(), "up"])
        .status()
        .map_err(TunError::Io)?;
    if !status.success() {
        return Err(TunError::Tun(format!("Failed to bring up {name}")));
    }

    Ok(())
}
