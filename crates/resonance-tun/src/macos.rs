use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

use crate::{Result, TunConfig, TunError};

const UTUN_CONTROL_NAME: &str = "com.apple.net.utun_control";
const CTLIOCGINFO: libc::c_ulong = 0xc0644e03;

#[repr(C)]
struct CtlInfo {
    ctl_id: u32,
    ctl_name: [u8; 96],
}

#[repr(C)]
struct SockaddrCtl {
    sc_len: u8,
    sc_family: u8,
    ss_sysaddr: u16,
    sc_id: u32,
    sc_unit: u32,
    sc_reserved: [u32; 5],
}

pub struct TunDevice {
    fd: AsyncFd<OwnedFd>,
    name: String,
}

impl TunDevice {
    pub fn create(config: &TunConfig) -> Result<Self> {
        let unit: u32 = config
            .name
            .strip_prefix("utun")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
            + 1;

        let fd = unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, 2);
            if fd < 0 {
                return Err(TunError::Io(std::io::Error::last_os_error()));
            }
            OwnedFd::from_raw_fd(fd)
        };

        let mut ctl_info = CtlInfo {
            ctl_id: 0,
            ctl_name: [0u8; 96],
        };
        let name_bytes = UTUN_CONTROL_NAME.as_bytes();
        ctl_info.ctl_name[..name_bytes.len()].copy_from_slice(name_bytes);

        let ret = unsafe { libc::ioctl(fd.as_raw_fd(), CTLIOCGINFO, &mut ctl_info) };
        if ret < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }

        let addr = SockaddrCtl {
            sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
            sc_family: libc::AF_SYSTEM as u8,
            ss_sysaddr: 2,
            sc_id: ctl_info.ctl_id,
            sc_unit: unit,
            sc_reserved: [0; 5],
        };

        let ret = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as u32,
            )
        };
        if ret < 0 {
            return Err(TunError::Io(std::io::Error::last_os_error()));
        }

        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };

        let name = format!("utun{}", unit - 1);

        configure_interface(
            &name,
            &config.address.to_string(),
            &config.netmask.to_string(),
            config.mtu,
        )?;

        let async_fd = AsyncFd::new(fd).map_err(TunError::Io)?;

        log::info!("TUN device {} created", name);

        Ok(Self { fd: async_fd, name })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut full_buf = vec![0u8; buf.len() + 4];
        loop {
            let mut guard = self.fd.readable().await.map_err(TunError::Io)?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe { libc::read(fd, full_buf.as_mut_ptr() as *mut _, full_buf.len()) };
                if n < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(n as usize)
                }
            }) {
                Ok(Ok(n)) if n > 4 => {
                    let payload_len = n - 4;
                    buf[..payload_len].copy_from_slice(&full_buf[4..n]);
                    return Ok(payload_len);
                }
                Ok(Ok(_)) => return Ok(0),
                Ok(Err(e)) => return Err(TunError::Io(e)),
                Err(_would_block) => continue,
            }
        }
    }

    pub fn try_read(&self, buf: &mut [u8]) -> Result<usize> {
        let mut full_buf = vec![0u8; buf.len() + 4];
        match self.fd.try_io(tokio::io::Interest::READABLE, |inner| {
            let fd = inner.as_raw_fd();
            let n = unsafe { libc::read(fd, full_buf.as_mut_ptr() as *mut _, full_buf.len()) };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(n) if n > 4 => {
                let payload_len = n - 4;
                buf[..payload_len].copy_from_slice(&full_buf[4..n]);
                Ok(payload_len)
            }
            Ok(_) => Ok(0),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(0),
            Err(e) => Err(TunError::Io(e)),
        }
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        let af: u32 = if !buf.is_empty() && (buf[0] >> 4) == 6 {
            libc::AF_INET6 as u32
        } else {
            libc::AF_INET as u32
        };
        let mut full_buf = Vec::with_capacity(4 + buf.len());
        full_buf.extend_from_slice(&af.to_be_bytes());
        full_buf.extend_from_slice(buf);

        loop {
            let mut guard = self.fd.writable().await.map_err(TunError::Io)?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe { libc::write(fd, full_buf.as_ptr() as *const _, full_buf.len()) };
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
    let status = std::process::Command::new("ifconfig")
        .args([name, "inet", addr, addr, "mtu", &mtu.to_string(), "up"])
        .status()
        .map_err(TunError::Io)?;
    if !status.success() {
        return Err(TunError::Tun(format!("Failed to configure {name}")));
    }
    Ok(())
}
