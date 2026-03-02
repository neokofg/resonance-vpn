# Resonance VPN Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a TUN-based VPN that bypasses AI DPI by masquerading as HTTPS/HTTP2 WebSocket with Chrome TLS fingerprint.

**Architecture:** Cargo workspace with 4 crates. Client creates TUN, encrypts IP packets with BLAKE3 XOR, sends over WebSocket tunneled through TLS 1.3 with Chrome fingerprint. Server decrypts and NATs to internet.

**Tech Stack:** Rust, tokio, boring/tokio-boring (BoringSSL), tokio-tungstenite, h2, blake3, hkdf, prost, clap

---

### Task 1: Project Scaffold

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/resonance-proto/Cargo.toml`
- Create: `crates/resonance-proto/src/lib.rs`
- Create: `crates/resonance-tun/Cargo.toml`
- Create: `crates/resonance-tun/src/lib.rs`
- Create: `crates/resonance-server/Cargo.toml`
- Create: `crates/resonance-server/src/main.rs`
- Create: `crates/resonance-client/Cargo.toml`
- Create: `crates/resonance-client/src/main.rs`
- Create: `proto/resonance.proto`
- Create: `crates/resonance-proto/build.rs`

**Step 1: Create workspace Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "crates/resonance-proto",
    "crates/resonance-tun",
    "crates/resonance-server",
    "crates/resonance-client",
]

[workspace.dependencies]
tokio = { version = "1", features = ["full"] }
blake3 = "1"
hkdf = "0.12"
sha2 = "0.10"
subtle = "2"
bytes = "1"
prost = "0.13"
log = "0.4"
env_logger = "0.11"
thiserror = "2"
serde = { version = "1", features = ["derive"] }
toml = "0.8"
anyhow = "1"

[profile.release]
lto = true
codegen-units = 1
panic = "abort"
strip = true
opt-level = 3

[profile.release.package."*"]
opt-level = 3
```

**Step 2: Create resonance-proto crate**

`crates/resonance-proto/Cargo.toml`:
```toml
[package]
name = "resonance-proto"
version = "0.1.0"
edition = "2024"

[dependencies]
blake3 = { workspace = true }
hkdf = { workspace = true }
sha2 = { workspace = true }
subtle = { workspace = true }
bytes = { workspace = true }
prost = { workspace = true }
thiserror = { workspace = true }

[build-dependencies]
prost-build = "0.13"
```

`crates/resonance-proto/src/lib.rs`:
```rust
pub mod crypto;
pub mod frame;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/resonance.rs"));
}
```

**Step 3: Create protobuf schema**

`proto/resonance.proto`:
```protobuf
syntax = "proto3";
package resonance;

message AuthRequest {
    bytes psk_hash = 1;
}

message ServerHello {
    string session_id = 1;
    bytes key_material = 2;
    string assigned_ip = 3;
}

message Ping {
    uint64 timestamp = 1;
}

message Pong {
    uint64 timestamp = 1;
}

message Error {
    string message = 1;
}
```

`crates/resonance-proto/build.rs`:
```rust
fn main() {
    prost_build::compile_protos(
        &["../../proto/resonance.proto"],
        &["../../proto/"],
    )
    .unwrap();
}
```

**Step 4: Create resonance-tun crate**

`crates/resonance-tun/Cargo.toml`:
```toml
[package]
name = "resonance-tun"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = { workspace = true }
log = { workspace = true }
thiserror = { workspace = true }

[target.'cfg(target_os = "linux")'.dependencies]
nix = { version = "0.29", features = ["ioctl", "net"] }

[target.'cfg(target_os = "macos")'.dependencies]
nix = { version = "0.29", features = ["net"] }

[target.'cfg(target_os = "windows")'.dependencies]
wintun = "0.8"
```

`crates/resonance-tun/src/lib.rs`:
```rust
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
```

**Step 5: Create resonance-server crate**

`crates/resonance-server/Cargo.toml`:
```toml
[package]
name = "resonance-server"
version = "0.1.0"
edition = "2024"

[dependencies]
resonance-proto = { path = "../resonance-proto" }
resonance-tun = { path = "../resonance-tun" }
tokio = { workspace = true }
blake3 = { workspace = true }
bytes = { workspace = true }
prost = { workspace = true }
log = { workspace = true }
env_logger = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
toml = { workspace = true }
anyhow = { workspace = true }
boring = "5"
tokio-boring = "5"
tokio-tungstenite = "0.26"
futures-util = "0.3"
hyper = { version = "1", features = ["http2", "server"] }
hyper-util = { version = "0.1", features = ["tokio"] }
http-body-util = "0.1"
clap = { version = "4", features = ["derive"] }
fastrand = "2"
```

`crates/resonance-server/src/main.rs`:
```rust
fn main() {
    println!("resonance-server");
}
```

**Step 6: Create resonance-client crate**

`crates/resonance-client/Cargo.toml`:
```toml
[package]
name = "resonance-client"
version = "0.1.0"
edition = "2024"

[dependencies]
resonance-proto = { path = "../resonance-proto" }
resonance-tun = { path = "../resonance-tun" }
tokio = { workspace = true }
blake3 = { workspace = true }
bytes = { workspace = true }
prost = { workspace = true }
log = { workspace = true }
env_logger = { workspace = true }
thiserror = { workspace = true }
serde = { workspace = true }
toml = { workspace = true }
anyhow = { workspace = true }
boring = "5"
tokio-boring = "5"
tokio-tungstenite = "0.26"
futures-util = "0.3"
h2 = "0.4"
http = "1"
clap = { version = "4", features = ["derive"] }
```

`crates/resonance-client/src/main.rs`:
```rust
fn main() {
    println!("resonance-client");
}
```

**Step 7: Verify workspace compiles**

Run: `cargo check`
Expected: Successful compilation with no errors.

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: scaffold workspace with 4 crates and protobuf schema"
```

---

### Task 2: Protocol Crate (resonance-proto)

**Files:**
- Create: `crates/resonance-proto/src/crypto.rs`
- Create: `crates/resonance-proto/src/frame.rs`
- Modify: `crates/resonance-proto/src/lib.rs`

**Context:** Adapted from oldaccord's `/accord-backend/src/protocol/crypto.rs` and `frame.rs`. Key differences from oldaccord:
- No padding buckets (removed per user request)
- No length masking (WebSocket handles framing)
- Simplified frame format: `[8 bytes nonce][encrypted data][16 bytes MAC]` inside WS binary frames
- No opcode/request_id in frame (VPN only carries IP packets + control messages as protobuf)

**Step 1: Write crypto.rs**

`crates/resonance-proto/src/crypto.rs`:
```rust
use blake3::Hasher as Blake3Hasher;
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;

const SESSION_SALT: &[u8] = b"resonance-vpn-v1";
const SCRAMBLE_KEY_LABEL: &[u8] = b"scramble";
const MAC_KEY_LABEL: &[u8] = b"mac";

#[derive(Clone)]
pub struct SessionKeys {
    pub scramble_key: [u8; 32],
    pub mac_key: [u8; 32],
}

impl SessionKeys {
    pub fn derive(key_material: &[u8]) -> Self {
        let hk = Hkdf::<Sha256>::new(Some(SESSION_SALT), key_material);

        let mut session_key = [0u8; 32];
        hk.expand(b"session", &mut session_key)
            .expect("HKDF expand failed");

        let scramble_key = blake3_derive(&session_key, SCRAMBLE_KEY_LABEL);
        let mac_key = blake3_derive(&session_key, MAC_KEY_LABEL);

        Self {
            scramble_key,
            mac_key,
        }
    }

    /// XOR data in-place with BLAKE3 XOF keystream. Same nonce produces same keystream,
    /// so applying twice decrypts.
    #[inline]
    pub fn xor_keystream(&self, data: &mut [u8], nonce: u64) {
        let mut hasher = Blake3Hasher::new_keyed(&self.scramble_key);
        hasher.update(&nonce.to_le_bytes());
        let mut output_reader = hasher.finalize_xof();

        const CHUNK_SIZE: usize = 64;
        let mut keystream_chunk = [0u8; CHUNK_SIZE];

        let full_chunks = data.len() / CHUNK_SIZE;
        let remainder = data.len() % CHUNK_SIZE;

        for i in 0..full_chunks {
            output_reader.fill(&mut keystream_chunk);
            let offset = i * CHUNK_SIZE;

            for j in (0..CHUNK_SIZE).step_by(8) {
                let data_slice = &mut data[offset + j..offset + j + 8];
                let key_slice = &keystream_chunk[j..j + 8];

                let d = u64::from_le_bytes(data_slice.try_into().unwrap());
                let k = u64::from_le_bytes(key_slice.try_into().unwrap());
                data_slice.copy_from_slice(&(d ^ k).to_le_bytes());
            }
        }

        if remainder > 0 {
            let offset = full_chunks * CHUNK_SIZE;
            output_reader.fill(&mut keystream_chunk[..remainder]);
            for i in 0..remainder {
                data[offset + i] ^= keystream_chunk[i];
            }
        }
    }

    /// Compute 16-byte BLAKE3 MAC over nonce + encrypted data.
    pub fn compute_mac(&self, nonce: &[u8], encrypted_data: &[u8]) -> [u8; 16] {
        let mut hasher = Blake3Hasher::new_keyed(&self.mac_key);
        hasher.update(nonce);
        hasher.update(encrypted_data);

        let hash = hasher.finalize();
        let mut mac = [0u8; 16];
        mac.copy_from_slice(&hash.as_bytes()[..16]);
        mac
    }

    pub fn verify_mac(
        &self,
        nonce: &[u8],
        encrypted_data: &[u8],
        expected_mac: &[u8; 16],
    ) -> bool {
        let computed = self.compute_mac(nonce, encrypted_data);
        computed.ct_eq(expected_mac).into()
    }
}

fn blake3_derive(key: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut hasher = Blake3Hasher::new_keyed(key);
    hasher.update(label);
    *hasher.finalize().as_bytes()
}

/// Hash PSK with BLAKE3 for safe transmission.
pub fn hash_psk(psk: &str) -> [u8; 32] {
    *blake3::hash(psk.as_bytes()).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let keys1 = SessionKeys::derive(&[42u8; 32]);
        let keys2 = SessionKeys::derive(&[42u8; 32]);
        assert_eq!(keys1.scramble_key, keys2.scramble_key);
        assert_eq!(keys1.mac_key, keys2.mac_key);
    }

    #[test]
    fn test_key_derivation_different_input() {
        let keys1 = SessionKeys::derive(&[1u8; 32]);
        let keys2 = SessionKeys::derive(&[2u8; 32]);
        assert_ne!(keys1.scramble_key, keys2.scramble_key);
    }

    #[test]
    fn test_xor_roundtrip() {
        let keys = SessionKeys::derive(&[42u8; 32]);
        let original = b"Hello, World! This is a test.".to_vec();
        let nonce = 12345u64;

        let mut data = original.clone();
        keys.xor_keystream(&mut data, nonce);
        assert_ne!(data, original);

        keys.xor_keystream(&mut data, nonce);
        assert_eq!(data, original);
    }

    #[test]
    fn test_xor_different_nonces() {
        let keys = SessionKeys::derive(&[42u8; 32]);
        let original = b"test data".to_vec();

        let mut data1 = original.clone();
        let mut data2 = original.clone();
        keys.xor_keystream(&mut data1, 1);
        keys.xor_keystream(&mut data2, 2);
        assert_ne!(data1, data2);
    }

    #[test]
    fn test_mac_verification() {
        let keys = SessionKeys::derive(&[42u8; 32]);
        let nonce = 1u64.to_le_bytes();
        let data = b"encrypted payload";

        let mac = keys.compute_mac(&nonce, data);
        assert!(keys.verify_mac(&nonce, data, &mac));

        let mut bad_mac = mac;
        bad_mac[0] ^= 1;
        assert!(!keys.verify_mac(&nonce, data, &bad_mac));
    }

    #[test]
    fn test_hash_psk() {
        let hash1 = hash_psk("my-secret");
        let hash2 = hash_psk("my-secret");
        let hash3 = hash_psk("different");
        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }
}
```

**Step 2: Write frame.rs**

Simplified frame codec for VPN. No opcodes, no padding. Each WebSocket binary message is one frame:
- Type byte: 0x00 = data (IP packet), 0x01 = control (protobuf)
- For data frames: `[1 byte type][8 bytes nonce][encrypted IP packet][16 bytes MAC]`
- For control frames: `[1 byte type][protobuf payload]` (unencrypted, only used during handshake before keys are established)

`crates/resonance-proto/src/frame.rs`:
```rust
use bytes::{Bytes, BytesMut};

use crate::crypto::SessionKeys;

pub const NONCE_SIZE: usize = 8;
pub const MAC_SIZE: usize = 16;
pub const TYPE_SIZE: usize = 1;
pub const FRAME_OVERHEAD: usize = TYPE_SIZE + NONCE_SIZE + MAC_SIZE; // 25 bytes

const NONCE_REKEY_THRESHOLD: u64 = u64::MAX - 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    Data = 0x00,
    Control = 0x01,
}

#[derive(Debug)]
pub enum Frame {
    /// Encrypted IP packet
    Data(Bytes),
    /// Unencrypted protobuf control message
    Control(Bytes),
}

pub struct FrameEncoder {
    keys: SessionKeys,
    nonce_counter: u64,
}

impl FrameEncoder {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            nonce_counter: 0,
        }
    }

    fn next_nonce(&mut self) -> Result<u64, FrameError> {
        if self.nonce_counter >= NONCE_REKEY_THRESHOLD {
            return Err(FrameError::NonceExhausted);
        }
        let nonce = self.nonce_counter;
        self.nonce_counter += 1;
        Ok(nonce)
    }

    /// Encrypt an IP packet into a data frame.
    /// Returns bytes ready to send as a WebSocket binary message.
    pub fn encode_data(&mut self, ip_packet: &[u8]) -> Result<Bytes, FrameError> {
        let nonce = self.next_nonce()?;
        let nonce_bytes = nonce.to_le_bytes();

        let mut encrypted = ip_packet.to_vec();
        self.keys.xor_keystream(&mut encrypted, nonce);

        let mac = self.keys.compute_mac(&nonce_bytes, &encrypted);

        let total = TYPE_SIZE + NONCE_SIZE + encrypted.len() + MAC_SIZE;
        let mut output = BytesMut::with_capacity(total);
        output.extend_from_slice(&[FrameType::Data as u8]);
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&encrypted);
        output.extend_from_slice(&mac);

        Ok(output.freeze())
    }

    /// Encode a control message (not encrypted).
    pub fn encode_control(payload: &[u8]) -> Bytes {
        let mut output = BytesMut::with_capacity(TYPE_SIZE + payload.len());
        output.extend_from_slice(&[FrameType::Control as u8]);
        output.extend_from_slice(payload);
        output.freeze()
    }
}

pub struct FrameDecoder {
    keys: SessionKeys,
    last_nonce: u64,
    replay_bitmap: u128,
}

impl FrameDecoder {
    pub fn new(keys: SessionKeys) -> Self {
        Self {
            keys,
            last_nonce: 0,
            replay_bitmap: 0,
        }
    }

    /// Decode a WebSocket binary message into a frame.
    pub fn decode(&mut self, data: &[u8]) -> Result<Frame, FrameError> {
        if data.is_empty() {
            return Err(FrameError::TooShort);
        }

        match data[0] {
            0x00 => self.decode_data(&data[1..]),
            0x01 => Ok(Frame::Control(Bytes::copy_from_slice(&data[1..]))),
            t => Err(FrameError::UnknownType(t)),
        }
    }

    fn decode_data(&mut self, data: &[u8]) -> Result<Frame, FrameError> {
        if data.len() < NONCE_SIZE + MAC_SIZE {
            return Err(FrameError::TooShort);
        }

        let nonce_bytes = &data[..NONCE_SIZE];
        let nonce = u64::from_le_bytes(nonce_bytes.try_into().unwrap());

        let encrypted = &data[NONCE_SIZE..data.len() - MAC_SIZE];
        let mac_slice = &data[data.len() - MAC_SIZE..];

        let mut expected_mac = [0u8; MAC_SIZE];
        expected_mac.copy_from_slice(mac_slice);

        if !self.keys.verify_mac(nonce_bytes, encrypted, &expected_mac) {
            return Err(FrameError::MacFailed);
        }

        if !self.check_replay(nonce) {
            return Err(FrameError::Replay);
        }

        let mut decrypted = encrypted.to_vec();
        self.keys.xor_keystream(&mut decrypted, nonce);

        Ok(Frame::Data(Bytes::from(decrypted)))
    }

    fn check_replay(&mut self, nonce: u64) -> bool {
        if nonce == 0 && self.last_nonce == 0 && self.replay_bitmap == 0 {
            self.replay_bitmap = 1;
            return true;
        }

        if nonce > self.last_nonce {
            let shift = (nonce - self.last_nonce).min(128) as u32;
            self.replay_bitmap = self.replay_bitmap.checked_shl(shift).unwrap_or(0);
            self.replay_bitmap |= 1;
            self.last_nonce = nonce;
            return true;
        }

        let diff = self.last_nonce - nonce;
        if diff >= 128 {
            return false;
        }

        let bit = 1u128 << diff;
        if self.replay_bitmap & bit != 0 {
            return false;
        }

        self.replay_bitmap |= bit;
        true
    }
}

/// Decode a control message without keys (used during handshake).
pub fn decode_control(data: &[u8]) -> Result<Bytes, FrameError> {
    if data.is_empty() {
        return Err(FrameError::TooShort);
    }
    if data[0] != FrameType::Control as u8 {
        return Err(FrameError::UnknownType(data[0]));
    }
    Ok(Bytes::copy_from_slice(&data[1..]))
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame too short")]
    TooShort,
    #[error("unknown frame type: 0x{0:02x}")]
    UnknownType(u8),
    #[error("MAC verification failed")]
    MacFailed,
    #[error("replay attack detected")]
    Replay,
    #[error("nonce exhausted, reconnect required")]
    NonceExhausted,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_keys() -> SessionKeys {
        SessionKeys::derive(&[42u8; 32])
    }

    #[test]
    fn test_data_roundtrip() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let original = b"Hello IP packet data";
        let encoded = encoder.encode_data(original).unwrap();
        let decoded = decoder.decode(&encoded).unwrap();

        match decoded {
            Frame::Data(data) => assert_eq!(&data[..], original),
            _ => panic!("expected data frame"),
        }
    }

    #[test]
    fn test_control_roundtrip() {
        let payload = b"protobuf data";
        let encoded = FrameEncoder::encode_control(payload);
        let decoded = decode_control(&encoded).unwrap();
        assert_eq!(&decoded[..], payload);
    }

    #[test]
    fn test_replay_rejected() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let encoded = encoder.encode_data(b"test").unwrap();
        decoder.decode(&encoded).unwrap(); // first time OK

        let result = decoder.decode(&encoded); // replay
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_mac_rejected() {
        let keys = test_keys();
        let mut encoder = FrameEncoder::new(keys.clone());
        let mut decoder = FrameDecoder::new(keys);

        let mut encoded = encoder.encode_data(b"test").unwrap().to_vec();
        let len = encoded.len();
        encoded[len - 1] ^= 1; // flip last MAC byte

        let result = decoder.decode(&encoded);
        assert!(result.is_err());
    }
}
```

**Step 3: Update lib.rs**

`crates/resonance-proto/src/lib.rs`:
```rust
pub mod crypto;
pub mod frame;

pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/resonance.rs"));
}
```

**Step 4: Verify tests pass**

Run: `cargo test -p resonance-proto`
Expected: All tests pass.

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: implement protocol crate with BLAKE3 XOR crypto and frame codec"
```

---

### Task 3: TUN Device Abstraction (resonance-tun)

**Files:**
- Create: `crates/resonance-tun/src/linux.rs`
- Create: `crates/resonance-tun/src/macos.rs`
- Create: `crates/resonance-tun/src/windows.rs`
- Modify: `crates/resonance-tun/src/lib.rs`

**Step 1: Implement Linux TUN**

`crates/resonance-tun/src/linux.rs`:
```rust
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, RawFd, FromRawFd, OwnedFd};
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
    // ip addr add <addr>/24 dev <name>
    let status = std::process::Command::new("ip")
        .args(["addr", "add", &format!("{addr}/24"), "dev", name])
        .status()
        .map_err(TunError::Io)?;
    if !status.success() {
        return Err(TunError::Tun(format!("Failed to set address on {name}")));
    }

    // ip link set <name> mtu <mtu> up
    let status = std::process::Command::new("ip")
        .args(["link", "set", name, "mtu", &mtu.to_string(), "up"])
        .status()
        .map_err(TunError::Io)?;
    if !status.success() {
        return Err(TunError::Tun(format!("Failed to bring up {name}")));
    }

    Ok(())
}
```

**Step 2: Implement macOS TUN stub**

`crates/resonance-tun/src/macos.rs`:
```rust
use std::os::fd::{AsRawFd, RawFd, FromRawFd, OwnedFd};
use tokio::io::unix::AsyncFd;

use crate::{TunConfig, TunError, Result};

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
        // Extract unit number from name (e.g., "utun5" -> 6, because utun is 0-indexed with +1)
        let unit: u32 = config
            .name
            .strip_prefix("utun")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0)
            + 1;

        let fd = unsafe {
            let fd = libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, 2 /* SYSPROTO_CONTROL */);
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
            ss_sysaddr: 2, // AF_SYS_CONTROL
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

        // Set non-blocking
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };

        let name = format!("utun{}", unit - 1);

        configure_interface(&name, &config.address.to_string(), &config.netmask.to_string(), config.mtu)?;

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
        // macOS utun prepends a 4-byte protocol header
        let mut full_buf = vec![0u8; buf.len() + 4];
        loop {
            let mut guard = self.fd.readable().await.map_err(TunError::Io)?;
            match guard.try_io(|inner| {
                let fd = inner.as_raw_fd();
                let n = unsafe {
                    libc::read(fd, full_buf.as_mut_ptr() as *mut _, full_buf.len())
                };
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

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        // Prepend 4-byte AF_INET/AF_INET6 header
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
                let n = unsafe {
                    libc::write(fd, full_buf.as_ptr() as *const _, full_buf.len())
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
    let status = std::process::Command::new("ifconfig")
        .args([name, "inet", addr, addr, "mtu", &mtu.to_string(), "up"])
        .status()
        .map_err(TunError::Io)?;
    if !status.success() {
        return Err(TunError::Tun(format!("Failed to configure {name}")));
    }
    Ok(())
}
```

**Step 3: Implement Windows TUN stub**

`crates/resonance-tun/src/windows.rs`:
```rust
use crate::{TunConfig, TunError, Result};

pub struct TunDevice {
    session: wintun::Session,
    name: String,
}

impl TunDevice {
    pub fn create(config: &TunConfig) -> Result<Self> {
        let wintun = unsafe { wintun::load() }.map_err(|e| TunError::Tun(e.to_string()))?;
        let adapter = wintun::Adapter::create(&wintun, &config.name, "ResonanceVPN", None)
            .map_err(|e| TunError::Tun(e.to_string()))?;

        // Set IP address via netsh
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

        // Set MTU
        let status = std::process::Command::new("netsh")
            .args([
                "interface",
                "ipv4",
                "set",
                "subinterface",
                &config.name,
                &format!("mtu={}", config.mtu),
            ])
            .status()
            .map_err(TunError::Io)?;

        let session = adapter
            .start_session(wintun::MAX_RING_CAPACITY)
            .map_err(|e| TunError::Tun(e.to_string()))?;

        log::info!("TUN device {} created", config.name);

        Ok(Self {
            session,
            name: config.name.clone(),
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub async fn read(&self, buf: &mut [u8]) -> Result<usize> {
        // Wintun read is blocking, wrap in spawn_blocking
        let session = self.session.clone();
        let max_len = buf.len();
        let packet = tokio::task::spawn_blocking(move || {
            session.receive_blocking()
        })
        .await
        .map_err(|e| TunError::Tun(e.to_string()))?
        .map_err(|e| TunError::Tun(e.to_string()))?;

        let len = packet.bytes().len().min(max_len);
        buf[..len].copy_from_slice(&packet.bytes()[..len]);
        Ok(len)
    }

    pub async fn write(&self, buf: &[u8]) -> Result<usize> {
        let session = self.session.clone();
        let data = buf.to_vec();
        tokio::task::spawn_blocking(move || {
            let mut packet = session
                .allocate_send_packet(data.len() as u16)
                .map_err(|e| TunError::Tun(e.to_string()))?;
            packet.bytes_mut().copy_from_slice(&data);
            session.send_packet(packet);
            Ok::<usize, TunError>(data.len())
        })
        .await
        .map_err(|e| TunError::Tun(e.to_string()))?
    }
}
```

**Step 4: Verify it compiles**

Run: `cargo check -p resonance-tun`
Expected: Compiles for current platform.

**Step 5: Commit**

```bash
git add -A
git commit -m "feat: implement cross-platform TUN device abstraction"
```

---

### Task 4: VPN Server (resonance-server)

**Files:**
- Create: `crates/resonance-server/src/config.rs`
- Create: `crates/resonance-server/src/tls.rs`
- Create: `crates/resonance-server/src/tunnel.rs`
- Create: `crates/resonance-server/src/nat.rs`
- Modify: `crates/resonance-server/src/main.rs`

**Step 1: Write config.rs**

`crates/resonance-server/src/config.rs`:
```rust
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Deserialize)]
pub struct Config {
    pub listen: String,
    pub tun_name: String,
    pub subnet: String,
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
        Ok(config)
    }

    /// Parse subnet like "10.8.0.0/24" and return (network_addr, prefix_len)
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
```

**Step 2: Write tls.rs**

`crates/resonance-server/src/tls.rs`:
```rust
use boring::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVersion};
use std::path::Path;

pub fn build_tls_acceptor(cert_path: &Path, key_path: &Path) -> anyhow::Result<SslAcceptor> {
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls())?;

    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    builder.set_certificate_chain_file(cert_path)?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;

    // ALPN: advertise h2 and http/1.1
    builder.set_alpn_select_callback(|_, client_protos| {
        boring::ssl::select_next_proto(b"\x02h2\x08http/1.1", client_protos)
            .ok_or(boring::ssl::AlpnError::NOACK)
    });

    Ok(builder.build())
}
```

**Step 3: Write nat.rs**

`crates/resonance-server/src/nat.rs`:
```rust
use std::process::Command;

/// Setup NAT masquerading for VPN subnet.
/// Enables IP forwarding and adds iptables MASQUERADE rule.
pub fn setup_nat(tun_name: &str, subnet: &str) -> anyhow::Result<()> {
    // Enable IP forwarding
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")?;
    log::info!("Enabled IPv4 forwarding");

    // Add iptables MASQUERADE rule
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

    // Allow forwarding from TUN
    let status = Command::new("iptables")
        .args([
            "-A", "FORWARD", "-i", tun_name, "-j", "ACCEPT",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to add iptables FORWARD rule");
    }

    let status = Command::new("iptables")
        .args([
            "-A", "FORWARD", "-o", tun_name, "-m", "state",
            "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT",
        ])
        .status()?;

    if !status.success() {
        anyhow::bail!("Failed to add iptables FORWARD ESTABLISHED rule");
    }

    log::info!("NAT setup complete for {tun_name}");
    Ok(())
}

pub fn cleanup_nat(tun_name: &str, subnet: &str) {
    let _ = Command::new("iptables")
        .args(["-t", "nat", "-D", "POSTROUTING", "-s", subnet, "!", "-o", tun_name, "-j", "MASQUERADE"])
        .status();
    let _ = Command::new("iptables")
        .args(["-D", "FORWARD", "-i", tun_name, "-j", "ACCEPT"])
        .status();
    let _ = Command::new("iptables")
        .args(["-D", "FORWARD", "-o", tun_name, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
        .status();
    log::info!("NAT cleanup complete");
}
```

**Step 4: Write tunnel.rs**

`crates/resonance-server/src/tunnel.rs`:
```rust
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::tungstenite::Message as WsMessage;

use resonance_proto::crypto::{self, SessionKeys};
use resonance_proto::frame::{self, FrameEncoder, FrameDecoder, Frame};
use resonance_proto::proto;

pub struct ClientSession {
    pub assigned_ip: Ipv4Addr,
    pub tx: mpsc::UnboundedSender<Bytes>,
}

pub type SessionMap = Arc<RwLock<HashMap<Ipv4Addr, ClientSession>>>;

/// IP address pool for client allocation.
pub struct IpPool {
    base: u32,
    next: u32,
    max: u32,
}

impl IpPool {
    pub fn new(network: Ipv4Addr, prefix: u8) -> Self {
        let base = u32::from(network);
        let host_bits = 32 - prefix;
        let max = base + (1 << host_bits) - 1; // broadcast addr
        Self {
            base,
            next: base + 2, // .1 is server, start from .2
            max: max - 1,   // exclude broadcast
        }
    }

    pub fn allocate(&mut self) -> Option<Ipv4Addr> {
        if self.next > self.max {
            return None;
        }
        let ip = Ipv4Addr::from(self.next);
        self.next += 1;
        Some(ip)
    }

    pub fn release(&mut self, _ip: Ipv4Addr) {
        // Simple pool: don't reclaim for now (1-5 users)
    }
}

/// Handle a single WebSocket client connection.
pub async fn handle_client<S>(
    ws_stream: S,
    psk_hash: [u8; 32],
    sessions: SessionMap,
    ip_pool: Arc<tokio::sync::Mutex<IpPool>>,
    tun_tx: mpsc::UnboundedSender<(Ipv4Addr, Bytes)>,
) where
    S: futures_util::Stream<Item = Result<WsMessage, tokio_tungstenite::tungstenite::Error>>
        + futures_util::Sink<WsMessage, Error = tokio_tungstenite::tungstenite::Error>
        + Send
        + Unpin
        + 'static,
{
    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Step 1: Wait for AuthRequest
    let auth_msg = match ws_read.next().await {
        Some(Ok(WsMessage::Binary(data))) => data,
        _ => {
            log::warn!("Client disconnected before auth");
            return;
        }
    };

    let auth_payload = match frame::decode_control(&auth_msg) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("Invalid auth frame: {e}");
            return;
        }
    };

    let auth_req = match proto::AuthRequest::decode(auth_payload) {
        Ok(r) => r,
        Err(e) => {
            log::warn!("Invalid AuthRequest: {e}");
            return;
        }
    };

    // Verify PSK
    if auth_req.psk_hash.len() != 32 || auth_req.psk_hash[..] != psk_hash[..] {
        log::warn!("Auth failed: invalid PSK");
        let err = proto::Error {
            message: "Invalid PSK".to_string(),
        };
        let frame = FrameEncoder::encode_control(&err.encode_to_vec());
        let _ = ws_write.send(WsMessage::Binary(frame.to_vec().into())).await;
        return;
    }

    // Allocate IP
    let assigned_ip = match ip_pool.lock().await.allocate() {
        Some(ip) => ip,
        None => {
            log::error!("IP pool exhausted");
            return;
        }
    };

    // Generate key material
    let mut key_material = [0u8; 32];
    fastrand::fill(&mut key_material);

    let session_id = format!("{:016x}", fastrand::u64(..));

    // Send ServerHello
    let hello = proto::ServerHello {
        session_id: session_id.clone(),
        key_material: key_material.to_vec(),
        assigned_ip: assigned_ip.to_string(),
    };
    let hello_frame = FrameEncoder::encode_control(&hello.encode_to_vec());
    if ws_write.send(WsMessage::Binary(hello_frame.to_vec().into())).await.is_err() {
        log::warn!("Failed to send ServerHello");
        return;
    }

    log::info!("Client authenticated: {session_id} -> {assigned_ip}");

    // Derive session keys
    let keys = SessionKeys::derive(&key_material);
    let mut encoder = FrameEncoder::new(keys.clone());
    let mut decoder = FrameDecoder::new(keys);

    // Channel for sending packets back to this client
    let (client_tx, mut client_rx) = mpsc::unbounded_channel::<Bytes>();

    // Register session
    {
        let mut sessions_w = sessions.write().await;
        sessions_w.insert(
            assigned_ip,
            ClientSession {
                assigned_ip,
                tx: client_tx,
            },
        );
    }

    // Spawn writer: TUN -> client
    let write_handle = tokio::spawn(async move {
        while let Some(ip_packet) = client_rx.recv().await {
            match encoder.encode_data(&ip_packet) {
                Ok(frame_data) => {
                    if ws_write
                        .send(WsMessage::Binary(frame_data.to_vec().into()))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(e) => {
                    log::error!("Encode error: {e}");
                    break;
                }
            }
        }
    });

    // Reader: client -> TUN
    while let Some(msg_result) = ws_read.next().await {
        match msg_result {
            Ok(WsMessage::Binary(data)) => {
                match decoder.decode(&data) {
                    Ok(Frame::Data(ip_packet)) => {
                        if tun_tx.send((assigned_ip, ip_packet)).is_err() {
                            break;
                        }
                    }
                    Ok(Frame::Control(payload)) => {
                        // Handle ping/pong
                        if let Ok(ping) = proto::Ping::decode(payload) {
                            log::debug!("Ping from {assigned_ip}: {}", ping.timestamp);
                        }
                    }
                    Err(e) => {
                        log::warn!("Decode error from {assigned_ip}: {e}");
                    }
                }
            }
            Ok(WsMessage::Close(_)) | Err(_) => break,
            _ => {}
        }
    }

    // Cleanup
    log::info!("Client disconnected: {assigned_ip}");
    write_handle.abort();
    sessions.write().await.remove(&assigned_ip);
    ip_pool.lock().await.release(assigned_ip);
}
```

**Step 5: Write main.rs**

`crates/resonance-server/src/main.rs`:
```rust
mod config;
mod nat;
mod tls;
mod tunnel;

use std::net::Ipv4Addr;
use std::sync::Arc;

use bytes::Bytes;
use clap::Parser;
use futures_util::StreamExt;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, Mutex, RwLock};
use tokio_tungstenite::tungstenite::http;

use resonance_proto::crypto;
use resonance_tun::{TunConfig, TunDevice};

use crate::config::Config;
use crate::tunnel::{IpPool, SessionMap};

#[derive(Parser)]
#[command(name = "resonance-server", about = "Resonance VPN Server")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();
    let config = Config::load(&cli.config)?;

    let (network_addr, prefix) = config.parse_subnet()?;
    let server_ip = Ipv4Addr::new(
        network_addr.octets()[0],
        network_addr.octets()[1],
        network_addr.octets()[2],
        1,
    );

    let psk_hash = crypto::hash_psk(&config.psk);

    // Create TUN device
    let tun = TunDevice::create(&TunConfig {
        name: config.tun_name.clone(),
        address: server_ip,
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1280,
    })?;
    let tun = Arc::new(tun);
    log::info!("TUN device {} ready at {server_ip}", tun.name());

    // Setup NAT
    nat::setup_nat(tun.name(), &config.subnet)?;

    // Build TLS acceptor
    let tls_acceptor = tls::build_tls_acceptor(&config.tls.cert, &config.tls.key)?;
    let tls_acceptor = Arc::new(tls_acceptor);

    // Session management
    let sessions: SessionMap = Arc::new(RwLock::new(std::collections::HashMap::new()));
    let ip_pool = Arc::new(Mutex::new(IpPool::new(network_addr, prefix)));

    // Channel: client packets -> TUN writer
    let (tun_tx, mut tun_rx) = mpsc::unbounded_channel::<(Ipv4Addr, Bytes)>();

    // TUN writer task: receives packets from clients, writes to TUN
    let tun_write = tun.clone();
    tokio::spawn(async move {
        while let Some((_src_ip, ip_packet)) = tun_rx.recv().await {
            if let Err(e) = tun_write.write(&ip_packet).await {
                log::error!("TUN write error: {e}");
            }
        }
    });

    // TUN reader task: reads packets from TUN, routes to correct client
    let tun_read = tun.clone();
    let sessions_reader = sessions.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            match tun_read.read(&mut buf).await {
                Ok(n) if n > 0 => {
                    // Extract destination IP from IP header
                    if n >= 20 {
                        let dst_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
                        let sessions_r = sessions_reader.read().await;
                        if let Some(session) = sessions_r.get(&dst_ip) {
                            let _ = session.tx.send(Bytes::copy_from_slice(&buf[..n]));
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    log::error!("TUN read error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            }
        }
    });

    // TCP listener
    let listener = TcpListener::bind(&config.listen).await?;
    log::info!("Listening on {}", config.listen);

    // Load fake site content
    let fake_html = if let Some(ref fake_site) = config.fake_site {
        let index = fake_site.root.join("index.html");
        if index.exists() {
            std::fs::read_to_string(index).unwrap_or_else(|_| default_fake_html())
        } else {
            default_fake_html()
        }
    } else {
        default_fake_html()
    };
    let fake_html = Arc::new(fake_html);

    // Graceful shutdown
    let subnet = config.subnet.clone();
    let tun_name = config.tun_name.clone();
    let shutdown = tokio::signal::ctrl_c();
    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let (tcp_stream, peer_addr) = match accept {
                    Ok(v) => v,
                    Err(e) => {
                        log::error!("Accept error: {e}");
                        continue;
                    }
                };

                log::debug!("New connection from {peer_addr}");

                let tls_acceptor = tls_acceptor.clone();
                let sessions = sessions.clone();
                let ip_pool = ip_pool.clone();
                let tun_tx = tun_tx.clone();
                let fake_html = fake_html.clone();

                tokio::spawn(async move {
                    // TLS handshake
                    let tls_stream = match tokio_boring::accept(&tls_acceptor, tcp_stream).await {
                        Ok(s) => s,
                        Err(e) => {
                            log::debug!("TLS handshake failed from {peer_addr}: {e}");
                            return;
                        }
                    };

                    // Check if this is a WebSocket upgrade or regular HTTP
                    let ws_config = tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default();
                    let callback = |req: &http::Request<()>, resp: http::Response<()>| -> Result<http::Response<()>, http::Response<Option<String>>> {
                        if req.uri().path() == "/ws" {
                            Ok(resp)
                        } else {
                            // Return fake site for non-WS requests
                            let body = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n{}",
                                "(fake site content)"
                            );
                            Err(http::Response::builder()
                                .status(200)
                                .body(Some("Not a websocket path".to_string()))
                                .unwrap())
                        }
                    };

                    match tokio_tungstenite::accept_hdr_async_with_config(
                        tls_stream,
                        callback,
                        Some(ws_config),
                    )
                    .await
                    {
                        Ok(ws_stream) => {
                            tunnel::handle_client(
                                ws_stream,
                                psk_hash,
                                sessions,
                                ip_pool,
                                tun_tx,
                            )
                            .await;
                        }
                        Err(e) => {
                            log::debug!("WebSocket handshake failed from {peer_addr}: {e}");
                        }
                    }
                });
            }
            _ = &mut shutdown => {
                log::info!("Shutting down...");
                nat::cleanup_nat(&tun_name, &subnet);
                break;
            }
        }
    }

    Ok(())
}

fn default_fake_html() -> String {
    r#"<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Welcome</title></head>
<body>
<h1>Welcome</h1>
<p>This server is running normally.</p>
</body>
</html>"#
        .to_string()
}
```

**Step 6: Create example config**

Create: `config.example.toml`
```toml
listen = "0.0.0.0:443"
tun_name = "rvpn0"
subnet = "10.8.0.0/24"
dns = ["1.1.1.1", "8.8.8.8"]
psk = "change-me-to-a-strong-secret"

[tls]
cert = "/etc/resonance/cert.pem"
key = "/etc/resonance/key.pem"

[fake_site]
root = "/var/www/resonance"
```

**Step 7: Verify it compiles**

Run: `cargo check -p resonance-server`
Expected: Compiles with no errors.

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: implement VPN server with TLS, WebSocket tunnel, and NAT"
```

---

### Task 5: VPN Client (resonance-client)

**Files:**
- Create: `crates/resonance-client/src/config.rs`
- Create: `crates/resonance-client/src/tls.rs`
- Create: `crates/resonance-client/src/tunnel.rs`
- Create: `crates/resonance-client/src/routing.rs`
- Modify: `crates/resonance-client/src/main.rs`

**Step 1: Write config.rs**

`crates/resonance-client/src/config.rs`:
```rust
use serde::Deserialize;

#[derive(Deserialize)]
pub struct Config {
    pub server: String,
    pub psk: String,
    pub dns: Option<Vec<String>>,
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }
}
```

**Step 2: Write tls.rs - Chrome TLS fingerprint**

`crates/resonance-client/src/tls.rs`:
```rust
use boring::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode, SslVersion};

pub fn chrome_tls_config() -> anyhow::Result<boring::ssl::ConnectConfiguration> {
    let mut builder = SslConnector::builder(SslMethod::tls())?;

    // Protocol versions
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;

    // Chrome cipher suite order (TLS 1.2; TLS 1.3 ciphers are BoringSSL defaults)
    builder.set_cipher_list(
        "ECDHE-ECDSA-AES128-GCM-SHA256:\
         ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-ECDSA-AES256-GCM-SHA384:\
         ECDHE-RSA-AES256-GCM-SHA384:\
         ECDHE-ECDSA-CHACHA20-POLY1305:\
         ECDHE-RSA-CHACHA20-POLY1305:\
         ECDHE-RSA-AES128-SHA:\
         ECDHE-RSA-AES256-SHA:\
         AES128-GCM-SHA256:\
         AES256-GCM-SHA384:\
         AES128-SHA:\
         AES256-SHA",
    )?;

    // GREASE: random values in cipher suites and extensions (Chrome does this)
    builder.set_grease_enabled(true);

    // Extension permutation (Chrome 110+)
    builder.set_permute_extensions(true);

    // Supported curves (Chrome: X25519, P-256, P-384)
    builder.set_curves_list("X25519:P-256:P-384")?;

    // Signature algorithms
    builder.set_sigalgs_list(
        "ECDSA+SHA256:RSA-PSS+SHA256:RSA+SHA256:\
         ECDSA+SHA384:RSA-PSS+SHA384:RSA+SHA384:\
         RSA-PSS+SHA512:RSA+SHA512",
    )?;

    // ALPN: h2 and http/1.1
    builder.set_alpn_protos(b"\x02h2\x08http/1.1")?;

    // OCSP stapling
    builder.enable_ocsp_stapling();

    // Signed certificate timestamps
    builder.enable_signed_cert_timestamps();

    // SSL options
    builder.set_options(
        SslOptions::NO_SSLV2 | SslOptions::NO_SSLV3 | SslOptions::NO_COMPRESSION,
    );

    // Accept server certificates (in production, load system CA bundle)
    builder.set_verify(SslVerifyMode::NONE);

    let connector = builder.build();
    let config = connector.configure()?;

    Ok(config)
}
```

**Step 3: Write routing.rs**

`crates/resonance-client/src/routing.rs`:
```rust
use std::net::Ipv4Addr;
use std::process::Command;

/// Saved routing state for cleanup on disconnect.
pub struct RoutingState {
    pub original_gateway: String,
    pub original_dns: Option<String>,
    pub server_ip: String,
    pub tun_name: String,
}

impl RoutingState {
    /// Setup routing: redirect all traffic through TUN, except VPN server traffic.
    pub fn setup(
        server_host: &str,
        assigned_ip: &str,
        tun_name: &str,
        dns: &[String],
    ) -> anyhow::Result<Self> {
        let server_ip = resolve_server_ip(server_host)?;
        let original_gateway = get_default_gateway()?;

        // Backup DNS
        let original_dns = std::fs::read_to_string("/etc/resolv.conf").ok();

        // Route server IP through original gateway
        run_cmd("ip", &["route", "add", &server_ip, "via", &original_gateway])?;

        // Replace default route with TUN
        run_cmd("ip", &["route", "replace", "default", "dev", tun_name])?;

        // Set DNS
        if !dns.is_empty() {
            let resolv = dns
                .iter()
                .map(|d| format!("nameserver {d}"))
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write("/etc/resolv.conf", format!("{resolv}\n"))?;
            log::info!("DNS set to: {}", dns.join(", "));
        }

        log::info!("Routing configured: all traffic -> {tun_name}");

        Ok(Self {
            original_gateway,
            original_dns,
            server_ip,
            tun_name: tun_name.to_string(),
        })
    }

    /// Restore original routing.
    pub fn cleanup(&self) {
        let _ = run_cmd("ip", &["route", "del", &self.server_ip]);
        let _ = run_cmd("ip", &["route", "replace", "default", "via", &self.original_gateway]);

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
    // Strip port if present
    let host = host.split(':').next().unwrap_or(host);

    // Try parsing as IP first
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(host.to_string());
    }

    // DNS resolve
    use std::net::ToSocketAddrs;
    let addr = format!("{host}:0")
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .ok_or_else(|| anyhow::anyhow!("Could not resolve {host}"))?;

    Ok(addr.ip().to_string())
}

#[cfg(target_os = "linux")]
fn get_default_gateway() -> anyhow::Result<String> {
    let output = Command::new("ip")
        .args(["route", "show", "default"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Parse: "default via 192.168.1.1 dev eth0 ..."
    let gw = stdout
        .split_whitespace()
        .skip_while(|w| *w != "via")
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("Could not find default gateway"))?
        .to_string();
    Ok(gw)
}

#[cfg(target_os = "macos")]
fn get_default_gateway() -> anyhow::Result<String> {
    let output = Command::new("route")
        .args(["-n", "get", "default"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let line = line.trim();
        if line.starts_with("gateway:") {
            return Ok(line.split_whitespace().nth(1).unwrap_or("").to_string());
        }
    }
    anyhow::bail!("Could not find default gateway")
}

#[cfg(target_os = "windows")]
fn get_default_gateway() -> anyhow::Result<String> {
    let output = Command::new("cmd")
        .args(["/c", "route", "print", "0.0.0.0"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains("0.0.0.0") && !line.trim().starts_with("0.0.0.0          0.0.0.0") {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 && parts[0] == "0.0.0.0" {
            return Ok(parts[2].to_string());
        }
    }
    anyhow::bail!("Could not find default gateway")
}

fn run_cmd(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(cmd).args(args).status()?;
    if !status.success() {
        anyhow::bail!("{} {} failed", cmd, args.join(" "));
    }
    Ok(())
}
```

**Step 4: Write tunnel.rs**

`crates/resonance-client/src/tunnel.rs`:
```rust
use std::sync::Arc;

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use prost::Message;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

use resonance_proto::crypto::{self, SessionKeys};
use resonance_proto::frame::{self, Frame, FrameDecoder, FrameEncoder};
use resonance_proto::proto;
use resonance_tun::TunDevice;

pub struct ConnectResult {
    pub assigned_ip: String,
    pub session_id: String,
}

pub async fn connect_and_run(
    server: &str,
    psk: &str,
    tun: Arc<TunDevice>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> anyhow::Result<ConnectResult> {
    // Resolve server address
    let addr = if server.contains(':') {
        server.to_string()
    } else {
        format!("{server}:443")
    };

    // TCP connect
    let tcp_stream = TcpStream::connect(&addr).await?;
    log::info!("TCP connected to {addr}");

    // TLS handshake with Chrome fingerprint
    let tls_config = crate::tls::chrome_tls_config()?;
    let host = addr.split(':').next().unwrap_or(&addr);
    let tls_stream = tokio_boring::connect(tls_config, host, tcp_stream).await?;

    if let Some(proto) = tls_stream.ssl().selected_alpn_protocol() {
        log::info!("ALPN: {}", String::from_utf8_lossy(proto));
    }

    // HTTP/2 WebSocket upgrade
    // Since boring+h2 manual HTTP/2 WS upgrade is complex, use tungstenite over TLS directly.
    // The TLS ALPN is set to h2, which helps with fingerprinting even though
    // tungstenite uses HTTP/1.1 upgrade internally.
    let ws_url = format!("wss://{host}/ws");
    let (ws_stream, _) = tokio_tungstenite::client_async(
        tokio_tungstenite::tungstenite::http::Request::builder()
            .uri(&ws_url)
            .header("Host", host)
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Version", "13")
            .header(
                "Sec-WebSocket-Key",
                tokio_tungstenite::tungstenite::handshake::client::generate_key(),
            )
            .body(())
            .unwrap(),
        tls_stream,
    )
    .await?;

    log::info!("WebSocket connected");

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Send AuthRequest
    let psk_hash = crypto::hash_psk(psk);
    let auth_req = proto::AuthRequest {
        psk_hash: psk_hash.to_vec(),
    };
    let auth_frame = FrameEncoder::encode_control(&auth_req.encode_to_vec());
    ws_write
        .send(WsMessage::Binary(auth_frame.to_vec().into()))
        .await?;

    // Receive ServerHello
    let hello_msg = ws_read
        .next()
        .await
        .ok_or_else(|| anyhow::anyhow!("Connection closed before ServerHello"))??;

    let hello_data = match hello_msg {
        WsMessage::Binary(d) => d,
        _ => anyhow::bail!("Expected binary ServerHello"),
    };

    let hello_payload = frame::decode_control(&hello_data)?;
    let hello = proto::ServerHello::decode(hello_payload)?;

    log::info!(
        "Authenticated: session={}, ip={}",
        hello.session_id,
        hello.assigned_ip
    );

    let result = ConnectResult {
        assigned_ip: hello.assigned_ip.clone(),
        session_id: hello.session_id.clone(),
    };

    // Derive session keys
    let keys = SessionKeys::derive(&hello.key_material);
    let mut encoder = FrameEncoder::new(keys.clone());
    let mut decoder = FrameDecoder::new(keys);

    // Spawn TUN -> WS writer
    let tun_read = tun.clone();
    let mut shutdown_w = shutdown.clone();
    let write_handle = tokio::spawn(async move {
        let mut buf = vec![0u8; 1500];
        loop {
            tokio::select! {
                read_result = tun_read.read(&mut buf) => {
                    match read_result {
                        Ok(n) if n > 0 => {
                            match encoder.encode_data(&buf[..n]) {
                                Ok(frame_data) => {
                                    if ws_write
                                        .send(WsMessage::Binary(frame_data.to_vec().into()))
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                }
                                Err(e) => {
                                    log::error!("Encode error: {e}");
                                    break;
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            log::error!("TUN read error: {e}");
                            break;
                        }
                    }
                }
                _ = shutdown_w.changed() => {
                    log::info!("Writer shutting down");
                    break;
                }
            }
        }
    });

    // WS -> TUN reader
    let tun_write = tun.clone();
    let mut shutdown_r = shutdown.clone();

    loop {
        tokio::select! {
            msg = ws_read.next() => {
                match msg {
                    Some(Ok(WsMessage::Binary(data))) => {
                        match decoder.decode(&data) {
                            Ok(Frame::Data(ip_packet)) => {
                                if let Err(e) = tun_write.write(&ip_packet).await {
                                    log::error!("TUN write error: {e}");
                                }
                            }
                            Ok(Frame::Control(_)) => {
                                // Control messages (pong, etc)
                            }
                            Err(e) => {
                                log::warn!("Decode error: {e}");
                            }
                        }
                    }
                    Some(Ok(WsMessage::Close(_))) | None => {
                        log::info!("Server disconnected");
                        break;
                    }
                    Some(Err(e)) => {
                        log::error!("WS read error: {e}");
                        break;
                    }
                    _ => {}
                }
            }
            _ = shutdown_r.changed() => {
                log::info!("Reader shutting down");
                break;
            }
        }
    }

    write_handle.abort();
    Ok(result)
}
```

**Step 5: Write main.rs**

`crates/resonance-client/src/main.rs`:
```rust
mod config;
mod routing;
mod tls;
mod tunnel;

use std::net::Ipv4Addr;
use std::sync::Arc;

use clap::Parser;
use tokio::sync::watch;

use resonance_tun::{TunConfig, TunDevice};

#[derive(Parser)]
#[command(name = "resonance-client", about = "Resonance VPN Client")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Connect to VPN server
    Connect {
        /// Server address (host:port or host)
        #[arg(short, long)]
        server: Option<String>,

        /// Pre-shared key
        #[arg(short, long)]
        key: Option<String>,

        /// DNS servers (comma-separated)
        #[arg(short, long)]
        dns: Option<String>,

        /// Config file path
        #[arg(short, long, default_value = "~/.config/resonance/client.toml")]
        config: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            server,
            key,
            dns,
            config: config_path,
        } => {
            // Load config file if it exists
            let config_path = config_path.replace('~', &dirs_home());
            let file_config = config::Config::load(&config_path).ok();

            let server = server
                .or_else(|| file_config.as_ref().map(|c| c.server.clone()))
                .ok_or_else(|| anyhow::anyhow!("Server address required (--server or config file)"))?;

            let psk = key
                .or_else(|| file_config.as_ref().map(|c| c.psk.clone()))
                .ok_or_else(|| anyhow::anyhow!("PSK required (--key or config file)"))?;

            let dns_servers: Vec<String> = if let Some(dns_str) = dns {
                dns_str.split(',').map(|s| s.trim().to_string()).collect()
            } else if let Some(ref fc) = file_config {
                fc.dns.clone().unwrap_or_else(|| vec!["1.1.1.1".to_string()])
            } else {
                vec!["1.1.1.1".to_string()]
            };

            connect(&server, &psk, &dns_servers).await?;
        }
    }

    Ok(())
}

async fn connect(server: &str, psk: &str, dns: &[String]) -> anyhow::Result<()> {
    log::info!("Connecting to {server}...");

    // Shutdown signal
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    // Create TUN device
    let tun_name = "rvpn0";
    // Use a temporary IP; will be updated after handshake
    let tun = Arc::new(TunDevice::create(&TunConfig {
        name: tun_name.to_string(),
        address: Ipv4Addr::new(10, 8, 0, 2), // will be replaced
        netmask: Ipv4Addr::new(255, 255, 255, 0),
        mtu: 1280,
    })?);

    log::info!("TUN device {tun_name} created");

    // Connect to server
    let result = tokio::select! {
        r = tunnel::connect_and_run(server, psk, tun.clone(), shutdown_rx) => r?,
        _ = tokio::signal::ctrl_c() => {
            log::info!("Interrupted");
            let _ = shutdown_tx.send(true);
            return Ok(());
        }
    };

    log::info!("Connected! Assigned IP: {}", result.assigned_ip);

    // Setup routing
    let _routing = routing::RoutingState::setup(
        server,
        &result.assigned_ip,
        tun_name,
        dns,
    )?;

    log::info!("VPN active. Press Ctrl+C to disconnect.");

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;
    log::info!("Disconnecting...");
    let _ = shutdown_tx.send(true);

    // RoutingState::drop() restores routing
    Ok(())
}

fn dirs_home() -> String {
    std::env::var("HOME").unwrap_or_else(|_| "/root".to_string())
}
```

**Step 6: Verify it compiles**

Run: `cargo check -p resonance-client`
Expected: Compiles with no errors.

**Step 7: Verify full workspace compiles**

Run: `cargo check`
Expected: All crates compile.

**Step 8: Commit**

```bash
git add -A
git commit -m "feat: implement VPN client with Chrome TLS fingerprint and routing"
```

---

### Task 6: Integration Testing and Build Verification

**Step 1: Verify full build**

Run: `cargo build --release`
Expected: Successful build producing `resonance-server` and `resonance-client` binaries.

**Step 2: Verify all tests pass**

Run: `cargo test`
Expected: All unit tests pass.

**Step 3: Add .gitignore**

Create: `.gitignore`
```
/target
*.swp
*.swo
*~
.env
```

**Step 4: Final commit**

```bash
git add -A
git commit -m "chore: add gitignore and verify full build"
```

---

### Post-Implementation Notes

**To deploy the server:**
1. Get a VPS outside Russia with a domain
2. Get TLS cert: `certbot certonly --standalone -d vpn.yourdomain.com`
3. Copy `config.example.toml` to `config.toml`, set PSK and cert paths
4. Run: `sudo ./resonance-server -c config.toml`

**To connect from client:**
```bash
sudo resonance-client connect --server vpn.yourdomain.com --key your-secret-key
```

**Known limitations for future improvement:**
- HTTP/2 WebSocket upgrade (RFC 8441) is not implemented yet (using HTTP/1.1 WS upgrade over TLS with h2 ALPN for fingerprinting)
- No automatic reconnection on disconnect
- No traffic shaping/timing obfuscation
- Windows TUN needs Wintun driver installed separately
- IP pool doesn't reclaim released IPs
