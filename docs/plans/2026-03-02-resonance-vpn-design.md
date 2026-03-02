# Resonance VPN Design

## Overview

A personal VPN that bypasses AI-powered DPI (TSPU) in Russia by masquerading as legitimate HTTPS/HTTP2 WebSocket traffic with Chrome TLS fingerprint mimicry. Based on the custom protocol from oldaccord messenger.

## Requirements

- **Type**: Full TUN-based VPN
- **Client**: CLI only (Rust)
- **Platforms**: Linux server, Linux/macOS/Windows client
- **Encryption**: BLAKE3 XOR stream cipher with BLAKE3 MAC (from oldaccord, no padding buckets)
- **Scale**: Personal (1-5 users), PSK authentication
- **DPI evasion**: TLS 1.3 + HTTP/2 WebSocket + Chrome TLS fingerprint

## Architecture

### Project Structure

```
resonance-vpn/
├── Cargo.toml                    # workspace
├── crates/
│   ├── resonance-server/         # VPN server
│   ├── resonance-client/         # CLI client
│   ├── resonance-proto/          # protocol: crypto, frames, protobuf
│   └── resonance-tun/            # TUN abstraction (Linux/macOS/Windows)
└── proto/
    └── resonance.proto           # protobuf schemas
```

### Approach: Direct WebSocket Tunnel

Single WebSocket connection carrying encrypted IP packets. Server looks like a regular HTTPS website.

```
Client TUN -> IP packets -> BLAKE3 XOR encrypt -> WS binary frame -> TLS 1.3 (Chrome fp) -> Internet
                                                                                              |
Server -> TLS terminate -> WS frame -> BLAKE3 XOR decrypt -> IP packets -> NAT -> Internet
```

## Protocol

### Handshake Flow

```
Client                                          Server
  |                                                |
  |-- TLS 1.3 ClientHello (Chrome JA3/JA4) ------>|
  |<-- ServerHello + Certificate ------------------|
  |                                                |
  |-- HTTP/2 SETTINGS (Chrome-like) -------------->|
  |-- GET /ws Upgrade: websocket ----------------->|
  |<-- 101 Switching Protocols --------------------|
  |                                                |
  |-- WSBinary: AuthRequest { psk_hash } --------->|
  |<-- WSBinary: ServerHello { session_id,         |
  |                            key_material,       |
  |                            assigned_ip }  -----|
  |                                                |
  |== Encrypted IP tunnel active =================>|
```

### TLS Fingerprint Mimicry (boring crate / BoringSSL)

- Cipher suites, extensions, GREASE values match Chrome exactly
- ALPN: `h2` (HTTP/2)
- HTTP/2 SETTINGS frame copies Chrome: `HEADER_TABLE_SIZE=65536`, `MAX_CONCURRENT_STREAMS=1000`, `INITIAL_WINDOW_SIZE=6291456`, `MAX_HEADER_LIST_SIZE=262144`
- Real HTTP/2 WebSocket upgrade (RFC 8441)

### Fake Website

Server responds to any non-`/ws` HTTP request with a static HTML page. Browser visitors see a regular website, not a VPN.

### Frame Format (inside WebSocket binary frames)

```
[8 bytes nonce] [encrypted IP packet] [16 bytes BLAKE3 MAC]
```

No length masking (WebSocket handles framing). No padding buckets. MAC ensures integrity.

### Encryption (from oldaccord)

**Key Derivation (HKDF-SHA256):**
```
SESSION_SALT = b"resonance-vpn-v1"
TLS Master Secret -> HKDF-SHA256 -> session_key (32 bytes)
session_key -> BLAKE3 derivations:
  - scramble_key (32 bytes) via BLAKE3(session_key, "scramble")
  - mac_key (32 bytes) via BLAKE3(session_key, "mac")
```

**XOR Keystream:**
- BLAKE3 in keyed XOF mode
- Key: scramble_key, Input: nonce (8 bytes LE)
- Data XORed with keystream in 64-byte chunks

**MAC:**
- BLAKE3 keyed hash (mac_key), 16-byte truncation
- Authenticates: nonce + encrypted_data

### MTU

Client TUN MTU = 1280 (IPv6 minimum). Ensures IP packets fit in WebSocket frames without fragmentation.

## Server

### Configuration (`config.toml`)

```toml
listen = "0.0.0.0:443"
tun_name = "rvpn0"
subnet = "10.8.0.0/24"
dns = ["1.1.1.1", "8.8.8.8"]
psk = "shared-secret-key"

[tls]
cert = "/etc/resonance/cert.pem"
key = "/etc/resonance/key.pem"

[fake_site]
root = "/var/www/resonance"
```

### NAT

Auto-configures iptables/nftables MASQUERADE for the client subnet.

### Sessions

Each client gets an IP from pool (10.8.0.2 - 10.8.0.254). Simple in-memory manager.

### Keepalive

Ping/pong every 30 seconds. Disconnect after 60s without response.

## Client

### CLI Interface

```bash
# Connect
resonance-client connect --server vpn.example.com --key mySecretKey

# With custom DNS
resonance-client connect --server vpn.example.com --key myKey --dns 1.1.1.1
```

### Config File (`~/.config/resonance/client.toml`)

```toml
server = "vpn.example.com:443"
psk = "shared-secret-key"
dns = ["1.1.1.1"]
```

### Routing

**On connect:**
1. Create TUN interface (MTU 1280)
2. Add route to server via current gateway (so WS connection goes direct)
3. Redirect default route through TUN
4. Configure DNS (resolv.conf backup + override)

**On disconnect (graceful or crash):**
- Restore original routes
- Restore DNS
- Remove TUN

### Cross-Platform TUN

- Linux: `ioctl` on `/dev/net/tun` (TUN_SET_IFF)
- macOS: `utun` via `sys/kern_control.h` socket
- Windows: Wintun driver (dll load)

## Dependencies

| Crate | Purpose |
|-------|---------|
| `boring` | TLS 1.3 with Chrome fingerprint |
| `tokio` | Async runtime |
| `tokio-boring` | Async TLS |
| `tokio-tungstenite` | WebSocket |
| `hyper` + `h2` | HTTP/2 framing |
| `blake3` | XOR encryption + MAC |
| `hkdf` + `sha2` | Key derivation |
| `prost` | Protobuf |
| `clap` | CLI args |
| `toml` + `serde` | Config |

## Performance

- Zero-copy where possible: `bytes::Bytes` for buffers
- Direct TUN->encrypt->WS pipeline without extra allocations
- `mimalloc` allocator
- Release profile: LTO, codegen-units=1, panic=abort

## Security

- PSK hashed with BLAKE3 before transmission (server stores hash, not plaintext)
- Key material: 32 bytes random from server + HKDF derivation
- Nonce: monotonic counter (8 bytes), replay protection
- MAC on every frame
- Graceful shutdown restores networking
