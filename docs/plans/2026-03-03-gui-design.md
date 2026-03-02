# Resonance VPN GUI — Design Document

## Overview

Desktop GUI for resonance-vpn using Tauri v2 + Svelte. Covers VPN connection management, multi-server profiles, remote server deployment, and settings. Dark glassmorphism visual style with Phosphor icons.

## Architecture

### Split privilege model

```
┌─────────────┐     JSON-RPC/IPC      ┌──────────────────┐
│  Tauri GUI   │ ◄──────────────────► │ resonance-daemon  │
│  (Svelte)    │    Unix socket /      │  (elevated)       │
│  unprivileged│    named pipe         │  TUN + routing    │
└─────────────┘                        └──────────────────┘
```

- **resonance-daemon**: Privileged sidecar binary bundled with the Tauri app. Owns TUN device creation, routing table manipulation, and tunnel forwarding. Runs as root/admin.
- **Tauri GUI**: Unprivileged desktop app. Communicates with daemon over IPC. Manages profiles, settings, and deploy operations.
- **resonance-vpn-lib**: Shared library crate extracted from resonance-client. Contains connect/tunnel/routing/deploy logic. Used by both CLI client and daemon.

### Project structure

```
resonance-vpn/
├── crates/
│   ├── resonance-proto/          # (existing) crypto + frames
│   ├── resonance-tun/            # (existing) TUN abstraction
│   ├── resonance-server/         # (existing) server binary
│   ├── resonance-client/         # (existing) CLI client — depends on vpn-lib
│   ├── resonance-daemon/         # NEW: privileged IPC daemon
│   └── resonance-vpn-lib/        # NEW: shared VPN logic extracted from client
├── gui/                           # NEW: Tauri v2 + Svelte app
│   ├── src-tauri/                 # Rust backend (Tauri commands, IPC client)
│   ├── src/                       # Svelte frontend
│   │   ├── lib/
│   │   │   ├── components/        # UI components
│   │   │   ├── stores/            # Svelte stores (state)
│   │   │   └── ipc/               # Daemon communication layer
│   │   └── routes/                # Pages
│   ├── static/                    # Static assets
│   └── package.json
```

## IPC Protocol

JSON-RPC over Unix socket (`/tmp/resonance-vpn.sock`) or named pipe (`\\.\pipe\resonance-vpn`) on Windows.

### Commands (GUI to Daemon)

| Command      | Params                                                       | Response                                    |
|-------------|--------------------------------------------------------------|---------------------------------------------|
| `connect`    | `{ server, psk, dns[] }`                                    | `{ assigned_ip, session_id }`              |
| `disconnect` | `{}`                                                         | `{}`                                        |
| `status`     | `{}`                                                         | `{ state, assigned_ip, uptime_secs, tx_bytes, rx_bytes }` |
| `deploy`     | `{ host, user, auth, ssh_port, domain, port, subnet }`      | Stream of progress events                   |

### Events (Daemon to GUI, pushed)

| Event             | Payload                                                         |
|-------------------|-----------------------------------------------------------------|
| `state_changed`   | `{ state: "connecting"\|"connected"\|"disconnecting"\|"disconnected"\|"error", error? }` |
| `stats_update`    | `{ tx_bytes, rx_bytes, tx_packets, rx_packets }` (every 1s)   |
| `deploy_progress` | `{ step, message, total_steps }`                               |

The daemon maintains exactly one active VPN connection. Profiles are stored in Tauri's app data directory on the GUI side.

## UI Screens

### Main screen (Connection)

- Large circular connect/disconnect button (120px) with state-dependent glow
- Current server name and assigned IP
- Connection status with subtle pulse animation when connected
- Live stats: upload/download speed, uptime
- Server selector dropdown from saved profiles

### Server profiles

- List of saved servers (name, address, last connected timestamp)
- Add / edit / delete profiles
- Each profile: name, server address, PSK, custom DNS (optional)
- Import from existing config file

### Deploy wizard

Step-by-step flow:
1. Server host + SSH credentials (key file picker or password input)
2. Options: domain (Let's Encrypt), port, subnet
3. Progress view with live log output streamed from daemon
4. Completion: auto-creates a profile with the deployed server address + generated PSK

### Settings

- Default DNS servers
- Auto-connect on launch toggle
- Connection timeout
- Log level selector
- About / version info

### System tray

- Tray icon reflecting connected/disconnected state
- Quick connect/disconnect
- Show window / Quit

## Visual Design

### Theme: Dark glassmorphism

| Token              | Value                          |
|--------------------|--------------------------------|
| Background         | `#0a0a0f`                      |
| Card surface       | `rgba(255,255,255,0.04)` + `backdrop-filter: blur(20px)` + border `rgba(255,255,255,0.06)` |
| Primary accent     | `#6366f1` (indigo)             |
| Success            | `#22c55e` (green)              |
| Error              | `#ef4444` (red)                |
| Text primary       | `#e2e8f0`                      |
| Text secondary     | `#64748b`                      |
| Font               | Inter (system fallback)        |
| Border radius      | 12px cards, 8px buttons, 20px connect button |

### Icons

Phosphor Icons (regular weight, bold for active states). No emojis.

### Animations

- 200ms ease-out for UI interactions
- 500ms for connection state transitions
- Subtle ring animation on the connect button during "connecting" state
- Green glow effect when connected

## Technical Decisions

- **Tauri v2**: Native webview, Rust backend, sidecar support, small bundle size
- **Svelte 5**: Minimal JS overhead, reactive stores, good Tauri integration
- **Phosphor Icons**: Consistent, 6 weights, Svelte package available
- **JSON-RPC over IPC**: Simple, debuggable, cross-platform
- **Profiles in app data**: SQLite or JSON file in Tauri's `appDataDir`
- **Deploy runs in daemon**: SSH operations need no elevation but keeping them in daemon simplifies the architecture (single IPC channel)
