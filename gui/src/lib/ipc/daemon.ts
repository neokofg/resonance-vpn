import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

export type VpnState = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error';

export interface DaemonEvent {
  type: 'response' | 'state_changed' | 'stats' | 'deploy_progress';
  success?: boolean;
  error?: string | null;
  data?: Record<string, unknown>;
  state?: VpnState;
  tx_bytes?: number;
  rx_bytes?: number;
  tx_packets?: number;
  rx_packets?: number;
  step?: number;
  total?: number;
  message?: string;
}

export type DaemonEventHandler = (event: DaemonEvent) => void;

let unlistenFn: UnlistenFn | null = null;
const handlers: Set<DaemonEventHandler> = new Set();

export async function initDaemonListener() {
  if (unlistenFn) return;
  unlistenFn = await listen<DaemonEvent>('daemon-event', (event) => {
    for (const handler of handlers) {
      handler(event.payload);
    }
  });
}

export function onDaemonEvent(handler: DaemonEventHandler): () => void {
  handlers.add(handler);
  return () => handlers.delete(handler);
}

export async function connectVpn(server: string, psk: string, dns: string[]) {
  return invoke('connect_vpn', { server, psk, dns });
}

export async function disconnectVpn() {
  return invoke('disconnect_vpn');
}

export async function getVpnStatus() {
  return invoke('get_vpn_status');
}

export interface DeployParams {
  host: string;
  user: string;
  sshKey?: string;
  password?: string;
  sshPort: number;
  domain?: string;
  port: number;
  subnet: string;
}

export async function deployServer(params: DeployParams) {
  return invoke('deploy_server', { params });
}
