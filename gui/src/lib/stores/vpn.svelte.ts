import { onDaemonEvent, initDaemonListener, type VpnState, type DaemonEvent } from '$lib/ipc/daemon';

class VpnStore {
  state = $state<VpnState>('disconnected');
  assignedIp = $state<string | null>(null);
  publicIp = $state<string | null>(null);
  sessionId = $state<string | null>(null);
  uptimeSecs = $state(0);
  error = $state<string | null>(null);
  txBytes = $state(0);
  rxBytes = $state(0);

  private uptimeInterval: ReturnType<typeof setInterval> | null = null;

  constructor() {
    initDaemonListener();
    onDaemonEvent((event) => this.handleEvent(event));
  }

  private handleEvent(event: DaemonEvent) {
    if (event.type === 'state_changed') {
      this.state = event.state ?? 'disconnected';
      this.error = event.error ?? null;
      if (this.state === 'connected') {
        this.startUptimeCounter();
        this.fetchPublicIp();
      } else if (this.state === 'disconnected') {
        this.stopUptimeCounter();
        this.assignedIp = null;
        this.publicIp = null;
        this.sessionId = null;
        this.uptimeSecs = 0;
        this.txBytes = 0;
        this.rxBytes = 0;
      }
    }
    if (event.type === 'response') {
      if (event.success && event.data) {
        if ('assigned_ip' in event.data) {
          this.assignedIp = event.data.assigned_ip as string;
          this.sessionId = event.data.session_id as string;
        }
      } else if (!event.success && event.error) {
        this.error = event.error;
        this.state = 'error';
      }
    }
    if (event.type === 'stats') {
      this.txBytes = event.tx_bytes ?? 0;
      this.rxBytes = event.rx_bytes ?? 0;
    }
  }

  private async fetchPublicIp() {
    try {
      const res = await fetch('https://api.ipify.org?format=text');
      if (res.ok) {
        this.publicIp = (await res.text()).trim();
      }
    } catch {
      this.publicIp = null;
    }
  }

  private startUptimeCounter() {
    this.uptimeSecs = 0;
    this.uptimeInterval = setInterval(() => { this.uptimeSecs++; }, 1000);
  }

  private stopUptimeCounter() {
    if (this.uptimeInterval) { clearInterval(this.uptimeInterval); this.uptimeInterval = null; }
  }

  get isConnected() { return this.state === 'connected'; }
  get isTransitioning() { return this.state === 'connecting' || this.state === 'disconnecting'; }

  get formattedUptime() {
    const h = Math.floor(this.uptimeSecs / 3600);
    const m = Math.floor((this.uptimeSecs % 3600) / 60);
    const s = this.uptimeSecs % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  }
}

export const vpnStore = new VpnStore();
