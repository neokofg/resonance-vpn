<script lang="ts">
  import { vpnStore } from '$lib/stores/vpn.svelte';
  import IconArrowUpBold from 'phosphor-icons-svelte/IconArrowUpBold.svelte';
  import IconArrowDownBold from 'phosphor-icons-svelte/IconArrowDownBold.svelte';
  import IconClockBold from 'phosphor-icons-svelte/IconClockBold.svelte';

  function formatBytes(bytes: number): { value: string; unit: string } {
    if (bytes < 1024) return { value: String(bytes), unit: 'B' };
    if (bytes < 1024 * 1024) return { value: (bytes / 1024).toFixed(1), unit: 'KB' };
    if (bytes < 1024 * 1024 * 1024) return { value: (bytes / (1024 * 1024)).toFixed(1), unit: 'MB' };
    return { value: (bytes / (1024 * 1024 * 1024)).toFixed(2), unit: 'GB' };
  }
</script>

{#if vpnStore.isConnected}
<div class="stats-container">
  {#if vpnStore.publicIp}
  <div class="ip-display">
    <span class="ip-value">{vpnStore.publicIp}</span>
    <span class="ip-label">PUBLIC IP</span>
  </div>
  {/if}

  <div class="stats-row">
    <div class="stat">
      <div class="stat-icon upload"><IconArrowUpBold /></div>
      <div class="stat-data">
        <span class="stat-value">{formatBytes(vpnStore.txBytes).value}<span class="stat-unit">{formatBytes(vpnStore.txBytes).unit}</span></span>
      </div>
      <span class="stat-label">UPLOAD</span>
    </div>

    <div class="divider"></div>

    <div class="stat">
      <div class="stat-icon download"><IconArrowDownBold /></div>
      <div class="stat-data">
        <span class="stat-value">{formatBytes(vpnStore.rxBytes).value}<span class="stat-unit">{formatBytes(vpnStore.rxBytes).unit}</span></span>
      </div>
      <span class="stat-label">DOWNLOAD</span>
    </div>

    <div class="divider"></div>

    <div class="stat">
      <div class="stat-icon timer"><IconClockBold /></div>
      <div class="stat-data">
        <span class="stat-value">{vpnStore.formattedUptime}</span>
      </div>
      <span class="stat-label">UPTIME</span>
    </div>
  </div>
</div>
{/if}

<style>
  .stats-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 14px;
    width: 100%;
    padding: 0 20px;
    animation: fadeUp 400ms ease-out;
  }

  .ip-display {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
  }
  .ip-value {
    font-family: var(--font-mono);
    font-size: 15px;
    font-weight: 500;
    color: var(--accent);
    letter-spacing: 0.02em;
  }
  .ip-label {
    font-family: var(--font-display);
    font-size: 9px;
    font-weight: 700;
    color: var(--text-muted);
    letter-spacing: 0.12em;
  }

  .stats-row {
    display: flex;
    align-items: center;
    width: 100%;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    padding: 14px 0;
  }

  .stat {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }

  .stat-icon {
    font-size: 14px;
    color: var(--text-muted);
    margin-bottom: 2px;
    line-height: 0;
  }
  .stat-icon.upload { color: var(--accent); }
  .stat-icon.download { color: #3B9EFF; }
  .stat-icon.timer { color: var(--text-secondary); }

  .stat-data {
    font-family: var(--font-mono);
    font-size: 16px;
    font-weight: 600;
    color: var(--text);
  }
  .stat-value {
    display: flex;
    align-items: baseline;
    gap: 2px;
  }
  .stat-unit {
    font-size: 11px;
    font-weight: 400;
    color: var(--text-secondary);
  }

  .stat-label {
    font-family: var(--font-display);
    font-size: 8px;
    font-weight: 700;
    color: var(--text-muted);
    letter-spacing: 0.12em;
  }

  .divider {
    width: 1px;
    height: 36px;
    background: var(--border);
  }

  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }
</style>
