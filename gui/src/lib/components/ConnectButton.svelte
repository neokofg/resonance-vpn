<script lang="ts">
  import { vpnStore } from '$lib/stores/vpn.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { connectVpn, disconnectVpn } from '$lib/ipc/daemon';
  import IconPowerBold from 'phosphor-icons-svelte/IconPowerBold.svelte';

  async function toggle() {
    if (vpnStore.isTransitioning) return;
    try {
      if (vpnStore.isConnected) {
        await disconnectVpn();
      } else {
        const profile = profilesStore.activeProfile;
        if (!profile) return;
        await profilesStore.touchLastConnected(profile.id);
        await connectVpn(profile.server, profile.psk, profile.dns);
      }
    } catch (e) {
      console.error('VPN action failed:', e);
      vpnStore.error = String(e);
      vpnStore.state = 'error';
    }
  }

  let stateClass = $derived(
    vpnStore.isConnected ? 'connected' :
    vpnStore.state === 'connecting' ? 'connecting' :
    vpnStore.state === 'disconnecting' ? 'disconnecting' :
    vpnStore.state === 'error' ? 'error' : 'idle'
  );

  let statusText = $derived(
    vpnStore.state === 'connected' ? 'SECURED' :
    vpnStore.state === 'connecting' ? 'CONNECTING' :
    vpnStore.state === 'disconnecting' ? 'DISCONNECTING' :
    vpnStore.state === 'error' ? 'FAILED' :
    !profilesStore.activeProfile ? 'NO SERVER' : 'DISCONNECTED'
  );

  let subStatus = $derived(
    vpnStore.isConnected && profilesStore.activeProfile
      ? profilesStore.activeProfile.name
      : vpnStore.error ?? ''
  );
</script>

<div class="connect-wrapper {stateClass}">
  <button class="connect-btn" onclick={toggle}
    disabled={vpnStore.isTransitioning || !profilesStore.activeProfile}
    aria-label={vpnStore.isConnected ? 'Disconnect' : 'Connect'}>
    <div class="glow"></div>
    <svg class="orbit" viewBox="0 0 200 200" fill="none">
      <circle class="orbit-track" cx="100" cy="100" r="97" />
    </svg>
    <div class="ring"></div>
    <div class="face">
      <IconPowerBold />
    </div>
  </button>
  <p class="status">{statusText}</p>
  {#if subStatus}
    <p class="sub-status">{subStatus}</p>
  {/if}
</div>

<style>
  .connect-wrapper {
    display: flex;
    flex-direction: column;
    align-items: center;
  }

  .connect-btn {
    position: relative;
    width: 200px;
    height: 200px;
    background: none;
    border: none;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 0;
  }
  .connect-btn:disabled { cursor: not-allowed; }

  .glow {
    position: absolute;
    width: 280px;
    height: 280px;
    border-radius: 50%;
    background: radial-gradient(circle, var(--accent-glow) 0%, transparent 70%);
    opacity: 0;
    transition: opacity 600ms ease;
    pointer-events: none;
  }
  .connected .glow {
    opacity: 1;
    animation: breathe 4s ease-in-out infinite;
  }
  .error .glow {
    opacity: 0.6;
    background: radial-gradient(circle, var(--error-glow) 0%, transparent 70%);
  }

  .orbit {
    position: absolute;
    width: 196px;
    height: 196px;
  }
  .orbit-track {
    stroke: var(--text-muted);
    stroke-width: 0.8;
    stroke-dasharray: 8 6;
    opacity: 0.5;
    animation: orbit-spin 40s linear infinite;
    transform-origin: center;
  }
  .connecting .orbit-track {
    stroke: var(--accent);
    opacity: 1;
    stroke-dasharray: 14 4;
    animation-duration: 1.5s;
  }
  .connected .orbit-track {
    stroke: var(--accent);
    opacity: 0.4;
    stroke-dasharray: none;
    animation: none;
  }
  .error .orbit-track {
    stroke: var(--error);
    opacity: 0.5;
    animation-duration: 20s;
  }
  .disconnecting .orbit-track {
    stroke: var(--text-secondary);
    opacity: 0.6;
    animation-duration: 3s;
  }

  .ring {
    position: absolute;
    width: 164px;
    height: 164px;
    border-radius: 50%;
    border: 1.5px solid var(--border);
    transition: all 500ms ease;
  }
  .connecting .ring {
    border-color: var(--accent-medium);
  }
  .connected .ring {
    border-color: var(--accent);
    box-shadow: 0 0 30px var(--accent-soft), inset 0 0 30px var(--accent-soft);
  }
  .error .ring {
    border-color: var(--error);
  }

  .face {
    position: relative;
    width: 148px;
    height: 148px;
    border-radius: 50%;
    background: var(--bg-secondary);
    border: 1px solid var(--border);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 36px;
    color: var(--text-muted);
    transition: all 500ms ease;
  }
  .connect-btn:not(:disabled):hover .face {
    border-color: var(--border-hover);
    color: var(--text-secondary);
    background: var(--bg-tertiary);
  }
  .connecting .face {
    color: var(--accent);
    border-color: var(--accent-medium);
  }
  .connected .face {
    color: var(--accent);
    border-color: rgba(0, 223, 162, 0.25);
    background: rgba(0, 223, 162, 0.04);
  }
  .error .face {
    color: var(--error);
    border-color: rgba(255, 92, 92, 0.3);
  }
  .connect-btn:disabled .face {
    opacity: 0.35;
  }

  .status {
    margin-top: 24px;
    font-family: var(--font-display);
    font-size: 12px;
    font-weight: 800;
    letter-spacing: 0.18em;
    color: var(--text-secondary);
    text-align: center;
    transition: color 400ms ease;
  }
  .connected .status { color: var(--accent); }
  .error .status { color: var(--error); }

  .sub-status {
    margin-top: 4px;
    font-size: 11px;
    color: var(--text-muted);
    text-align: center;
    max-width: 280px;
    word-break: break-word;
  }
  .error .sub-status { color: rgba(255, 92, 92, 0.7); }

  @keyframes breathe {
    0%, 100% { opacity: 0.5; transform: scale(1); }
    50% { opacity: 1; transform: scale(1.05); }
  }
  @keyframes orbit-spin {
    to { transform: rotate(360deg); }
  }
</style>
