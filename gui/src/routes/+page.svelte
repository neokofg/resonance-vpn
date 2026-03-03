<script lang="ts">
  import { onMount } from 'svelte';
  import ConnectButton from '$lib/components/ConnectButton.svelte';
  import ConnectionStats from '$lib/components/ConnectionStats.svelte';
  import ServerSelector from '$lib/components/ServerSelector.svelte';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { vpnStore } from '$lib/stores/vpn.svelte';

  onMount(async () => { await profilesStore.init(); });
</script>

<div class="page">
  <div class="hero">
    <ConnectButton />
  </div>
  <div class="bottom">
    {#if vpnStore.isConnected}
      <ConnectionStats />
    {:else}
      <ServerSelector />
    {/if}
  </div>
</div>

<style>
  .page {
    display: flex;
    flex-direction: column;
    height: 100%;
    position: relative;
  }
  .page::before {
    content: '';
    position: absolute;
    top: 30%;
    left: 50%;
    width: 400px;
    height: 400px;
    transform: translate(-50%, -50%);
    background: radial-gradient(circle, rgba(0, 223, 162, 0.03) 0%, transparent 70%);
    pointer-events: none;
  }
  .hero {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
    z-index: 1;
  }
  .bottom {
    padding-bottom: 12px;
    position: relative;
    z-index: 1;
  }
</style>
