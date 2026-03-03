<script lang="ts">
  import { page } from '$app/stores';
  import IconShieldCheckBold from 'phosphor-icons-svelte/IconShieldCheckBold.svelte';
  import IconShieldCheckFill from 'phosphor-icons-svelte/IconShieldCheckFill.svelte';
  import IconListBold from 'phosphor-icons-svelte/IconListBold.svelte';
  import IconListFill from 'phosphor-icons-svelte/IconListFill.svelte';
  import IconRocketLaunchBold from 'phosphor-icons-svelte/IconRocketLaunchBold.svelte';
  import IconRocketLaunchFill from 'phosphor-icons-svelte/IconRocketLaunchFill.svelte';
  import IconGearSixBold from 'phosphor-icons-svelte/IconGearSixBold.svelte';
  import IconGearSixFill from 'phosphor-icons-svelte/IconGearSixFill.svelte';

  const nav = [
    { href: '/', label: 'VPN', icon: IconShieldCheckBold, activeIcon: IconShieldCheckFill },
    { href: '/profiles', label: 'Servers', icon: IconListBold, activeIcon: IconListFill },
    { href: '/deploy', label: 'Deploy', icon: IconRocketLaunchBold, activeIcon: IconRocketLaunchFill },
    { href: '/settings', label: 'Settings', icon: IconGearSixBold, activeIcon: IconGearSixFill },
  ];

  let currentPath = $derived($page.url.pathname);
</script>

<nav class="navbar">
  {#each nav as item (item.href)}
    {@const active = currentPath === item.href}
    <a href={item.href} class="nav-item" class:active>
      {#if active}
        {@const Icon = item.activeIcon}
        <Icon />
      {:else}
        {@const Icon = item.icon}
        <Icon />
      {/if}
      <span>{item.label}</span>
      {#if active}<div class="indicator"></div>{/if}
    </a>
  {/each}
</nav>

<style>
  .navbar {
    display: flex;
    align-items: center;
    justify-content: space-around;
    height: 52px;
    border-top: 1px solid var(--border);
    background: rgba(5, 7, 9, 0.9);
    backdrop-filter: blur(20px);
    flex-shrink: 0;
    position: relative;
    z-index: 10;
  }
  .nav-item {
    position: relative;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 3px;
    padding: 6px 18px;
    color: var(--text-muted);
    text-decoration: none;
    font-size: 16px;
    transition: color 200ms ease;
  }
  .nav-item span {
    font-family: var(--font-display);
    font-size: 9px;
    font-weight: 700;
    letter-spacing: 0.08em;
    text-transform: uppercase;
  }
  .nav-item:hover { color: var(--text-secondary); }
  .nav-item.active { color: var(--accent); }
  .indicator {
    position: absolute;
    bottom: 0;
    width: 16px;
    height: 2px;
    background: var(--accent);
    border-radius: 1px;
  }
</style>
