<script lang="ts">
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import IconCaretDownBold from 'phosphor-icons-svelte/IconCaretDownBold.svelte';

  let open = $state(false);

  function select(id: string) {
    profilesStore.setActive(id);
    open = false;
  }
</script>

<div class="selector">
  <button class="selected" onclick={() => open = !open}>
    {#if profilesStore.activeProfile}
      <div class="server-info">
        <span class="server-name">{profilesStore.activeProfile.name}</span>
        <span class="server-addr">{profilesStore.activeProfile.server}</span>
      </div>
    {:else}
      <div class="server-info">
        <span class="server-name empty">No server selected</span>
        <span class="server-addr">Add a profile to connect</span>
      </div>
    {/if}
    <div class="caret"><IconCaretDownBold /></div>
  </button>
  {#if open && profilesStore.profiles.length > 1}
  <div class="dropdown">
    {#each profilesStore.profiles as profile (profile.id)}
    <button class="option" class:active={profile.id === profilesStore.activeProfileId}
      onclick={() => select(profile.id)}>
      <span class="option-name">{profile.name}</span>
      <span class="option-addr">{profile.server}</span>
    </button>
    {/each}
  </div>
  {/if}
</div>

<style>
  .selector { position: relative; width: 100%; padding: 0 20px; }

  .selected {
    width: 100%;
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    color: var(--text-secondary);
    cursor: pointer;
    transition: all 150ms ease;
  }
  .selected:hover {
    border-color: var(--border-hover);
    background: var(--surface-hover);
  }

  .server-info { display: flex; flex-direction: column; gap: 1px; text-align: left; }
  .server-name {
    font-family: var(--font-display);
    font-size: 13px;
    font-weight: 600;
    color: var(--text);
  }
  .server-name.empty { color: var(--text-muted); }
  .server-addr {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-muted);
  }

  .caret { font-size: 12px; color: var(--text-muted); }

  .dropdown {
    position: absolute;
    top: calc(100% + 4px);
    left: 20px;
    right: 20px;
    background: var(--bg-tertiary);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    z-index: 20;
    overflow: hidden;
    animation: dropIn 150ms ease-out;
  }
  .option {
    width: 100%;
    display: flex;
    flex-direction: column;
    gap: 1px;
    padding: 10px 14px;
    background: none;
    border: none;
    color: var(--text);
    cursor: pointer;
    text-align: left;
    transition: background 120ms ease;
  }
  .option:hover { background: var(--surface-hover); }
  .option.active { background: var(--accent-soft); }
  .option-name { font-family: var(--font-display); font-size: 13px; font-weight: 600; }
  .option-addr { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }

  @keyframes dropIn {
    from { opacity: 0; transform: translateY(-4px); }
    to { opacity: 1; transform: translateY(0); }
  }
</style>
