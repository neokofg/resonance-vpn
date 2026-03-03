<script lang="ts">
  import { getCurrentWindow } from '@tauri-apps/api/window';
  import IconMinusBold from 'phosphor-icons-svelte/IconMinusBold.svelte';
  import IconXBold from 'phosphor-icons-svelte/IconXBold.svelte';

  const appWindow = getCurrentWindow();
</script>

<div class="titlebar" data-tauri-drag-region>
  <span class="title" data-tauri-drag-region>RESONANCE</span>
  <div class="controls">
    <button onclick={() => appWindow.minimize()} aria-label="Minimize">
      <IconMinusBold />
    </button>
    <button class="close" onclick={() => appWindow.hide()} aria-label="Close">
      <IconXBold />
    </button>
  </div>
</div>

<style>
  .titlebar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    height: 36px;
    padding: 0 10px 0 14px;
    background: transparent;
    border-bottom: 1px solid var(--border);
    flex-shrink: 0;
  }
  .title {
    font-family: var(--font-display);
    font-size: 10px;
    font-weight: 800;
    color: var(--text-muted);
    letter-spacing: 0.2em;
  }
  .controls { display: flex; gap: 2px; }
  .controls button {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 26px;
    height: 26px;
    border: none;
    background: transparent;
    color: var(--text-muted);
    border-radius: 6px;
    cursor: pointer;
    font-size: 12px;
    transition: all 120ms ease;
  }
  .controls button:hover { background: var(--surface-hover); color: var(--text-secondary); }
  .controls .close:hover { background: var(--error-soft); color: var(--error); }
</style>
