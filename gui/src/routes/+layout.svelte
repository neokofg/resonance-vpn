<script lang="ts">
  import '../app.css';
  import Titlebar from '$lib/components/Titlebar.svelte';
  import NavBar from '$lib/components/NavBar.svelte';

  let { children } = $props();
</script>

<div class="app">
  <Titlebar />
  <main>{@render children()}</main>
  <NavBar />
</div>

<style>
  .app {
    display: flex;
    flex-direction: column;
    height: 100vh;
    background: var(--bg);
  }
  main {
    flex: 1;
    overflow-y: auto;
    position: relative;
  }
</style>
