<script lang="ts">
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import { onMount } from 'svelte';
  import IconPlusBold from 'phosphor-icons-svelte/IconPlusBold.svelte';
  import IconTrashBold from 'phosphor-icons-svelte/IconTrashBold.svelte';
  import IconPencilSimpleBold from 'phosphor-icons-svelte/IconPencilSimpleBold.svelte';

  onMount(() => profilesStore.init());

  let showForm = $state(false);
  let editingId = $state<string | null>(null);
  let name = $state('');
  let server = $state('');
  let psk = $state('');
  let dns = $state('1.1.1.1');

  function openAdd() {
    editingId = null; name = ''; server = ''; psk = ''; dns = '1.1.1.1';
    showForm = true;
  }

  function openEdit(profile: typeof profilesStore.profiles[0]) {
    editingId = profile.id;
    name = profile.name; server = profile.server; psk = profile.psk;
    dns = profile.dns.join(', ');
    showForm = true;
  }

  async function save() {
    const dnsArr = dns.split(',').map(s => s.trim()).filter(Boolean);
    if (editingId) {
      await profilesStore.updateProfile(editingId, { name, server, psk, dns: dnsArr });
    } else {
      await profilesStore.addProfile({ name, server, psk, dns: dnsArr });
    }
    showForm = false;
  }

  async function remove(id: string) {
    await profilesStore.deleteProfile(id);
  }
</script>

<div class="page">
  <div class="header">
    <h2>Servers</h2>
    <button class="icon-btn" onclick={openAdd}><IconPlusBold /></button>
  </div>

  {#if showForm}
    <div class="card form">
      <label>
        <span>NAME</span>
        <input bind:value={name} placeholder="My VPN Server" />
      </label>
      <label>
        <span>SERVER</span>
        <input bind:value={server} placeholder="vpn.example.com:443" />
      </label>
      <label>
        <span>PSK</span>
        <input bind:value={psk} type="password" placeholder="Pre-shared key" />
      </label>
      <label>
        <span>DNS</span>
        <input bind:value={dns} placeholder="1.1.1.1, 8.8.8.8" />
      </label>
      <div class="form-actions">
        <button class="btn-ghost" onclick={() => showForm = false}>Cancel</button>
        <button class="btn-primary" onclick={save} disabled={!name || !server || !psk}>
          {editingId ? 'Update' : 'Add'}
        </button>
      </div>
    </div>
  {/if}

  <div class="list">
    {#each profilesStore.profiles as profile (profile.id)}
      <div class="card profile" class:active={profile.id === profilesStore.activeProfileId}>
        <button class="profile-main" onclick={() => profilesStore.setActive(profile.id)}>
          <span class="profile-name">{profile.name}</span>
          <span class="profile-server">{profile.server}</span>
        </button>
        <div class="profile-actions">
          <button class="icon-btn-sm" onclick={() => openEdit(profile)}><IconPencilSimpleBold /></button>
          <button class="icon-btn-sm" onclick={() => remove(profile.id)}><IconTrashBold /></button>
        </div>
      </div>
    {/each}
    {#if profilesStore.profiles.length === 0}
      <p class="empty">No servers configured yet.</p>
    {/if}
  </div>
</div>

<style>
  .page { padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }
  .header { display: flex; align-items: center; justify-content: space-between; }
  h2 { font-family: var(--font-display); font-size: 18px; font-weight: 800; }

  .icon-btn {
    display: flex; align-items: center; justify-content: center;
    width: 32px; height: 32px;
    border: 1px solid var(--border); background: var(--surface);
    color: var(--text-secondary); border-radius: var(--radius-sm);
    cursor: pointer; font-size: 16px; transition: all 150ms ease;
  }
  .icon-btn:hover { border-color: var(--accent); color: var(--accent); }

  .card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
  }

  .form { padding: 16px; display: flex; flex-direction: column; gap: 12px; }
  .form label { display: flex; flex-direction: column; gap: 4px; }
  .form label span {
    font-family: var(--font-display);
    font-size: 10px; color: var(--text-secondary); font-weight: 700;
    letter-spacing: 0.08em;
  }
  .form input {
    padding: 10px 14px; background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border); border-radius: var(--radius-sm);
    color: var(--text); font-size: 13px; font-family: var(--font-mono);
    outline: none; transition: border-color 150ms ease;
  }
  .form input:focus { border-color: var(--accent); }
  .form input::placeholder { color: var(--text-muted); }

  .form-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px; }

  .btn-primary {
    padding: 8px 18px; background: var(--accent); color: #050709;
    border: none; border-radius: var(--radius-sm);
    font-family: var(--font-display); font-size: 12px; font-weight: 700;
    cursor: pointer; transition: all 150ms ease;
  }
  .btn-primary:hover { filter: brightness(1.1); }
  .btn-primary:disabled { opacity: 0.4; cursor: not-allowed; }

  .btn-ghost {
    padding: 8px 18px; background: transparent; color: var(--text-secondary);
    border: 1px solid var(--border); border-radius: var(--radius-sm);
    font-family: var(--font-display); font-size: 12px; font-weight: 600;
    cursor: pointer; transition: all 150ms ease;
  }
  .btn-ghost:hover { border-color: var(--border-hover); color: var(--text); }

  .profile { display: flex; align-items: center; transition: border-color 200ms ease; }
  .profile.active { border-color: var(--accent); background: var(--accent-soft); }

  .profile-main {
    flex: 1; display: flex; flex-direction: column; gap: 2px;
    padding: 12px 16px; background: none; border: none;
    color: var(--text); cursor: pointer; text-align: left;
  }
  .profile-name { font-family: var(--font-display); font-weight: 700; font-size: 14px; }
  .profile-server { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); }

  .profile-actions { display: flex; gap: 2px; padding-right: 8px; }
  .icon-btn-sm {
    display: flex; align-items: center; justify-content: center;
    width: 28px; height: 28px;
    background: none; border: none;
    color: var(--text-muted); cursor: pointer;
    border-radius: 6px; font-size: 14px; transition: all 120ms ease;
  }
  .icon-btn-sm:hover { color: var(--text); background: var(--surface-hover); }

  .list { display: flex; flex-direction: column; gap: 8px; }
  .empty { text-align: center; color: var(--text-muted); font-size: 13px; padding: 40px 20px; }
</style>
