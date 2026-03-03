<script lang="ts">
  import { deployServer, onDaemonEvent, type DaemonEvent } from '$lib/ipc/daemon';
  import { profilesStore } from '$lib/stores/profiles.svelte';
  import IconRocketLaunchBold from 'phosphor-icons-svelte/IconRocketLaunchBold.svelte';
  import IconCheckCircleFill from 'phosphor-icons-svelte/IconCheckCircleFill.svelte';
  import IconWarningCircleFill from 'phosphor-icons-svelte/IconWarningCircleFill.svelte';
  import IconSlidersHorizontalBold from 'phosphor-icons-svelte/IconSlidersHorizontalBold.svelte';

  let step = $state(1);
  let advanced = $state(false);

  let host = $state('');
  let authMethod = $state<'key' | 'password'>('key');
  let sshKey = $state('~/.ssh/id_ed25519');
  let password = $state('');

  let user = $state('root');
  let sshPort = $state(22);
  let domain = $state('');
  let port = $state(443);
  let subnet = $state('10.8.0.0/24');

  let logs = $state<string[]>([]);
  let deployError = $state<string | null>(null);
  let deployedPsk = $state<string | null>(null);

  const cleanup = onDaemonEvent((event: DaemonEvent) => {
    if (event.type === 'deploy_progress') {
      logs = [...logs, `[${event.step}/${event.total}] ${event.message}`];
    }
    if (event.type === 'response' && step === 2) {
      if (event.success) {
        step = 3;
        if (event.data && 'psk' in event.data) {
          deployedPsk = event.data.psk as string;
          const serverAddr = port === 443 ? host : `${host}:${port}`;
          profilesStore.addProfile({
            name: domain || host,
            server: serverAddr,
            psk: deployedPsk,
            dns: ['1.1.1.1', '8.8.8.8'],
          });
        }
      } else {
        deployError = event.error ?? 'Deploy failed';
        step = 3;
      }
    }
  });

  async function startDeploy() {
    step = 2; logs = []; deployError = null;
    await deployServer({
      host, user,
      sshKey: authMethod === 'key' ? sshKey : undefined,
      password: authMethod === 'password' ? password : undefined,
      sshPort, domain: domain || undefined, port, subnet,
    });
  }

  let canDeploy = $derived(
    host && (authMethod === 'key' ? sshKey : password)
  );
</script>

<div class="page">
  {#if step === 1}
    <h2>Deploy</h2>
    <p class="subtitle">Provision a VPN server via SSH</p>

    <div class="form">
      <label><span>HOST</span><input bind:value={host} placeholder="1.2.3.4 or vpn.example.com" /></label>

      <div class="auth-toggle">
        <button class:active={authMethod === 'key'} onclick={() => authMethod = 'key'}>SSH Key</button>
        <button class:active={authMethod === 'password'} onclick={() => authMethod = 'password'}>Password</button>
      </div>

      {#if authMethod === 'key'}
        <label><span>SSH KEY PATH</span><input bind:value={sshKey} /></label>
      {:else}
        <label><span>SSH PASSWORD</span><input type="password" bind:value={password} placeholder="Server password" /></label>
      {/if}

      <button class="advanced-toggle" class:open={advanced} onclick={() => advanced = !advanced}>
        <IconSlidersHorizontalBold />
        <span>Advanced</span>
        <svg class="chevron" viewBox="0 0 10 6" fill="none">
          <path d="M1 1L5 5L9 1" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
      </button>

      {#if advanced}
        <div class="advanced-fields">
          <label><span>SSH USER</span><input bind:value={user} /></label>
          <label><span>SSH PORT</span><input type="number" bind:value={sshPort} /></label>
          <label><span>DOMAIN</span><input bind:value={domain} placeholder="For Let's Encrypt (optional)" /></label>
          <label><span>SERVER PORT</span><input type="number" bind:value={port} /></label>
          <label><span>VPN SUBNET</span><input bind:value={subnet} /></label>
        </div>
      {/if}

      <button class="btn-deploy" onclick={startDeploy} disabled={!canDeploy}>
        <IconRocketLaunchBold />
        Deploy Server
      </button>
    </div>

  {:else if step === 2}
    <h2>Deploying</h2>
    <div class="log-area">
      {#each logs as line}
        <p class="log-line">{line}</p>
      {/each}
      <div class="spinner"></div>
    </div>

  {:else}
    {#if deployError}
      <div class="result error">
        <div class="result-icon"><IconWarningCircleFill /></div>
        <h2>Deploy Failed</h2>
        <p>{deployError}</p>
        <button class="btn-deploy" onclick={() => step = 1}>Try Again</button>
      </div>
    {:else}
      <div class="result success">
        <div class="result-icon"><IconCheckCircleFill /></div>
        <h2>Server Deployed</h2>
        <p>Profile added automatically.</p>
        <button class="btn-deploy" onclick={() => step = 1}>Deploy Another</button>
      </div>
    {/if}
  {/if}
</div>

<style>
  .page { padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }
  h2 { font-family: var(--font-display); font-size: 18px; font-weight: 800; }
  .subtitle { font-size: 12px; color: var(--text-secondary); }

  .form { display: flex; flex-direction: column; gap: 12px; }
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

  .auth-toggle {
    display: flex; gap: 3px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm); padding: 3px;
  }
  .auth-toggle button {
    flex: 1; padding: 7px;
    border: none; background: none;
    color: var(--text-secondary);
    font-family: var(--font-display); font-size: 12px; font-weight: 700;
    cursor: pointer; border-radius: 5px;
    transition: all 150ms ease;
  }
  .auth-toggle button.active { background: var(--accent); color: #050709; }

  .advanced-toggle {
    display: flex; align-items: center; gap: 8px;
    padding: 8px 0;
    background: none; border: none;
    color: var(--text-muted);
    font-family: var(--font-display); font-size: 12px; font-weight: 700;
    letter-spacing: 0.04em;
    cursor: pointer; transition: color 150ms ease;
  }
  .advanced-toggle:hover { color: var(--text-secondary); }
  .advanced-toggle.open { color: var(--accent); }
  .chevron {
    width: 10px; height: 6px;
    transition: transform 200ms ease;
    margin-left: auto;
  }
  .advanced-toggle.open .chevron { transform: rotate(180deg); }

  .advanced-fields {
    display: flex; flex-direction: column; gap: 12px;
    padding: 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius-md);
    animation: slideDown 200ms ease-out;
  }

  .btn-deploy {
    display: flex; align-items: center; justify-content: center; gap: 8px;
    padding: 11px; background: var(--accent); color: #050709;
    border: none; border-radius: var(--radius-sm);
    font-family: var(--font-display); font-size: 13px; font-weight: 700;
    cursor: pointer; margin-top: 4px; transition: all 150ms ease;
  }
  .btn-deploy:hover { filter: brightness(1.1); }
  .btn-deploy:disabled { opacity: 0.4; cursor: not-allowed; }

  .log-area {
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    padding: 14px; max-height: 420px;
    overflow-y: auto;
  }
  .log-line {
    font-family: var(--font-mono); font-size: 11px;
    color: var(--text-secondary); padding: 3px 0;
  }

  .spinner {
    width: 14px; height: 14px;
    border: 2px solid var(--border);
    border-top-color: var(--accent);
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin-top: 10px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  @keyframes slideDown {
    from { opacity: 0; transform: translateY(-6px); }
    to { opacity: 1; transform: translateY(0); }
  }

  .result {
    display: flex; flex-direction: column;
    align-items: center; gap: 12px;
    padding: 48px 24px; text-align: center;
  }
  .result-icon { font-size: 48px; }
  .result.success { color: var(--accent); }
  .result.error { color: var(--error); }
  .result p { font-size: 13px; color: var(--text-secondary); }
</style>
