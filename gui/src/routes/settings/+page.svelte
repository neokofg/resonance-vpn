<script lang="ts">
  let defaultDns = $state('1.1.1.1');
  let autoConnect = $state(false);
</script>

<div class="page">
  <h2>Settings</h2>

  <div class="section">
    <label class="setting">
      <div>
        <span class="label">Default DNS</span>
        <span class="desc">DNS servers for new profiles</span>
      </div>
      <input bind:value={defaultDns} placeholder="1.1.1.1" />
    </label>

    <label class="setting">
      <div>
        <span class="label">Auto-connect</span>
        <span class="desc">Connect on app launch</span>
      </div>
      <input type="checkbox" bind:checked={autoConnect} />
    </label>
  </div>

  <div class="section about">
    <div>
      <p class="about-name">Resonance VPN</p>
      <p class="about-ver">v0.1.0</p>
    </div>
  </div>
</div>

<style>
  .page { padding: 16px 20px; display: flex; flex-direction: column; gap: 16px; }
  h2 { font-family: var(--font-display); font-size: 18px; font-weight: 800; }

  .section {
    display: flex; flex-direction: column;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: var(--radius-md); overflow: hidden;
  }

  .setting {
    display: flex; align-items: center; justify-content: space-between;
    padding: 14px 16px; cursor: pointer;
  }
  .setting + .setting { border-top: 1px solid var(--border); }

  .label {
    font-family: var(--font-display);
    font-size: 14px; font-weight: 700; display: block;
  }
  .desc { font-size: 11px; color: var(--text-secondary); display: block; margin-top: 2px; }

  .setting input:not([type]) {
    width: 130px; padding: 7px 10px;
    background: rgba(0, 0, 0, 0.3);
    border: 1px solid var(--border);
    border-radius: var(--radius-sm);
    color: var(--text); font-size: 13px;
    font-family: var(--font-mono);
    outline: none; text-align: right;
  }
  .setting input:not([type]):focus { border-color: var(--accent); }

  .setting input[type="checkbox"] {
    width: 38px; height: 20px;
    appearance: none; background: var(--text-muted);
    border-radius: 10px; position: relative;
    cursor: pointer; transition: background 200ms ease;
  }
  .setting input[type="checkbox"]::after {
    content: ''; position: absolute;
    top: 2px; left: 2px;
    width: 16px; height: 16px;
    background: white; border-radius: 50%;
    transition: transform 200ms ease;
  }
  .setting input[type="checkbox"]:checked { background: var(--accent); }
  .setting input[type="checkbox"]:checked::after { transform: translateX(18px); }

  .about {
    flex-direction: row; align-items: center;
    gap: 12px; padding: 16px;
  }
  .about-name { font-family: var(--font-display); font-size: 14px; font-weight: 800; }
  .about-ver { font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); margin-top: 2px; }
</style>
