<script lang="ts">
  type ForwardingMode = 'none' | 'bungeecord' | 'obsidian';
  type WaitingStrategy = 'limbo' | 'hold' | 'message';

  type Backend = {
    name: string;
    addr: string;
    hostnames: string[];
    default: boolean;
    wake: string | null;
    wake_on_connect: boolean;
    waiting: WaitingStrategy[];
    limbo: string | null;
    forwarding: ForwardingMode;
    send_proxy_v2: boolean;
    hibernates: boolean;
    health: 'unknown' | 'up' | 'down' | 'starting' | string;
  };

  // The token is entered by the operator and kept for the tab's lifetime only.
  // It used to be a literal compiled into this bundle, which meant publishing
  // the admin credential to anyone who loaded the page.
  const TOKEN_KEY = 'obsidian.adminToken';

  let token = $state<string>(sessionStorage.getItem(TOKEN_KEY) ?? '');
  let tokenInput = $state<string>('');
  let authenticated = $state<boolean>(false);

  type ProxyEvent = {
    at: number;
    backend: string | null;
    kind: string;
    detail: string | null;
  };

  let backends = $state<Backend[]>([]);
  let events = $state<ProxyEvent[]>([]);
  let error = $state<string>('');
  let notice = $state<string>('');

  let newName = $state<string>('');
  let newAddr = $state<string>('');
  let newHostnames = $state<string>('');
  let newForwarding = $state<ForwardingMode>('none');

  let stats = $state({
    total_bytes_rx: 0,
    total_bytes_tx: 0,
    active_connections: 0
  });

  // Same-origin relative paths: the panel is served by the proxy itself, so
  // there is no cross-origin request to authorise.
  async function api(path: string, init: RequestInit = {}): Promise<Response> {
    const headers = new Headers(init.headers);
    headers.set('Authorization', `Bearer ${token}`);

    const res = await fetch(`/api${path}`, { ...init, headers });
    if (res.status === 401) {
      signOut('That token was rejected.');
      throw new Error('Unauthorized');
    }
    return res;
  }

  async function failureText(res: Response): Promise<string> {
    try {
      const body = await res.json();
      if (body && typeof body.error === 'string') return body.error;
    } catch {
      // Fall through to the status line.
    }
    return `Request failed (${res.status})`;
  }

  function signOut(message = '') {
    sessionStorage.removeItem(TOKEN_KEY);
    token = '';
    authenticated = false;
    backends = [];
    error = message;
  }

  async function signIn(e: Event) {
    e.preventDefault();
    if (!tokenInput.trim()) return;

    token = tokenInput.trim();
    error = '';
    try {
      const res = await api('/backends');
      if (!res.ok) throw new Error(await failureText(res));
      backends = await res.json();
      sessionStorage.setItem(TOKEN_KEY, token);
      authenticated = true;
      tokenInput = '';
      await Promise.all([fetchStats(), fetchEvents()]);
    } catch (err: any) {
      if (err.message !== 'Unauthorized') {
        token = '';
        error = err.message;
      }
    }
  }

  async function fetchBackends() {
    try {
      const res = await api('/backends');
      if (!res.ok) throw new Error(await failureText(res));
      backends = await res.json();
    } catch (err: any) {
      if (err.message !== 'Unauthorized') error = err.message;
    }
  }

  async function fetchEvents() {
    try {
      const res = await api('/events?limit=25');
      if (res.ok) events = await res.json();
    } catch {
      // History is a convenience; a failed poll is not worth an error banner.
    }
  }

  function formatEvent(kind: string): string {
    switch (kind) {
      case 'backend_up':
        return 'came up';
      case 'backend_down':
        return 'went down';
      case 'wake_requested':
        return 'wake requested';
      case 'config_applied':
        return 'configuration applied';
      case 'player_refused':
        return 'player refused';
      default:
        return kind;
    }
  }

  function formatTime(unixSeconds: number): string {
    return new Date(unixSeconds * 1000).toLocaleString();
  }

  async function fetchStats() {
    try {
      const res = await api('/stats');
      if (res.ok) stats = await res.json();
    } catch {
      // A failed stats poll is not worth interrupting the operator for.
    }
  }

  /// Sends the whole list. The file is the unit of change, so partial updates
  /// would only add conflict handling without buying anything.
  async function save(next: Backend[], what: string) {
    error = '';
    notice = '';
    try {
      const res = await api('/backends', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(
          next.map((b) => ({
            name: b.name,
            addr: b.addr,
            hostnames: b.hostnames,
            default: b.default,
            wake: b.wake,
            wake_on_connect: b.wake_on_connect ?? true,
            waiting: b.waiting,
            limbo: b.limbo ?? null,
            forwarding: b.forwarding ?? 'none',
            send_proxy_v2: b.send_proxy_v2 ?? false
          }))
        )
      });

      if (res.status === 409) {
        error =
          'The configuration file changed on disk. Reload to pick up that edit, then try again.';
        return;
      }
      if (!res.ok) throw new Error(await failureText(res));

      backends = await res.json();
      notice = what;
    } catch (err: any) {
      if (err.message !== 'Unauthorized') error = err.message;
    }
  }

  function addBackend(e: Event) {
    e.preventDefault();
    if (!newName || !newAddr) return;

    const hostnames = newHostnames
      .split(',')
      .map((h) => h.trim())
      .filter(Boolean);

    save(
      [
        ...backends,
        {
          name: newName,
          addr: newAddr,
          hostnames,
          default: backends.length === 0,
          wake: null,
          wake_on_connect: true,
          waiting: ['limbo', 'hold', 'message'],
          limbo: null,
          forwarding: newForwarding,
          send_proxy_v2: false,
          hibernates: false,
          health: 'unknown'
        }
      ],
      `Added ${newName}.`
    ).then(() => {
      newName = '';
      newAddr = '';
      newHostnames = '';
      newForwarding = 'none';
    });
  }

  function removeBackend(name: string) {
    if (!confirm(`Remove backend "${name}" from the configuration file?`)) return;
    save(
      backends.filter((b) => b.name !== name),
      `Removed ${name}.`
    );
  }

  function makeDefault(name: string) {
    save(
      backends.map((b) => ({ ...b, default: b.name === name })),
      `${name} is now the default backend.`
    );
  }

  function toggleForwarding(name: string, nextMode: ForwardingMode) {
    save(
      backends.map((b) => (b.name === name ? { ...b, forwarding: nextMode } : b)),
      `Updated forwarding for ${name} to ${nextMode}.`
    );
  }

  async function wakeBackend(name: string) {
    error = '';
    notice = '';
    try {
      const res = await api(`/backends/${encodeURIComponent(name)}/wake`, { method: 'POST' });
      if (!res.ok) throw new Error(await failureText(res));
      notice = `Wake requested for ${name}.`;
      await Promise.all([fetchBackends(), fetchEvents()]);
    } catch (err: any) {
      if (err.message !== 'Unauthorized') error = err.message;
    }
  }

  async function reload() {
    error = '';
    notice = '';
    try {
      const res = await api('/reload', { method: 'POST' });
      if (!res.ok) throw new Error(await failureText(res));
      backends = await res.json();
      notice = 'Reloaded from disk.';
    } catch (err: any) {
      if (err.message !== 'Unauthorized') error = err.message;
    }
  }

  // Restore a session token from a previous page load.
  $effect(() => {
    if (token && !authenticated) {
      fetchBackends().then(() => {
        if (token) authenticated = true;
      });
    }
  });

  $effect(() => {
    if (!authenticated) return;
    fetchStats();
    fetchEvents();
    const stats = setInterval(fetchStats, 1000);
    const health = setInterval(fetchBackends, 5000);
    const history = setInterval(fetchEvents, 10000);
    return () => {
      clearInterval(stats);
      clearInterval(health);
      clearInterval(history);
    };
  });
</script>

<main class="dashboard">
  <header>
    <h1>Obsidian</h1>
    <p>Server Administration Dashboard</p>
  </header>

  {#if error}
    <div class="error">{error}</div>
  {/if}
  {#if notice}
    <div class="notice">{notice}</div>
  {/if}

  {#if !authenticated}
    <section class="add-server-form">
      <h2>Sign in</h2>
      <p style="color: #a1a1aa; margin-bottom: 12px;">
        The proxy prints an admin token when it starts. Paste it here, or set
        <code>OBSIDIAN_ADMIN_TOKEN</code> to keep the same one across restarts.
      </p>
      <form onsubmit={signIn}>
        <input
          type="password"
          placeholder="Admin token"
          bind:value={tokenInput}
          autocomplete="current-password"
          required
        />
        <button type="submit">Sign in</button>
      </form>
    </section>
  {:else}
    <section class="stats-dashboard" style="display: flex; gap: 20px; margin-bottom: 20px;">
      <div class="stat-box" style="background: #1e1e24; padding: 15px; border-radius: 8px; flex: 1; text-align: center;">
        <h3 style="margin: 0; color: #a1a1aa; font-size: 0.9rem;">Active Connections</h3>
        <p style="margin: 10px 0 0; font-size: 2rem; font-weight: bold; color: #fff;">{stats.active_connections}</p>
      </div>
      <div class="stat-box" style="background: #1e1e24; padding: 15px; border-radius: 8px; flex: 1; text-align: center;">
        <h3 style="margin: 0; color: #a1a1aa; font-size: 0.9rem;">Total Data Transferred</h3>
        <p style="margin: 10px 0 0; font-size: 2rem; font-weight: bold; color: #fff;">{((stats.total_bytes_rx + stats.total_bytes_tx) / 1024).toFixed(2)} KB</p>
      </div>
    </section>

    <section class="add-server-form">
      <h2>Add Backend</h2>
      <p style="color: #a1a1aa; margin-bottom: 12px;">
        Saving writes to the proxy's configuration file and takes effect immediately.
      </p>
      <form onsubmit={addBackend}>
        <input type="text" placeholder="Name (e.g. survival)" bind:value={newName} required />
        <input type="text" placeholder="Address (e.g. 127.0.0.1:25566)" bind:value={newAddr} required />
        <input type="text" placeholder="Hostnames, comma separated (optional)" bind:value={newHostnames} />
        <select bind:value={newForwarding} aria-label="Forwarding mode">
          <option value="none">Forwarding: none</option>
          <option value="bungeecord">Forwarding: bungeecord</option>
          <option value="obsidian">Forwarding: obsidian (HMAC)</option>
        </select>
        <button type="submit">Add</button>
      </form>
    </section>

    <section class="server-list">
      <table>
        <thead>
          <tr>
            <th>Name</th>
            <th>Address</th>
            <th>Hostnames</th>
            <th>Forwarding</th>
            <th>Health</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {#each backends as backend}
            <tr>
              <td>
                {backend.name}
                {#if backend.default}<span class="badge active">default</span>{/if}
                {#if backend.hibernates}<span class="badge hibernated">hibernates</span>{/if}
              </td>
              <td>{backend.addr}</td>
              <td>{backend.hostnames.length ? backend.hostnames.join(', ') : '—'}</td>
              <td>
                <select
                  value={backend.forwarding ?? 'none'}
                  onchange={(e) => toggleForwarding(backend.name, (e.currentTarget as HTMLSelectElement).value as ForwardingMode)}
                  aria-label="Forwarding mode for {backend.name}"
                >
                  <option value="none">none</option>
                  <option value="bungeecord">bungeecord</option>
                  <option value="obsidian">obsidian</option>
                </select>
              </td>
              <td>
                <span class="badge {backend.health === 'up' ? 'active' : 'hibernated'}">
                  {backend.health}
                </span>
              </td>
              <td>
                {#if backend.hibernates && backend.health !== 'up' && backend.health !== 'starting'}
                  <button class="wake-btn" onclick={() => wakeBackend(backend.name)}>
                    Wake
                  </button>
                {/if}
                {#if !backend.default}
                  <button class="wake-btn" onclick={() => makeDefault(backend.name)}>
                    Make default
                  </button>
                {/if}
                <button class="delete-btn" onclick={() => removeBackend(backend.name)}>
                  Remove
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </section>

    {#if events.length}
      <section class="server-list" style="margin-top: 24px;">
        <h2>Recent activity</h2>
        <table>
          <thead>
            <tr>
              <th>When</th>
              <th>Backend</th>
              <th>What</th>
              <th>Detail</th>
            </tr>
          </thead>
          <tbody>
            {#each events as event}
              <tr>
                <td>{formatTime(event.at)}</td>
                <td>{event.backend ?? '—'}</td>
                <td>{formatEvent(event.kind)}</td>
                <td>{event.detail ?? '—'}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {/if}

    <div style="margin-top: 20px; display: flex; gap: 10px;">
      <button class="wake-btn" onclick={reload}>Reload from disk</button>
      <button class="delete-btn" onclick={() => signOut()}>Sign out</button>
    </div>
  {/if}
</main>
