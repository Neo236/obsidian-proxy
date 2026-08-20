<script lang="ts">
  type Server = {
    id: number | string;
    name: string;
    target_addr?: string;
    is_hibernating?: boolean;
    status: 'active' | 'hibernated' | string;
  };

  let servers = $state<Server[]>([]);
  let error = $state<string>('');
  
  let newName = $state<string>('');
  let newAddr = $state<string>('');

  let stats = $state({
    total_bytes_rx: 0,
    total_bytes_tx: 0,
    active_connections: 0
  });

  async function fetchServers() {
    try {
      const res = await fetch('http://localhost:3000/api/servers', {
        headers: {
          'Authorization': 'Bearer obsidian_secret'
        }
      });
      if (!res.ok) throw new Error('Failed to fetch servers');
      servers = await res.json();
    } catch (err: any) {
      error = err.message;
    }
  }

  async function fetchStats() {
    try {
      const res = await fetch('http://localhost:3000/api/stats', {
        headers: {
          'Authorization': 'Bearer obsidian_secret'
        }
      });
      if (res.ok) {
        stats = await res.json();
      }
    } catch (err) {
      // ignore
    }
  }

  async function wakeUp(id: number | string) {
    try {
      const res = await fetch(`http://localhost:3000/api/servers/${id}/wake`, {
        method: 'POST',
        headers: {
          'Authorization': 'Bearer obsidian_secret'
        }
      });
      if (!res.ok) throw new Error('Failed to wake up server');
      await fetchServers();
    } catch (err: any) {
      error = err.message;
    }
  }

  async function addServer(e: Event) {
    e.preventDefault();
    if (!newName || !newAddr) return;
    try {
      const res = await fetch('http://localhost:3000/api/servers', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer obsidian_secret'
        },
        body: JSON.stringify({ name: newName, target_addr: newAddr })
      });
      if (!res.ok) throw new Error('Failed to add server');
      newName = '';
      newAddr = '';
      await fetchServers();
    } catch (err: any) {
      error = err.message;
    }
  }

  async function deleteServer(id: number | string) {
    if (!confirm('Are you sure you want to delete this server?')) return;
    try {
      const res = await fetch(`http://localhost:3000/api/servers/${id}`, {
        method: 'DELETE',
        headers: {
          'Authorization': 'Bearer obsidian_secret'
        }
      });
      if (!res.ok) throw new Error('Failed to delete server');
      await fetchServers();
    } catch (err: any) {
      error = err.message;
    }
  }

  // Fetch initially
  $effect(() => {
    fetchServers();
    fetchStats();
    const interval = setInterval(fetchStats, 1000);
    return () => clearInterval(interval);
  });
</script>

<main class="dashboard">
  <header>
    <h1>Obsidian</h1>
    <p>Server Administration Dashboard</p>
  </header>

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

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <section class="add-server-form">
    <h2>Add Server</h2>
    <form onsubmit={addServer}>
      <input type="text" placeholder="Server Name" bind:value={newName} required />
      <input type="text" placeholder="Target Addr (e.g., 127.0.0.1:25565)" bind:value={newAddr} required />
      <button type="submit">Add</button>
    </form>
  </section>

  <section class="server-list">
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Name</th>
          <th>Address</th>
          <th>Status</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each servers as server}
          <tr>
            <td>{server.id}</td>
            <td>{server.name}</td>
            <td>{server.target_addr || 'N/A'}</td>
            <td>
              <span class="badge {server.status}">{server.status}</span>
            </td>
            <td>
              {#if server.status === 'hibernated'}
                <button class="wake-btn" onclick={() => wakeUp(server.id)}>Wake Up</button>
              {/if}
              <button class="delete-btn" onclick={() => deleteServer(server.id)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  </section>
</main>
