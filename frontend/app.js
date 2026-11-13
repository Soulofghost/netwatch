const API_BASE = '/api';

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initModal();
  initScanner();
  loadStats();
  loadAssets();
  loadSubnets();
});

function initTabs() {
  const tabs = document.querySelectorAll('.tab-btn');
  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      tabs.forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      const target = tab.dataset.tab === 'assets' ? 'paneAssets' :
                     tab.dataset.tab === 'subnets' ? 'paneSubnets' : 'paneScanner';
      document.getElementById(target)?.classList.add('active');

      if (tab.dataset.tab === 'assets') loadAssets();
      if (tab.dataset.tab === 'subnets') loadSubnets();
    });
  });
}

function initModal() {
  const modal = document.getElementById('subnetModal');
  const openBtn = document.getElementById('openSubnetModal');
  const closeBtn = document.getElementById('closeSubnetBtn');
  const cancelBtn = document.getElementById('cancelSubnetBtn');
  const form = document.getElementById('createSubnetForm');

  openBtn?.addEventListener('click', () => modal.classList.add('active'));
  closeBtn?.addEventListener('click', () => modal.classList.remove('active'));
  cancelBtn?.addEventListener('click', () => modal.classList.remove('active'));

  form?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const label = document.getElementById('subLabel').value.trim();
    const cidr = document.getElementById('subCidr').value.trim();

    try {
      const res = await fetch(`${API_BASE}/subnets`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label, cidr })
      });

      if (!res.ok) {
        const err = await res.json();
        throw new Error(err.detail || 'Failed to register subnet');
      }

      modal.classList.remove('active');
      form.reset();
      await loadStats();
      await loadSubnets();
      await loadAssets();
    } catch (err) {
      alert(`Error: ${err.message}`);
    }
  });
}

function initScanner() {
  const btn = document.getElementById('runScanBtn');
  btn?.addEventListener('click', async () => {
    const ip = document.getElementById('targetIpInput').value.trim();
    const portsRaw = document.getElementById('targetPortsInput').value.trim();
    if (!ip) {
      alert('Please enter a target IP address.');
      return;
    }
    const ports = portsRaw ? portsRaw.split(',').map(p => parseInt(p.trim())).filter(n => !isNaN(n)) : [21, 22, 23, 80, 443];

    btn.disabled = true;
    btn.innerText = 'Scanning Sockets...';

    try {
      const res = await fetch(`${API_BASE}/scan/host`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip, ports })
      });

      if (!res.ok) throw new Error('Port scan probe failed');
      const data = await res.json();
      renderScanResults(data);
      loadStats();
    } catch (err) {
      alert(`Scan failed: ${err.message}`);
    } finally {
      btn.disabled = false;
      btn.innerText = '⚡ Initiate Socket Probe';
    }
  });
}

function renderScanResults(data) {
  const badge = document.getElementById('scanRiskBadge');
  badge.innerText = `STATUS: ${data.is_alive ? 'HOST UP' : 'NO RESPONSE'}`;
  badge.className = 'badge ' + (data.highest_risk === 'CRITICAL' ? 'badge-critical' : data.is_alive ? 'badge-open' : 'badge-closed');

  const tbody = document.getElementById('scanResultsBody');
  if (!data.findings || data.findings.length === 0) {
    tbody.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No probe results available.</td></tr>`;
    return;
  }

  tbody.innerHTML = data.findings.map(f => `
    <tr>
      <td class="text-mono"><strong>${f.port}/${f.protocol}</strong></td>
      <td>${f.service}</td>
      <td><span class="badge ${f.state === 'OPEN' ? 'badge-open' : 'badge-closed'}">${f.state}</span></td>
      <td><span class="badge ${f.risk_level === 'CRITICAL' ? 'badge-critical' : 'badge-clean'}">${f.risk_level}</span></td>
      <td class="text-mono">${f.latency_ms} ms</td>
    </tr>
  `).join('');
}

async function loadStats() {
  try {
    const res = await fetch(`${API_BASE}/stats`);
    const data = await res.json();
    document.getElementById('statSubnets').innerText = data.totalSubnets;
    document.getElementById('statAssets').innerText = data.totalAssets;
    document.getElementById('statRogues').innerText = data.rogueAssets;
    document.getElementById('statHighRisk').innerText = data.highRiskPorts;
  } catch (err) {
    console.warn('Failed to load stats', err);
  }
}

async function loadAssets() {
  const tbody = document.getElementById('assetsTableBody');
  try {
    const res = await fetch(`${API_BASE}/assets`);
    const assets = await res.json();

    if (!assets || assets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; padding: 2rem; color: var(--text-secondary);">No assets discovered. Register a CIDR subnet to map network nodes.</td></tr>`;
      return;
    }

    tbody.innerHTML = assets.map(a => `
      <tr>
        <td><span class="badge badge-online">${a.status}</span></td>
        <td class="text-mono" style="color: var(--accent-sky); font-weight:600;">${a.ip_address}</td>
        <td><strong>${escapeHtml(a.hostname)}</strong></td>
        <td class="text-mono" style="font-size:0.75rem;">${a.mac_address}</td>
        <td>${a.os_family}</td>
        <td><span class="badge badge-info">${a.open_ports_count} Ports</span></td>
        <td><span class="badge ${a.is_rogue ? 'badge-rogue' : 'badge-clean'}">${a.is_rogue ? '⚠️ ROGUE' : 'Authorized'}</span></td>
        <td style="font-size:0.75rem;">${new Date(a.last_seen).toLocaleDateString()}</td>
      </tr>
    `).join('');
  } catch (err) {
    tbody.innerHTML = `<tr><td colspan="8" style="color: var(--accent-red); padding: 1rem;">Failed to load assets: ${err.message}</td></tr>`;
  }
}

async function loadSubnets() {
  const grid = document.getElementById('subnetsGrid');
  try {
    const res = await fetch(`${API_BASE}/subnets`);
    const subnets = await res.json();

    if (!subnets || subnets.length === 0) {
      grid.innerHTML = `<div style="grid-column: 1/-1; text-align: center; color: var(--text-secondary); padding: 3rem;">No subnets registered. Click "+ Add CIDR Subnet" to begin discovery.</div>`;
      return;
    }

    grid.innerHTML = subnets.map(s => `
      <div class="subnet-card">
        <div class="sub-header">
          <strong style="font-size: 1.1rem;">${escapeHtml(s.label)}</strong>
          <span class="badge badge-info">Active</span>
        </div>
        <div class="sub-cidr">${s.cidr}</div>
        <div class="sub-details">
          <div>Netmask: <code>${s.netmask}</code></div>
          <div>Usable Hosts: <strong>${s.total_hosts}</strong></div>
          <div>Network: <code>${s.network_address}</code></div>
          <div>Broadcast: <code>${s.broadcast_address}</code></div>
        </div>
      </div>
    `).join('');
  } catch (err) {
    grid.innerHTML = `<div style="color: var(--accent-red);">Failed to load subnets: ${err.message}</div>`;
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
