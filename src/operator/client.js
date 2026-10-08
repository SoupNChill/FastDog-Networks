const $ = (id) => document.getElementById(id);
let token = '';
let currentAttachHostname = '';
async function api(path, options = {}) {
  if (!token.trim()) throw new Error('Enter the agent token, then load the dashboard.');
  const response = await fetch(path, { ...options, headers: { 'x-fastdog-token': token, ...(options.headers || {}) } });
  const data = await response.json();
  if (response.status === 401) throw new Error('Agent token rejected (401). Check the token and try again.');
  if (!response.ok) throw new Error(data.error || `HTTP ${response.status}`);
  return data;
}
function row(cells) {
  const tr = document.createElement('tr');
  for (const value of cells) { const td = document.createElement('td'); td.textContent = String(value); tr.append(td); }
  return tr;
}
function list(id, values) {
  const ul = $(id); ul.replaceChildren();
  for (const value of values) { const li = document.createElement('li'); li.textContent = value; ul.append(li); }
}
function inviteAvailability(remaining) {
  $('create-zone').disabled = !Number.isSafeInteger(remaining) || remaining < 1;
  $('invite-guidance').textContent = remaining < 1
    ? 'No active invite uses remain. Mint an invite before creating a zone.'
    : `${remaining} active invite use${remaining === 1 ? '' : 's'} available. Enter a valid invite code to create a zone.`;
}
function holdError(error) { return `${error.message} Zone creation did not complete. Registrar NS remains on HOLD.`; }
function metric(label, value) {
  const div = document.createElement('div'); div.className = 'metric';
  const strong = document.createElement('strong'); strong.textContent = String(value);
  div.append(strong, document.createTextNode(label)); return div;
}
function relativeTime(value) {
  const age = Date.now() - Date.parse(value);
  if (!Number.isFinite(age)) return 'unknown';
  if (age < 60000) return `${Math.max(0, Math.floor(age / 1000))}s ago`;
  if (age < 3600000) return `${Math.floor(age / 60000)}m ago`;
  return `${Math.floor(age / 3600000)}h ago`;
}
async function showZone(zone) {
  try {
    const detail = await api(`/_fastdog/dns/zones/${encodeURIComponent(zone)}`);
    $('zone-title').textContent = `Records for ${detail.zone}`;
    $('records').replaceChildren(...(detail.records || []).map((r) => row([r.name, r.type, r.content, r.ttl ?? detail.ttl_default ?? ''])));
  } catch (error) { $('message').textContent = error.message; }
}
async function load() {
  token = $('token').value;
  $('message').textContent = 'Loading…';
  try {
    const [metrics, invites, zones, agents, status, attachedHosts] = await Promise.all([
      api('/_fastdog/operator/metrics'), api('/_fastdog/onboard/invites'),
      api('/_fastdog/dns/zones'), api('/_fastdog/agents'), api('/status.json'),
      api('/_fastdog/onboard/attached-hosts'),
    ]);
    $('metrics').replaceChildren(
      metric('Attached hosts', attachedHosts.hosts.length),
      metric('Active hosts', attachedHosts.hosts.filter((h) => h.status === 'active').length),
      metric('Zones', metrics.zoneCount), metric('Invite uses remaining', metrics.invitesRemaining),
      metric('Unused invites', metrics.unusedInviteCount), metric('Last paid_test', metrics.lastPaidTest || 'none'),
      metric('Edge /health', metrics.edgeHealthOk ? 'OK' : 'DOWN'), metric('Tunnels connected', `${metrics.agentsConnected}/${metrics.agentsRegistered}`),
      metric('Tunnel connected', metrics.tunnelConnected ? 'yes' : 'no'),
      metric('Newest connected last seen', metrics.newestConnectedLastSeen ? `${relativeTime(metrics.newestConnectedLastSeen)} (${metrics.newestConnectedLastSeen})` : 'none'),
    );
    inviteAvailability(metrics.invitesRemaining);
    $('invites').replaceChildren(...invites.map((i) => row([i.created_at, i.remaining_uses, i.expires_at && Date.parse(i.expires_at) <= Date.now() ? 'yes' : 'no', i.expires_at || 'never', i.note || ''])));
    const zoneList = $('zones'); zoneList.replaceChildren();
    for (const zone of zones.zones) {
      const li = document.createElement('li'); const button = document.createElement('button');
      button.type = 'button'; button.textContent = zone; button.addEventListener('click', () => showZone(zone));
      li.append(button); zoneList.append(li);
    }
    list('agents', agents.agents.map((a) => `${a.name} · ${a.hostname} · connected ${a.connected ? 'yes' : 'no'} · registered ${a.registeredAt || 'unknown'} · last seen ${a.lastSeen ? `${relativeTime(a.lastSeen)} (${a.lastSeen})` : 'unknown'} · upstream ${a.localUpstream || 'unknown'}`));
    $('status-summary').textContent = `${status.overall} · checked ${status.lastChecked}`;
    await loadAttachedHosts();
    $('message').textContent = 'Dashboard updated.';
  } catch (error) { inviteAvailability(0); $('message').textContent = error.message; }
}
$('load').addEventListener('click', load);
$('invite-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  $('invite-code').textContent = ''; $('invite-code').style.display = 'none';
  try {
    token = $('token').value;
    const fields = new FormData(event.target);
    const body = { max_uses: Number(fields.get('max_uses')) };
    if (fields.get('expires_in_hours')) body.expires_in_hours = Number(fields.get('expires_in_hours'));
    if (fields.get('note')) body.note = fields.get('note');
    const invite = await api('/_fastdog/onboard/invites', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    $('invite-code').textContent = `Copy this code now: ${invite.code}`;
    $('invite-code').style.display = 'block';
    await load();
  } catch (error) { $('message').textContent = `Invite not minted: ${error.message}`; }
});
$('zone-form').addEventListener('submit', async (event) => {
  event.preventDefault(); token = $('token').value;
  const output = $('zone-created'); output.replaceChildren();
  try {
    const fields = new FormData(event.target);
    const body = { zone: String(fields.get('zone')).trim(), invite_code: String(fields.get('invite_code')).trim() };
    if (!body.invite_code) throw new Error('Invite code required. Mint an invite first.');
    if (fields.get('edge_ip')) body.edge_ip = String(fields.get('edge_ip')).trim();
    const result = await api('/_fastdog/onboard/zones', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const instructions = result.instructions;
    const title = document.createElement('p'); title.textContent = `Created ${result.zone}. Proposed NS: ${instructions.ns.join(', ')}. ${instructions.hold}`;
    const next = document.createElement('p'); next.textContent = 'LAN preview: check SOA and NS directly on both PoPs. DNS publication is separate; CoreDNS auto sync stays off.';
    const checks = document.createElement('ul');
    for (const command of instructions.dig_verify) { const li = document.createElement('li'); li.textContent = command; checks.append(li); }
    const steps = document.createElement('p'); steps.textContent = 'LAN next steps: ' + instructions.next_steps_lan.join(' ');
    output.append(title, next, checks, steps);
    await load(); await showZone(result.zone);
  } catch (error) { output.replaceChildren(); $('message').textContent = holdError(error); }
});
$('run-checklist').addEventListener('click', async () => {
  token = $('token').value; $('checklist-result').textContent = 'Running checklist…';
  try {
    const result = await api('/_fastdog/operator/ns-cut-checklist');
    const panel = $('checklist-result'); panel.replaceChildren();
    const valid = Array.isArray(result.lines) && Array.isArray(result.checks) && result.checks.length > 0 && !result.checks.some((line) => !line.startsWith('PASS')) && !result.error;
    const safe = valid && result.SAFE_TO_FLIP === 'yes' ? 'yes' : 'no';
    const summary = document.createElement('p'); summary.textContent = `SAFE_TO_FLIP=${safe}. Registrar NS remains on HOLD. ${result.error || (!valid ? 'Checklist failed or returned no checks; inspect the server and dig availability.' : result.hold || '')}`;
    const lines = document.createElement('pre'); lines.textContent = Array.isArray(result.lines) ? result.lines.join('\n') || 'No checklist output' : 'No checklist output';
    panel.append(summary, lines);
  } catch (error) { $('checklist-result').textContent = `SAFE_TO_FLIP=no. Registrar NS remains on HOLD. Checklist failed: ${error.message}`; }
});
async function loadAttachedHosts() {
  try {
    const data = await api('/_fastdog/onboard/attached-hosts');
    const tbody = $('attached-hosts'); tbody.replaceChildren();
    for (const host of data.hosts) {
      const tr = document.createElement('tr');
      const status = host.status === 'active' ? 'Active' : host.status === 'verified' ? 'Verified' : 'Pending';
      const cells = [host.hostname, status, host.created_at || '', host.verified_at || ''];
      for (const value of cells) { const td = document.createElement('td'); td.textContent = value; tr.append(td); }
      const actionTd = document.createElement('td');
      const detachBtn = document.createElement('button');
      detachBtn.textContent = 'Detach';
      detachBtn.style.background = '#dc2626';
      detachBtn.addEventListener('click', async () => {
        if (!confirm(`Detach ${host.hostname}? This removes the tunnel binding.`)) return;
        try {
          await api(`/_fastdog/onboard/attached-hosts/${encodeURIComponent(host.hostname)}`, { method: 'DELETE' });
          await loadAttachedHosts();
          $('message').textContent = `Detached ${host.hostname}`;
        } catch (err) { $('message').textContent = err.message; }
      });
      actionTd.append(detachBtn);
      tr.append(actionTd);
      tbody.append(tr);
    }
  } catch (error) { $('message').textContent = error.message; }
}
$('attach-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  token = $('token').value;
  const result = $('attach-result');
  const instructions = $('attach-instructions');
  const verifyResult = $('verify-result');
  result.style.display = 'none'; result.className = '';
  instructions.style.display = 'none';
  verifyResult.style.display = 'none';
  try {
    const fields = new FormData(event.target);
    const hostname = String(fields.get('hostname')).trim();
    if (!hostname) throw new Error('Hostname required');
    const data = await api('/_fastdog/onboard/attach-host', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hostname }) });
    currentAttachHostname = hostname;
    result.textContent = data.status === 'pending' ? `Attached ${hostname} (pending verification)` : `${hostname} already attached (${data.status})`;
    result.style.display = 'block';
    $('cname-record').textContent = `${hostname}.  300  IN  CNAME  ${data.cname_target}.`;
    instructions.style.display = 'block';
    await loadAttachedHosts();
  } catch (error) {
    result.textContent = error.message;
    result.className = 'error';
    result.style.display = 'block';
  }
});
$('copy-cname').addEventListener('click', () => {
  navigator.clipboard.writeText($('cname-record').textContent).then(() => {
    $('copy-cname').textContent = 'Copied!';
    setTimeout(() => { $('copy-cname').textContent = 'Copy'; }, 2000);
  });
});
$('verify-btn').addEventListener('click', async () => {
  token = $('token').value;
  const result = $('verify-result');
  result.style.display = 'none'; result.className = '';
  if (!currentAttachHostname) { result.textContent = 'No hostname attached. Attach a hostname first.'; result.className = 'error'; result.style.display = 'block'; return; }
  try {
    const data = await api('/_fastdog/onboard/verify-host', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ hostname: currentAttachHostname }) });
    if (data.verified) {
      let msg = `Verified! ${currentAttachHostname} is now active.\n\n`;
      if (data.credential) {
        msg += `Agent credential (save now, shown once):\nAGENT_TOKEN=${data.credential.token}\nAGENT_HOSTNAME=${currentAttachHostname}\n\n`;
      }
      if (data.caddy_block) {
        msg += `Caddy block (add to Caddyfile, then reload Caddy):\n${data.caddy_block}`;
      }
      result.textContent = msg;
      result.style.display = 'block';
      await loadAttachedHosts();
    } else {
      result.textContent = `Verification failed: ${data.error}${data.found ? ` (found: ${data.found})` : ''}. Check DNS and try again.`;
      result.className = 'error';
      result.style.display = 'block';
    }
  } catch (error) {
    result.textContent = error.message;
    result.className = 'error';
    result.style.display = 'block';
  }
});


async function loadVerdict(token) {
  const status = document.getElementById('verdict-status');
  const metricsEl = document.getElementById('verdict-metrics');
  const hostsEl = document.getElementById('verdict-hosts');
  const reasonsEl = document.getElementById('verdict-reasons');
  const recentEl = document.getElementById('verdict-recent');
  if (!status) return;
  const headers = { 'x-fastdog-token': token };
  try {
    const [metrics, hosts, recent] = await Promise.all([
      fetch('/_fastdog/verdict/metrics', { headers }).then(r => r.json()),
      fetch('/_fastdog/verdict/hosts', { headers }).then(r => r.json()),
      fetch('/_fastdog/verdict/recent', { headers }).then(r => r.json()),
    ]);
    if (metrics.error) throw new Error(metrics.error);
    status.textContent = 'Edge Verdict metrics loaded.';
    const actions = metrics.actions || {};
    metricsEl.innerHTML = ['allow','challenge','block'].map(k =>
      `<div class="metric"><strong>${actions[k] ?? '—'}</strong>${k}</div>`).join('');
    const lat = metrics.endpoints?.['/v1/edge-auth']?.latency_ms;
    if (lat) metricsEl.innerHTML += `<div class="metric"><strong>${lat.p50 ?? '—'} / ${lat.p99 ?? '—'}</strong>edge-auth p50/p99 ms</div>`;
    hostsEl.innerHTML = (hosts.hosts || []).map(h =>
      `<tr><td>${h.host}</td><td>${h.mode}</td><td>${h.fail}</td><td>${h.enable}</td></tr>`).join('') || '<tr><td colspan="4">No hosts configured</td></tr>';
    // reasons from shadow if available
    reasonsEl.innerHTML = '<li>See shadow summary endpoint for live would-be reasons.</li>';
    recentEl.innerHTML = (recent.recent || []).slice(0, 15).map(r =>
      `<tr><td>${r.ts || ''}</td><td>${r.action}</td><td>${r.reason || ''}</td><td><code>${r.path || ''}</code></td></tr>`).join('') || '<tr><td colspan="4">None yet</td></tr>';
  } catch (e) {
    status.textContent = 'Verdict unavailable: ' + e.message;
  }
}


document.getElementById('load')?.addEventListener('click', () => {
  const t = document.getElementById('token')?.value || '';
  loadVerdict(t);
});
