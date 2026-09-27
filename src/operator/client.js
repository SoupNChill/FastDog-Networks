const $ = (id) => document.getElementById(id);
let token = '';
async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { 'x-fastdog-token': token, ...(options.headers || {}) } });
  const data = await response.json();
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
    const [metrics, invites, zones, agents, status] = await Promise.all([
      api('/_fastdog/operator/metrics'), api('/_fastdog/onboard/invites'),
      api('/_fastdog/dns/zones'), api('/_fastdog/agents'), api('/status.json'),
    ]);
    $('metrics').replaceChildren(
      metric('Zones', metrics.zoneCount), metric('Invite uses remaining', metrics.invitesRemaining),
      metric('Unused invites', metrics.unusedInviteCount), metric('Last paid_test', metrics.lastPaidTest || 'none'),
      metric('Edge /health', metrics.edgeHealthOk ? 'OK' : 'DOWN'), metric('Tunnels connected', `${metrics.agentsConnected}/${metrics.agentsRegistered}`),
      metric('Tunnel connected', metrics.tunnelConnected ? 'yes' : 'no'),
      metric('Newest connected last seen', metrics.newestConnectedLastSeen ? `${relativeTime(metrics.newestConnectedLastSeen)} (${metrics.newestConnectedLastSeen})` : 'none'),
    );
    $('invites').replaceChildren(...invites.map((i) => row([i.created_at, i.remaining_uses, i.expires_at && Date.parse(i.expires_at) <= Date.now() ? 'yes' : 'no', i.expires_at || 'never', i.note || ''])));
    const zoneList = $('zones'); zoneList.replaceChildren();
    for (const zone of zones.zones) {
      const li = document.createElement('li'); const button = document.createElement('button');
      button.type = 'button'; button.textContent = zone; button.addEventListener('click', () => showZone(zone));
      li.append(button); zoneList.append(li);
    }
    list('agents', agents.agents.map((a) => `${a.name} · ${a.hostname} · connected ${a.connected ? 'yes' : 'no'} · registered ${a.registeredAt || 'unknown'} · last seen ${a.lastSeen ? `${relativeTime(a.lastSeen)} (${a.lastSeen})` : 'unknown'} · upstream ${a.localUpstream || 'unknown'}`));
    $('status-summary').textContent = `${status.overall} · checked ${status.lastChecked}`;
    $('message').textContent = 'Dashboard updated.';
  } catch (error) { $('message').textContent = error.message; }
}
$('load').addEventListener('click', load);
$('invite-form').addEventListener('submit', async (event) => {
  event.preventDefault();
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
  } catch (error) { $('message').textContent = error.message; }
});
$('zone-form').addEventListener('submit', async (event) => {
  event.preventDefault(); token = $('token').value;
  try {
    const fields = new FormData(event.target);
    const body = { zone: String(fields.get('zone')).trim(), invite_code: String(fields.get('invite_code')).trim() };
    if (fields.get('edge_ip')) body.edge_ip = String(fields.get('edge_ip')).trim();
    const result = await api('/_fastdog/onboard/zones', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });
    const output = $('zone-created'); output.replaceChildren();
    const title = document.createElement('p'); title.textContent = `Created ${result.zone}. NS: ${result.ns.join(', ')}. ${result.hold}`;
    const next = document.createElement('p'); next.textContent = 'Next: verify DNS on both servers, then issue an agent credential and map a hostname through the onboard API. Keep registrar NS on HOLD.';
    const checks = document.createElement('ul');
    for (const command of result.instructions.dig_verify) { const li = document.createElement('li'); li.textContent = command; checks.append(li); }
    output.append(title, next, checks);
    await load(); await showZone(result.zone);
  } catch (error) { $('message').textContent = error.message; }
});
$('run-checklist').addEventListener('click', async () => {
  token = $('token').value; $('checklist-result').textContent = 'Running checklist…';
  try {
    const result = await api('/_fastdog/operator/ns-cut-checklist');
    const panel = $('checklist-result'); panel.replaceChildren();
    const summary = document.createElement('p'); summary.textContent = `SAFE_TO_FLIP=${result.SAFE_TO_FLIP}. ${result.hold}`;
    const lines = document.createElement('pre'); lines.textContent = result.lines.join('\n') || result.error || 'No output';
    panel.append(summary, lines);
  } catch (error) { $('checklist-result').textContent = error.message; }
});
