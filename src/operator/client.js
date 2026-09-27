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
    );
    $('invites').replaceChildren(...invites.map((i) => row([i.created_at, i.remaining_uses, i.expires_at && Date.parse(i.expires_at) <= Date.now() ? 'yes' : 'no', i.expires_at || 'never', i.note || ''])));
    list('zones', zones.zones);
    list('agents', agents.agents.map((a) => `${a.name} · ${a.hostname} · ${a.connected ? 'connected' : 'disconnected'}`));
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
