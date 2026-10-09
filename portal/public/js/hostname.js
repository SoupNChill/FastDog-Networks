import { api, init, form, button, copy, message } from './api.js';
import { showCredential, watchAgent } from './agent-view.js';
let poll;
let stopAgent;
function showDns(record) {
  const panel = document.querySelector('#dns');
  panel.replaceChildren();
  for (const value of [record.dns?.cname, record.dns?.txt].filter(Boolean)) {
    const text = `${value.name}  ${value.ttl}  ${value.type}  ${value.value}`;
    const code = document.createElement('pre');
    code.textContent = text;
    panel.append(code, button(`Copy ${value.type} record`, () => copy(text)));
  }
  if (record.dns?.apex_note) {
    const note = document.createElement('p');
    note.textContent = record.dns.apex_note;
    panel.append(note);
  }
  document.querySelector('#claim').hidden = false;
  document.querySelector('#claim-hostname').textContent = record.hostname;
  const path = `/api/hostnames/${encodeURIComponent(record.hostname)}`;
  const deadline = Date.now() + 600000;
  clearTimeout(poll);
  const verify = async () => {
    clearTimeout(poll);
    const result = await api(`${path}/verify`, 'POST');
    if (result.verified) {
      message('DNS verified. Connect your origin below.');
      if (result.credential) showCredential(result.credential);
      stopAgent?.();
      stopAgent = watchAgent(record.hostname);
      await list();
      return;
    }
    const details = Object.entries(result.checks || {}).map(([name, check]) => {
      if (check.ok) return `${name}: ready`;
      return `${name}: ${String(check.error || 'waiting').replaceAll('_', ' ')}${check.found ? `; found ${check.found}` : ''}${check.expected ? `; expected ${check.expected}` : ''}${check.expected_name ? `; check ${check.expected_name}` : ''}`;
    });
    message(`Waiting for DNS. ${details.join('. ')}`);
    if (Date.now() < deadline) poll = setTimeout(() => verify().catch((error) => message(error.message)), 30000);
  };
  document.querySelector('#verify-actions').replaceChildren(button('Verify DNS', verify));
  poll = setTimeout(() => verify().catch((error) => message(error.message)), 30000);
}
async function list() {
  const { hostnames } = await api('/api/hostnames');
  const container = document.querySelector('#hostnames');
  container.replaceChildren();
  for (const record of hostnames) {
    const row = document.createElement('article');
    const label = document.createElement('p');
    label.textContent = `${record.hostname} — ${record.status}`;
    row.append(label);
    if (record.status === 'pending') row.append(button('Show DNS records', () => showDns(record)));
    else {
      const connect = document.createElement('a');
      connect.textContent = 'Connect origin';
      connect.href = `/connect?hostname=${encodeURIComponent(record.hostname)}`;
      row.append(connect);
    }
    row.append(button('Detach hostname', async () => {
      await api(`/api/hostnames/${encodeURIComponent(record.hostname)}`, 'DELETE');
      clearTimeout(poll);
      stopAgent?.();
      document.querySelector('#credential').hidden = true;
      document.querySelector('#command').textContent = '';
      document.querySelector('#claim').hidden = true;
      message('Hostname detached. Remove its DNS records at your DNS provider.');
      await list();
    }));
    container.append(row);
  }
  if (!hostnames.length) container.textContent = 'No hostnames yet.';
}
try {
  const me = await init(true);
  if (!me.email_verified) message('Verify your email before adding a hostname. Use the link sent after signup.');
  form('#add-hostname', async (data) => {
    const record = await api('/api/hostnames', 'POST', data);
    showDns(record);
    message('Add both records at your DNS provider. We will recheck every 30 seconds for ten minutes.');
    await list();
  });
  await list();
} catch (error) { message(error.message); }
window.addEventListener('pagehide', () => clearTimeout(poll));
