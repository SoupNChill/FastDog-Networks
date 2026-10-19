// Agent connection codes (served only with PORTAL_AGENT_BOOTSTRAP_ENABLED=1). Text is set with textContent only.
import { api, init, message } from './api.js';

const $ = (selector) => document.querySelector(selector);
const host = () => $('#agent-hostname').value.trim().toLowerCase();
const base = () => `/api/hostnames/${encodeURIComponent(host())}`;
const run = (fn) => async (event) => { event?.preventDefault(); try { await fn(); } catch (error) { message(error.message); } };

async function load() {
  const data = await api(`${base()}/bootstraps`);
  const list = $('#agent-list');
  list.replaceChildren();
  $('#agent-empty').hidden = data.bootstraps.length > 0;
  for (const item of data.bootstraps) {
    const entry = document.createElement('li');
    entry.textContent = `${item.created_at}: ${item.state}${item.status ? ` (${item.status})` : ''}, by ${item.issuer_kind}, deployment ${item.deployment_id}`;
    list.append(entry);
  }
}

async function main() {
  await init(true);
  const params = new URLSearchParams(location.search);
  if (params.get('hostname')) $('#agent-hostname').value = params.get('hostname');
  $('#agent-host-form').addEventListener('submit', run(async () => {
    const issued = await api(`${base()}/bootstraps`, 'POST', { origin: $('#agent-origin').value.trim() });
    $('#agent-code-value').textContent = issued.code;
    $('#agent-code-detail').textContent = `Expires ${issued.expires_at}. Deployment ${issued.deployment_id}.`;
    $('#agent-code').hidden = false;
    message('Connection code created.');
    await load();
  }));
  $('#agent-refresh').addEventListener('click', run(load));
  $('#agent-cancel').addEventListener('click', run(async () => {
    await api(`${base()}/bootstraps`, 'DELETE');
    $('#agent-code').hidden = true;
    message('Pending codes cancelled. The connected agent keeps running.');
    await load();
  }));
  $('#agent-confirm-form').addEventListener('submit', run(async () => {
    const id = $('#agent-credential').value.trim();
    await api(`${base()}/bootstraps/candidates/${encodeURIComponent(id)}/confirm`, 'POST', { key_fingerprint: $('#agent-fingerprint').value.trim().toLowerCase() });
    message('Agent confirmed.');
  }));
  $('#agent-revoke').addEventListener('click', run(async () => {
    if (!confirm(`Revoke the agent for ${host()}? The site goes offline until you connect a server again.`)) return;
    await api(`${base()}/revoke-agent`, 'POST', { confirm: true });
    message('Agent revoked.');
    await load();
  }));
}

main().catch((error) => message(error.message));
