import { api, init, message } from './api.js';

const reasonText = {
  agent_disconnected: 'Your server isn’t connected to FastDog right now. Check that the connection software is running.',
  origin_unreachable: 'Your server is connected, but the app on it isn’t answering. Check that your app is running.',
  certificate_missing: 'No HTTPS certificate is being served yet. It is issued automatically on the first visit.',
  certificate_invalid: 'The HTTPS certificate isn’t valid for this address yet.',
  certificate_expired: 'The HTTPS certificate has expired.',
};
const when = (iso) => {
  const time = Date.parse(iso);
  return Number.isFinite(time) ? new Date(time).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : 'unknown';
};
const daysLeft = (iso) => Math.floor((Date.parse(iso) - Date.now()) / 86400000);
const set = (id, text) => { document.querySelector(id).textContent = text; };

// Bars are plain elements sized through the CSSOM (allowed by the page's CSP; no inline style attributes).
export function sparkline(hourly) {
  const chart = document.createElement('div');
  chart.className = 'bars';
  chart.setAttribute('aria-hidden', 'true');
  const max = Math.max(1, ...hourly);
  hourly.forEach((count, index) => {
    const bar = document.createElement('span');
    bar.className = count ? 'bar' : 'bar zero';
    bar.style.height = `${count ? Math.max(5, Math.round((count / max) * 100)) : 3}%`;
    bar.title = `${count} request${count === 1 ? '' : 's'}, ${23 - index === 0 ? 'this hour' : `${23 - index}h ago`}`;
    chart.append(bar);
  });
  return chart;
}

export function describe(status) {
  const agent = status.agent || {};
  const out = {};
  out.live = status.live ? 'Live' : 'Not live';
  out.reason = status.live ? 'Visitors can reach your website over HTTPS.' : (reasonText[status.reasons?.[0]] || 'Something isn’t ready yet.');
  out.agent = agent.connected ? `Connected${agent.agent_version ? ` (version ${agent.agent_version})` : ''}` : 'Not connected';
  if (agent.origin_reachable === true) out.origin = 'Answering';
  else if (agent.origin_reachable === false) out.origin = 'Not answering';
  else out.origin = agent.connected ? 'Not reported. Update the connection software to get this check.' : 'Unknown until your server connects';
  const cert = status.cert;
  if (!cert) out.cert = 'Not issued yet';
  else if (!cert.valid) out.cert = 'Not valid for this address';
  else if (cert.expires_at) {
    const days = daysLeft(cert.expires_at);
    out.cert = `Valid, expires ${when(cert.expires_at)} (${days} day${days === 1 ? '' : 's'}). Renews automatically.`;
  } else out.cert = 'Valid';
  const traffic = status.traffic || {};
  out.total = traffic.available ? `${traffic.total.toLocaleString()} request${traffic.total === 1 ? '' : 's'}` : 'Not available yet';
  out.p50 = traffic.available && traffic.p50_ms !== null && traffic.p50_ms !== undefined ? `${traffic.p50_ms} ms` : '—';
  const verdict = status.verdict || {};
  if (!verdict.available) out.verdict = 'Bot check counts aren’t available for this website yet.';
  else if (!verdict.scored) out.verdict = 'No visits scored in the last 24 hours.';
  else out.verdict = `${verdict.scored} visits scored: ${verdict.would_block} would have been blocked and ${verdict.would_challenge} challenged.`;
  return out;
}

function render(status) {
  const text = describe(status);
  document.querySelector('#live-card').dataset.live = status.live ? 'yes' : 'no';
  set('#live-state', text.live);
  set('#live-reason', text.reason);
  set('#checked', `Last checked ${when(status.checked_at)}`);
  set('#agent-state', text.agent);
  set('#origin-state', text.origin);
  set('#cert-state', text.cert);
  set('#p50', text.p50);
  set('#traffic-total', text.total);
  const spark = document.querySelector('#sparkline');
  spark.replaceChildren();
  if (status.traffic?.available) spark.append(sparkline(status.traffic.hourly));
  set('#verdict-state', text.verdict);
}

function renderTest(result) {
  const box = document.querySelector('#test-result');
  const list = document.createElement('dl');
  const rows = [
    ['Result', result.ok ? 'Your website answered' : result.error === 'timeout' ? 'No answer within 4 seconds' : result.status ? 'Your website returned an error' : 'Could not reach your website'],
    ['Status', result.status ? String(result.status) : '—'],
    ['Time', result.ms !== null && result.ms !== undefined ? `${result.ms} ms` : '—'],
    ['Certificate', result.cert ? `${result.cert.valid ? 'Valid' : 'Not valid'}${result.cert.expires_at ? `, expires ${when(result.cert.expires_at)}` : ''}${result.cert.issuer ? ` (${result.cert.issuer})` : ''}` : '—'],
    ['Tested', when(result.tested_at)],
  ];
  for (const [label, value] of rows) {
    const dt = document.createElement('dt'); dt.textContent = label;
    const dd = document.createElement('dd'); dd.textContent = value;
    list.append(dt, dd);
  }
  box.replaceChildren(list);
}

let timer;
async function load(hostname) {
  clearTimeout(timer);
  try {
    render(await api(`/api/hostnames/${encodeURIComponent(hostname)}/status`));
    message('');
  } catch (error) { message(error.message); }
  timer = setTimeout(() => load(hostname), 30000);
}

if (typeof document !== 'undefined' && document.querySelector('#status')) {
  try {
    await init(true);
    const { hostnames } = await api('/api/hostnames');
    const active = hostnames.filter((record) => record.status === 'active');
    const select = document.querySelector('#hostname');
    const wanted = new URLSearchParams(location.search).get('hostname');
    for (const record of active) {
      const option = document.createElement('option');
      option.value = record.hostname;
      option.textContent = record.hostname;
      option.selected = record.hostname === wanted;
      select.append(option);
    }
    document.querySelector('#status-empty').hidden = active.length > 0;
    document.querySelector('#status-picker').hidden = active.length < 2;
    document.querySelector('#status').hidden = active.length === 0;
    if (select.value) load(select.value);
    select.addEventListener('change', () => { document.querySelector('#test-result').replaceChildren(); load(select.value); });
    const test = document.querySelector('#test-site');
    test.addEventListener('click', async () => {
      test.disabled = true;
      test.setAttribute('aria-busy', 'true');
      try { renderTest(await api(`/api/hostnames/${encodeURIComponent(select.value)}/test`, 'POST')); }
      catch (error) { message(error.message); }
      finally { test.disabled = false; test.removeAttribute('aria-busy'); }
    });
  } catch (error) { message(error.message); }
}
