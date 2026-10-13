import { api as request, init, form, button, message } from './api.js';
import { showCredential } from './agent-view.js';
import { renderGuide } from './guide.js';
let poll;
let agentPoll;
let selected;
let generation = 0;
let agentGeneration = 0;
let emailVerified = false;
const pending = "We haven't seen your records yet. DNS changes can take a few minutes to spread. We check automatically; you can also press Check again.";
const waiting = 'Waiting for your server to connect. Go to Connect your server.';
const live = 'Live. HTTPS certificate is issued automatically on first visit.';

export function prepareHostname(input) {
  let hostname = input.trim().replace(/^https?:\/\//i, '').split(/[/?#]/, 1)[0].replace(/\.$/, '').toLowerCase();
  const invalid = (text) => { throw new Error(text); };
  if (!hostname) invalid('Enter your website address, such as app.example.com.');
  if (/\s/u.test(hostname)) invalid('Remove the spaces inside your website address.');
  if (/[\x00-\x1f\x7f*:/\\@%]/u.test(hostname)) invalid('Use a domain name without a port, wildcard or special characters.');
  if (!hostname.includes('.')) invalid('Enter a full address with a dot, such as app.example.com.');
  // Convert international domain names using the browser URL implementation.
  try { hostname = new URL(`https:${'//'}${hostname}`).hostname; } catch { invalid('Check the address for missing parts or unsupported characters.'); }
  const labels = hostname.split('.');
  if (hostname.length > 253 || labels.some((label) => label.length > 63)) invalid('This address is too long. Use at most 253 characters, with at most 63 between dots.');
  if (labels.some((label) => !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
    || !/^(?:[a-z]{2,63}|xn--[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)$/.test(labels.at(-1))) invalid('Use a domain name with valid endings, such as app.example.com. Each part must start and end with a letter or number.');
  return { hostname, changed: hostname !== input };
}

// A helpful hint, not public-suffix validation or a restriction on registration.
export function rootDomainHelp(hostname, target) {
  const labels = hostname.toLowerCase().split('.');
  const suffixes = ['co.uk', 'org.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.in', 'com.br', 'co.za'];
  const root = labels.length === (suffixes.includes(labels.slice(-2).join('.')) ? 3 : 2);
  if (!root) return '';
  return `This is a root domain. Most DNS providers can't put a CNAME on the root. Recommended: use www.${hostname} instead and redirect the root to it at your DNS provider. Or, if your provider supports ALIAS/ANAME/CNAME flattening on the root, point it at ${target || 'the attach target in the DNS records shown after you add the address'}.`;
}
function updateRootHelp(hostname, target) {
  const note = document.querySelector('#root-domain-help');
  note.textContent = rootDomainHelp(hostname, target);
  note.hidden = !note.textContent;
}

async function api(...args) {
  try { return await request(...args); }
  catch (error) {
    const replacements = {
      'This hostname is reserved. Choose another name.': "This address can't be used. It's reserved or already connected to another account.",
      'This hostname is unavailable.': "This address can't be used. It's reserved or already connected to another account.",
      'Please sign in, verify your email, or check the details and try again.': emailVerified ? 'Your session may have ended. Sign in again to continue.' : 'Open the verification link in your email, then reload this page.',
      'Your plan’s hostname limit has been reached.': 'Your plan has no room for another website address. Remove an unused address or contact support.',
      'Please wait before trying again.': 'Too many checks in a short time. Wait a minute, then try again.',
    };
    throw new Error(replacements[error.message] || error.message);
  }
}

export async function copyFeedback(text, control, output) {
  try {
    await navigator.clipboard.writeText(text);
    control.textContent = 'Copied';
    message('Copied.');
  } catch {
    output.focus();
    const range = document.createRange();
    range.selectNodeContents(output);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    message('Automatic copy is unavailable. The text is selected. Use your device’s Copy action.');
  }
}
function displayCredential(credential) {
  showCredential(credential);
  const control = document.querySelector('#copy-command');
  control.textContent = 'Copy command';
  control.onclick = () => copyFeedback(document.querySelector('#command').textContent, control, document.querySelector('#command'));
}
function guide(record, agent) { renderGuide(document.querySelector('#getting-started'), record, agent); }
function showDns(record) {
  selected = record.hostname;
  guide(record);
  const panel = document.querySelector('#dns');
  panel.replaceChildren();
  for (const value of [record.dns?.cname, record.dns?.txt].filter(Boolean)) {
    const text = `Type: ${value.type}\nName: ${value.name}\nValue: ${value.value}\nTTL (cache time in seconds): ${value.ttl}`;
    const code = document.createElement('pre');
    code.tabIndex = 0;
    code.textContent = text;
    const control = button(`Copy ${value.type} record`, () => copyFeedback(text, control, code));
    panel.append(code, control);
  }
  updateRootHelp(record.hostname, record.dns?.cname?.value);
  if (!record.dns) {
    const note = document.createElement('p');
    note.textContent = 'Keep the original two DNS records in place. If you no longer have them, contact support before making changes.';
    panel.append(note);
  }
  document.querySelector('#claim').hidden = false;
  document.querySelector('#claim-hostname').textContent = record.hostname;
  const path = `/api/hostnames/${encodeURIComponent(record.hostname)}`;
  const deadline = Date.now() + 600000;
  const current = ++generation;
  clearTimeout(poll);
  const verify = async () => {
    clearTimeout(poll);
    const result = await api(`${path}/verify`, 'POST');
    if (current !== generation) return;
    if (result.verified) {
      document.querySelector('#claim').hidden = true;
      message('Your DNS records are ready. Next, connect your server.');
      if (result.credential) displayCredential(result.credential);
      await list();
      return;
    }
    const corrections = [];
    if (result.checks?.routing?.error === 'cname_wrong_target' || result.checks?.routing?.error === 'a_wrong_target') corrections.push('The address points somewhere else. Compare its value with the routing record above.');
    if (result.checks?.ownership?.error === 'txt_mismatch') corrections.push('The TXT value does not match. Copy the value above into your DNS settings.');
    message(`${pending} ${corrections.join(' ')}`.trim());
    if (Date.now() < deadline) poll = setTimeout(check, 30000);
    else message('Automatic checks have paused after ten minutes. DNS changes can take a few hours. Press Check again when you are ready.');
  };
  const check = () => verify().catch((error) => message(error.message));
  document.querySelector('#verify-actions').replaceChildren(button('Check again', verify));
  message(pending);
  poll = setTimeout(check, 30000);
}
async function list() {
  const currentAgent = ++agentGeneration;
  clearTimeout(agentPoll);
  const { hostnames } = await api('/api/hostnames');
  const container = document.querySelector('#hostnames');
  container.replaceChildren();
  const chosen = hostnames.find((record) => record.hostname === selected) || hostnames[0];
  selected = chosen?.hostname;
  guide(chosen);
  const refreshers = [];
  for (const record of hostnames) {
    const row = document.createElement('article');
    const heading = document.createElement('h3');
    heading.textContent = record.hostname;
    const status = document.createElement('p');
    status.textContent = record.status === 'pending' ? pending : record.status === 'active' ? waiting : 'This address is paused. Check the DNS records, then check again to reconnect it.';
    row.append(heading, status);
    if (record.status !== 'active') row.append(button('Show DNS records', async () => {
      const details = await api(`/api/hostnames/${encodeURIComponent(record.hostname)}`);
      showDns(details);
    }));
    else {
      const connect = document.createElement('a');
      connect.textContent = 'Connect your server';
      connect.href = `/connect?hostname=${encodeURIComponent(record.hostname)}`;
      const visit = document.createElement('a');
      visit.textContent = 'Visit your website to check HTTPS';
      visit.href = `https:${'//'}${record.hostname}/`;
      visit.target = '_blank';
      visit.rel = 'noopener noreferrer';
      visit.hidden = true;
      row.append(connect, visit);
      refreshers.push(async () => {
        try {
          const agent = await api(`/api/hostnames/${encodeURIComponent(record.hostname)}/agent`);
          status.textContent = agent.connected ? live : waiting;
          visit.hidden = !agent.connected;
          if (currentAgent === agentGeneration && selected === record.hostname) guide(record, agent);
        } catch (error) { status.textContent = `We could not check your server connection. ${error.message}`; }
      });
    }
    row.append(button('Remove website address', async () => {
      await api(`/api/hostnames/${encodeURIComponent(record.hostname)}`, 'DELETE');
      ++generation;
      clearTimeout(poll);
      document.querySelector('#credential').hidden = true;
      document.querySelector('#command').textContent = '';
      document.querySelector('#claim').hidden = true;
      message('Website address removed. You can now remove its two DNS records at your domain provider.');
      await list();
    }));
    container.append(row);
  }
  if (!hostnames.length) container.textContent = 'No website addresses yet. Add your first address above to get started.';
  const refresh = async () => {
    await Promise.all(refreshers.map((fn) => fn()));
    if (currentAgent === agentGeneration && refreshers.length) agentPoll = setTimeout(refresh, 10000);
  };
  await refresh();
  if (chosen?.status === 'pending' && document.querySelector('#claim').hidden) {
    const details = await api(`/api/hostnames/${encodeURIComponent(chosen.hostname)}`);
    showDns(details);
  }
}
document.querySelector('#hostname').addEventListener('input', (event) => {
  try { updateRootHelp(prepareHostname(event.target.value).hostname); }
  catch { updateRootHelp(''); }
});
try {
  const me = await init(true);
  emailVerified = me.email_verified;
  if (!emailVerified) message('Open the verification link in your email before adding an address. Then reload this page.');
  form('#add-hostname', async (data) => {
    const input = document.querySelector('#hostname');
    let prepared;
    try { prepared = prepareHostname(data.hostname); input.removeAttribute('aria-invalid'); }
    catch (error) { input.setAttribute('aria-invalid', 'true'); input.focus(); throw error; }
    input.value = prepared.hostname;
    document.querySelector('#hostname-note').textContent = prepared.changed ? `We cleaned up your entry. Using ${prepared.hostname}. Only the website address is needed.` : 'Using this website address. Keep its DNS records in place after setup.';
    const record = await api('/api/hostnames', 'POST', { hostname: prepared.hostname });
    showDns(record);
    await list();
  });
  await list();
} catch (error) { message(error.message); }
window.addEventListener('pagehide', () => { ++generation; ++agentGeneration; clearTimeout(poll); clearTimeout(agentPoll); });
