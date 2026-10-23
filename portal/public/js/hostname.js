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
      "This hostname is reserved (for example, a name under FastDog's own domain). Use a hostname on a domain you control.": "This address can't be used. It's reserved or already connected to another account.",
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
function showNextStep(hostname) {
  const next = document.querySelector('#next-step');
  if (!next) return;
  next.href = `/connect?hostname=${encodeURIComponent(hostname)}`;
  next.hidden = false;
}
function displayCredential(credential) {
  showCredential(credential);
  const control = document.querySelector('#copy-command');
  control.textContent = 'Copy command';
  control.onclick = () => copyFeedback(document.querySelector('#command').textContent, control, document.querySelector('#command'));
}
function guide(record, agent) { renderGuide(document.querySelector('#getting-started'), record, agent); }
const TWO_PART = ['co.uk', 'org.uk', 'me.uk', 'com.au', 'net.au', 'org.au', 'co.nz', 'co.jp', 'co.in', 'com.br', 'co.za'];
// The zone a provider form usually appends; a guess for display only.
export function zoneOf(hostname) {
  const labels = hostname.split('.');
  return labels.slice(TWO_PART.includes(labels.slice(-2).join('.')) ? -3 : -2).join('.');
}
export function relativeName(name, zone) { return name === zone ? '@' : name.endsWith(`.${zone}`) ? name.slice(0, -zone.length - 1) : name; }
export const PROVIDERS = [
  ['cloudflare', 'Cloudflare'], ['namecheap', 'Namecheap'], ['godaddy', 'GoDaddy'], ['route53', 'Route 53'], ['porkbun', 'Porkbun'], ['other', 'Other'],
];
// Field labels and values as each provider's "add record" form shows them.
export function providerFields(provider, record, zone) {
  const rel = relativeName(record.name, zone);
  const cname = record.type === 'CNAME';
  switch (provider) {
    case 'cloudflare': return [['Type', record.type], ['Name', rel], [cname ? 'Target' : 'Content', record.value], ...(cname ? [['Proxy status', 'DNS only (grey cloud)']] : []), ['TTL', 'Auto']];
    case 'namecheap': return [['Type', `${record.type} Record`], ['Host', rel], ['Value', record.value], ['TTL', 'Automatic']];
    case 'godaddy': return [['Type', record.type], ['Name', rel], ['Value', record.value], ['TTL', 'Default']];
    case 'route53': return [['Record name', rel === '@' ? '(leave blank)' : rel], ['Record type', record.type], ['Value', record.value], ['TTL (seconds)', String(record.ttl)], ['Routing policy', 'Simple routing']];
    case 'porkbun': return [['Type', record.type], ['Host', rel === '@' ? '(leave blank)' : rel], ['Answer', record.value], ['TTL', '600']];
    default: return [['Type', record.type], ['Name', record.name], ['Value', record.value], ['TTL', String(record.ttl)]];
  }
}
const providerNotes = {
  cloudflare: 'Cloudflare adds your domain to the Name automatically. Set Proxy status to DNS only (grey cloud), not Proxied. Grey cloud means Cloudflare only answers DNS and visitors go straight to FastDog; orange cloud puts Cloudflare in the middle, which hides your record from our check and stops your HTTPS certificate.',
  namecheap: 'Find these under Domain List, Manage, Advanced DNS. Namecheap adds your domain to the Host automatically.',
  godaddy: 'Find these under My Products, DNS. GoDaddy adds your domain to the Name automatically.',
  route53: 'Open your hosted zone and choose Create record. Route 53 adds your domain to the Record name automatically.',
  porkbun: 'Open Domain Management, then DNS. Porkbun adds your domain to the Host automatically.',
  other: 'Use the full names below. If your provider adds your domain automatically, enter only the part before it.',
};
function showDns(record) {
  selected = record.hostname;
  guide(record);
  const panel = document.querySelector('#dns');
  const records = [record.dns?.cname, record.dns?.txt].filter(Boolean);
  const zone = zoneOf(record.hostname);
  const note = document.createElement('p');
  note.className = 'dns-cloudflare-note';
  note.textContent = 'If your DNS is on Cloudflare, set Proxy status to DNS only (grey cloud). Grey cloud means Cloudflare just answers DNS; it doesn’t sit between your visitors and FastDog.';
  const tabs = document.createElement('div');
  tabs.className = 'provider-tabs';
  tabs.setAttribute('role', 'tablist');
  tabs.setAttribute('aria-label', 'Your DNS provider');
  const body = document.createElement('div');
  body.id = 'provider-panel';
  body.setAttribute('role', 'tabpanel');
  body.tabIndex = 0;
  const render = (provider) => {
    const help = document.createElement('p');
    help.className = 'hostname-note';
    help.textContent = providerNotes[provider];
    const blocks = records.map((value) => {
      const block = document.createElement('div');
      block.className = 'dns-record';
      const title = document.createElement('h3');
      title.textContent = value.type === 'CNAME' ? 'Record 1: points your address at FastDog' : 'Record 2: proves you own the domain';
      const why = document.createElement('p');
      why.className = 'why';
      why.textContent = value.type === 'CNAME'
        ? 'Why: visitors who type your address are sent to FastDog, which serves HTTPS and passes each request to your server.'
        : 'Why: only someone who controls your domain’s DNS can add this value, so only you can connect this address.';
      const list = document.createElement('dl');
      for (const [label, text] of providerFields(provider, value, zone)) {
        const term = document.createElement('dt');
        term.textContent = label;
        const detail = document.createElement('dd');
        const code = document.createElement('code');
        code.textContent = text;
        detail.append(code);
        if (text === value.value || text === relativeName(value.name, zone) || text === value.name) {
          const control = button(`Copy ${label}`, () => copyFeedback(text, control, code));
          detail.append(control);
        }
        list.append(term, detail);
      }
      block.append(title, why, list);
      return block;
    });
    body.replaceChildren(help, ...blocks);
  };
  const buttons = PROVIDERS.map(([id, label], index) => {
    const tab = document.createElement('button');
    tab.type = 'button';
    tab.id = `provider-tab-${id}`;
    tab.textContent = label;
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-controls', 'provider-panel');
    return tab;
  });
  const activate = (index, focus = false) => {
    buttons.forEach((tab, i) => { tab.setAttribute('aria-selected', String(i === index)); tab.tabIndex = i === index ? 0 : -1; });
    body.setAttribute('aria-labelledby', buttons[index].id);
    render(PROVIDERS[index][0]);
    if (focus) buttons[index].focus?.();
  };
  buttons.forEach((tab, index) => {
    tab.addEventListener('click', () => activate(index));
    tab.addEventListener('keydown', (event) => {
      const next = { ArrowRight: (index + 1) % buttons.length, ArrowLeft: (index + buttons.length - 1) % buttons.length, Home: 0, End: buttons.length - 1 }[event.key];
      if (next !== undefined) { event.preventDefault(); activate(next, true); }
    });
  });
  tabs.append(...buttons);
  const zoneFile = document.createElement('details');
  const summary = document.createElement('summary');
  summary.textContent = 'Zone file format (advanced)';
  const pre = document.createElement('pre');
  pre.tabIndex = 0;
  pre.textContent = records.map((value) => `${value.name}. ${value.ttl} IN ${value.type} ${value.type === 'TXT' ? `"${value.value}"` : `${value.value}.`}`).join('\n');
  zoneFile.append(summary, pre);
  panel.replaceChildren(note, tabs, body, zoneFile);
  activate(0);
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
      message('Your DNS records are ready. Next, connect your server on the Server page.');
      showNextStep(record.hostname);
      await list();
      return;
    }
    const corrections = [];
    if (result.checks?.routing?.error === 'cname_wrong_target' || result.checks?.routing?.error === 'a_wrong_target') corrections.push('The address points somewhere else. Compare its value with the routing record above.');
    if (result.checks?.routing?.error === 'dns_proxied') corrections.push('Your record is proxied by Cloudflare (orange cloud). Set Proxy status to DNS only (grey cloud), then check again.');
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
