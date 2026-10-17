import { api, button, copy, message } from './api.js';
const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
const powershellQuote = (value) => `'${String(value).replace(/'/g, "''")}'`;
const AGENT_IMAGE = 'ghcr.io/soupnchill/fastdog-agent:0.1.2@sha256:6dcc855e5dcc5c058326d961133186b30cfa158a0173facd50d5e4e00cefd726';
const LOCAL = (port) => `http:${'//'}127.0.0.1:${port}`;
const PRIVATE_V4 = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;
// URL.hostname has already canonicalised numeric addresses (including mapped IPv4).
function blockedOriginHost(host) {
  if (!host.includes(':')) {
    const octets = host.split('.').map(Number);
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n))) return false;
    const ip = octets.reduce((value, n) => value * 256 + n, 0);
    // 0.0.0.0, 169.254.0.0/16 and 100.64.0.0/10.
    return ip === 0 || Math.floor(ip / 65536) === 0xa9fe || Math.floor(ip / 4194304) === 0x191;
  }
  const halves = host.split('::').map((part) => part ? part.split(':') : []);
  const words = halves.length === 2 ? [...halves[0], ...Array(8 - halves[0].length - halves[1].length).fill('0'), ...halves[1]] : halves[0];
  const ip = words.reduce((value, word) => (value << 16n) + BigInt(`0x${word}`), 0n);
  return ip >> 118n === 0x3fan // fe80::/10
    || ip >> 96n === 0xfd000ec2n // fd00:ec2::/32
    || ip >> 32n === 0x64ff9b0000000000000000n // 64:ff9b::/96
    || (ip >> 32n === 0xffffn && blockedOriginHost([24n, 16n, 8n, 0n].map((shift) => Number((ip >> shift) & 255n)).join('.')));
}
export const LINK_LOCAL_ERROR = "Link-local and restricted addresses (169.254.0.0/16, fe80::/10, fd00:ec2::/32, 64:ff9b::/96, 100.64.0.0/10, 0.0.0.0, including IPv4-mapped forms) are not allowed as an origin. Use 127.0.0.1 or your app's private address.";
// Small synchronous SHA-256 (hex) so the browser derives the same container name as the server twin.
function sha256Hex(text) {
  const bytes = [...new TextEncoder().encode(text)];
  const bits = bytes.length * 8;
  bytes.push(0x80);
  while (bytes.length % 64 !== 56) bytes.push(0);
  for (let i = 7; i >= 0; i--) bytes.push(i > 3 ? 0 : (bits >>> (i * 8)) & 255);
  const K = []; const H = [];
  for (let n = 2, found = 0; found < 64; n++) {
    if (![...Array(n).keys()].slice(2).every((d) => n % d)) continue;
    if (found < 8) H[found] = (Math.sqrt(n) % 1) * 2 ** 32 | 0;
    K[found++] = (Math.cbrt(n) % 1) * 2 ** 32 | 0;
  }
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < bytes.length; off += 64) {
    const w = [];
    for (let i = 0; i < 16; i++) w[i] = (bytes[off + 4 * i] << 24) | (bytes[off + 4 * i + 1] << 16) | (bytes[off + 4 * i + 2] << 8) | bytes[off + 4 * i + 3];
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
      const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
      w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i]) | 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0;
      [h, g, f, e, d, c, b, a] = [g, f, e, (d + t1) | 0, c, b, a, (t1 + t2) | 0];
    }
    [a, b, c, d, e, f, g, h].forEach((v, i) => { H[i] = (H[i] + v) | 0; });
  }
  return H.map((v) => (v >>> 0).toString(16).padStart(8, '0')).join('');
}
// Same suffix as the server twin: sanitised hostname plus 10 hex of sha256(hostname), so lookalike hostnames never share a name.
export function agentSuffix(hostname) {
  const full = String(hostname).toLowerCase();
  const slug = full.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
  return `${slug}-${sha256Hex(full).slice(0, 10)}`;
}
// Advisory only (the agent runs on the customer's own server). Returns { value } for a usable local app address or { error } with plain-language advice.
export function validateOrigin(input) {
  const text = String(input ?? '').trim();
  if (!text) return { error: `Enter the address your app listens on, such as ${LOCAL(5000)}.` };
  if (/[\s'"<>\\`$;|&]/.test(text)) return { error: 'Remove spaces, quotes and special characters from the address.' };
  let url;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:\/{2}/i.test(text) ? text : `http:${'//'}${text}`); } catch { return { error: `Use a full address such as ${LOCAL(5000)}.` }; }
  if (!['http:', 'https:'].includes(url.protocol)) return { error: `The address must start with http:${'//'} or https:${'//'}.` };
  if (url.username || url.password || url.search || url.hash || (url.pathname && url.pathname !== '/')) return { error: `Use only the address and port, such as ${LOCAL(5000)}, with no path.` };
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (blockedOriginHost(host)) return { error: LINK_LOCAL_ERROR };
  const local = host === 'localhost' || host === '::1' || host === 'host.docker.internal' || PRIVATE_V4.test(host)
    || /^(?:fc|fd)[0-9a-f]{2}:/i.test(host);
  if (!local) return { error: `Use a local or private address on that server, such as ${LOCAL(5000)}.` };
  if (!url.port) return { error: 'Add the port your app uses, such as :5000.' };
  return { value: `${url.protocol}//${url.host}` };
}
// Returns null when a required value is missing, so an incomplete command is never shown.
export function connectionCommand(agentEnv, platform, portalOrigin = window.location.origin, origin = agentEnv.AGENT_LOCAL_UPSTREAM) {
  const upstream = validateOrigin(origin).value;
  if (!agentEnv.AGENT_TOKEN || !agentEnv.AGENT_HOSTNAME || !agentEnv.EDGE_HTTP_URL || !upstream) return null;
  const env = Object.fromEntries(['AGENT_TOKEN', 'AGENT_HOSTNAME', 'AGENT_NAME']
    .filter((key) => typeof agentEnv[key] === 'string').map((key) => [key, agentEnv[key]]));
  env.AGENT_NAME ||= env.AGENT_HOSTNAME; // same default as the server-side twin
  Object.assign(env, {
    EDGE_HTTP_URL: agentEnv.EDGE_HTTP_URL,
    EDGE_WS_URL: agentEnv.EDGE_WS_URL || `${agentEnv.EDGE_HTTP_URL.replace(/^http/, 'ws').replace(/\/$/, '')}/_fastdog/tunnel`,
    AGENT_LOCAL_UPSTREAM: upstream,
  });
  const entries = Object.entries(env);
  if (platform === 'linux') return `curl -fsSL ${shellQuote(new URL('/install/agent.sh', portalOrigin).href)} -o /tmp/fastdog-agent-install.sh && sudo FASTDOG_AGENT_TOKEN=${shellQuote(env.AGENT_TOKEN)} bash /tmp/fastdog-agent-install.sh --edge ${shellQuote(env.EDGE_HTTP_URL)} --hostname ${shellQuote(env.AGENT_HOSTNAME)} --origin ${shellQuote(env.AGENT_LOCAL_UPSTREAM)}`;
  const run = `docker run -d --restart unless-stopped --env-file fastdog-agent.env ${AGENT_IMAGE}`;
  // Plain Linux Docker: host networking reaches an app on 127.0.0.1; the stable name lets a re-run replace the agent.
  const name = `fastdog-agent-${agentSuffix(env.AGENT_HOSTNAME)}`;
  const envFile = platform === 'docker' ? `${name}.env` : 'fastdog-agent.env';
  const hostRun = `{ docker rm -f ${name} >/dev/null 2>&1; true; } && docker run -d --name ${name} --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file ${envFile} ${AGENT_IMAGE}`;
  if (platform === 'windows') {
    return `Set-Content -LiteralPath fastdog-agent.env -Encoding ASCII -Value @(${entries.map(([key, value]) => powershellQuote(`${key}=${value}`)).join(', ')}) -ErrorAction Stop; ${run}`;
  }
  const write = `${platform === 'docker' ? '(set -C; ' : ''}printf '%s\\n' ${entries.map(([key, value]) => shellQuote(`${key}=${value}`)).join(' ')} > ${envFile}${platform === 'docker' ? ')' : ''} && chmod 600 ${envFile}`;
  // Docker pulls first so a failed pull never leaves the token file on disk.
  return platform === 'docker' ? `umask 077; docker pull ${AGENT_IMAGE} && rm -f ${envFile} && ${write} && ${hostRun} || { rm -f ${envFile}; false; }` : `umask 077; ${write} && ${run}`;
}
const CHOICES = [['docker', 'Docker (recommended)'], ['linux', 'Linux installer (sudo)'], ['macos', 'macOS'], ['windows', 'Windows (Untested)']];
// Docker (host networking) is Linux-only; Mac and Windows visitors start on their Docker Desktop tab.
export function defaultChoice(nav = globalThis.navigator) {
  const text = `${nav?.platform ?? ''} ${nav?.userAgent ?? ''}`;
  if (/^win/i.test(nav?.platform ?? '') || /Windows/i.test(text)) return CHOICES.findIndex(([key]) => key === 'windows');
  if (/mac|iphone|ipad/i.test(nav?.platform ?? '') || /Macintosh|Mac OS X/i.test(text)) return CHOICES.findIndex(([key]) => key === 'macos');
  return 0;
}
const originInput =() => document.querySelector('#origin');
export function showCredential(credential) {
  const output = document.querySelector('#command');
  const copyButton = document.querySelector('#copy-command');
  const tabs = document.querySelector('#command-tabs');
  const panel = document.querySelector('#command-panel');
  const help = document.querySelector('#command-help');
  const render = (platform) => {
    const command = connectionCommand(credential.agent_env, platform, window.location.origin, originInput()?.value);
    output.textContent = command ?? '';
    if (!command) {
      if (help) help.textContent = credential.agent_env?.EDGE_HTTP_URL ? 'Enter where your app runs above to finish the command.' : 'Your connect command could not be completed. Email support and we will help.';
      return;
    }
    copyButton.textContent = 'Copy command';
    if (help) help.textContent = platform === 'linux'
      ? 'Alternative for Linux: this installer needs sudo (administrator permission) and sets up a system service. Docker needs no sudo.'
      : platform === 'docker'
        ? 'Recommended: run this in a Linux terminal where your user can run docker without sudo (check with docker info). It uses host networking, so 127.0.0.1 reaches your app, and running it again replaces the old agent. Docker access is root-equivalent, so use this only if you already have it. Delete the .env file it writes after the command finishes. It contains your connection token. On Docker Desktop (macOS or Windows) use those tabs instead, and use host.docker.internal for your app’s address.'
        : `${platform === 'windows' ? 'Untested. Install Docker Desktop and use PowerShell.' : 'Install Docker Desktop and use Terminal.'} Keep fastdog-agent.env private. It contains your connection token. In Docker Desktop, use host.docker.internal to reach a website on the same computer; 127.0.0.1 refers to the container itself.`;
  };
  if (tabs) {
    tabs.replaceChildren();
    const choices = CHOICES;
    const activate = (index, focus = false) => {
      [...tabs.children].forEach((tab, i) => {
        tab.setAttribute('aria-selected', String(i === index));
        tab.tabIndex = i === index ? 0 : -1;
      });
      panel.setAttribute('aria-labelledby', `command-tab-${choices[index][0]}`);
      render(choices[index][0]);
      if (focus) tabs.children[index].focus();
    };
    choices.forEach(([platform, label], index) => {
      const tab = document.createElement('button');
      tab.type = 'button';
      tab.id = `command-tab-${platform}`;
      tab.textContent = label;
      tab.setAttribute('role', 'tab');
      tab.setAttribute('aria-controls', 'command-panel');
      tab.addEventListener('click', () => activate(index));
      tab.addEventListener('keydown', (event) => {
        const next = { ArrowRight: (index + 1) % choices.length, ArrowLeft: (index + choices.length - 1) % choices.length, Home: 0, End: choices.length - 1 }[event.key];
        if (next !== undefined) { event.preventDefault(); activate(next, true); }
      });
      tabs.append(tab);
    });
    activate(defaultChoice());
  } else render('docker'); // The hostname page also displays newly issued commands.
  document.querySelector('#credential').hidden = false;
  const input = originInput();
  if (input) input.oninput = () => { const selected = [...(tabs?.children ?? [])].findIndex((tab) => tab.attrs?.['aria-selected'] === 'true' || tab.getAttribute?.('aria-selected') === 'true'); render(CHOICES[Math.max(selected, 0)][0]); };
  copyButton.onclick = async () => {
    try { await copy(output.textContent); copyButton.textContent = 'Copied'; }
    catch { message('Copy was unavailable. Select the command to copy it.'); }
  };
  // Credentials stay only in this document, never in URLs or browser storage.
  window.addEventListener('pagehide', () => {
    output.textContent = '';
    tabs?.replaceChildren();
    copyButton.onclick = null;
    document.querySelector('#credential').hidden = true;
  }, { once: true });
}
function wireOrigin() {
  const input = originInput();
  const error = document.querySelector('#origin-error');
  if (!input) return;
  input.placeholder = LOCAL(5000);
  if (!input.value) input.value = LOCAL(3000);
  const validate = () => { const result = validateOrigin(input.value); if (error) error.textContent = result.error ?? ''; input.setAttribute('aria-invalid', String(Boolean(result.error))); return result; };
  input.addEventListener('input', validate);
  for (const chip of document.querySelectorAll('[data-port]')) chip.onclick = () => {
    input.value = LOCAL(chip.dataset.port);
    validate();
    input.oninput?.();
  };
  return validate;
}
export function agentStatusText(agent) {
  if (!agent.connected) return 'Waiting for your server. Run your connect command on the server where your app runs.';
  if (agent.origin_reachable === false) return `Agent connected, but your app at ${agent.origin_address || 'the address you entered'} isn't answering. Start your app, or check the address you entered.`;
  return 'Server connected. Open your website to check that it loads securely.';
}
export function watchAgent(hostname, record = {}) {
  const path = `/api/hostnames/${encodeURIComponent(hostname)}`;
  const container = document.querySelector('#origin-actions');
  const credentialSection = document.querySelector('#credential');
  if (credentialSection) credentialSection.hidden = true;
  const commandOutput = document.querySelector('#command');
  if (commandOutput) commandOutput.textContent = '';
  const validate = wireOrigin();
  let issued = Boolean(record?.command_issued);
  const warning = document.createElement('p');
  warning.className = 'rotate-warning';
  warning.textContent = 'Your old command will stop working. Any current connection will close until you run the new command.';
  const primary = button('Get my connect command', async () => {
    if (validate && validate().error) { originInput()?.focus(); return; }
    if (issued && typeof window.confirm === 'function' && !window.confirm('Your old command will stop working. Get a new command?')) return;
    const result = await api(`${path}/rotate`, 'POST');
    issued = true;
    warning.hidden = false;
    showCredential(result.credential);
    message('Your command is ready. Run it on your server, then press Check.');
  });
  primary.classList.add('primary');
  warning.hidden = !issued;
  container.replaceChildren(warning, primary);
  const status = document.querySelector('#connection');
  const checkButton = document.querySelector('#check-agent');
  const checkedAt = document.querySelector('#checked-at');
  const link = document.querySelector('#visit');
  link.href = `https:${'//'}${hostname}/`;
  link.hidden = false;
  let stopped = false;
  let timer;
  const check = async () => {
    clearTimeout(timer);
    if (checkButton) { checkButton.disabled = true; checkButton.setAttribute('aria-busy', 'true'); }
    status.textContent = 'Checking…';
    try {
      const agent = await api(`${path}/agent`);
      if (stopped) return;
      status.textContent = agentStatusText(agent);
      const healthy = Boolean(agent.connected) && agent.origin_reachable !== false;
      status.classList.toggle('healthy', healthy);
      // Cosmetic only: never gate a credential or action on this client-side state.
      const explainer = document.querySelector('#what-happened');
      if (explainer) {
        explainer.hidden = !healthy;
        const statusLink = explainer.querySelector('a[href^="/status"]');
        if (statusLink) statusLink.href = `/status?hostname=${encodeURIComponent(hostname)}`;
      }
    } catch (error) { if (!stopped) status.textContent = error.message; }
    finally {
      if (checkButton) { checkButton.disabled = false; checkButton.removeAttribute('aria-busy'); }
      if (checkedAt) checkedAt.textContent = `Checked at ${new Date().toLocaleTimeString()}`;
    }
    if (!stopped) timer = setTimeout(check, 10000);
  };
  if (checkButton) checkButton.onclick = check;
  check();
  const stop = () => { stopped = true; clearTimeout(timer); };
  window.addEventListener('pagehide', stop, { once: true });
  return stop;
}
