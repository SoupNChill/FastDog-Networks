import { api, button, copy, message } from './api.js';
const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
const powershellQuote = (value) => `'${String(value).replace(/'/g, "''")}'`;
const AGENT_IMAGE = 'ghcr.io/soupnchill/fastdog-agent:0.1.2@sha256:6dcc855e5dcc5c058326d961133186b30cfa158a0173facd50d5e4e00cefd726';
const LOCAL = (port) => `http:${'//'}127.0.0.1:${port}`;
const PRIVATE_V4 = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)/;
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
  const local = host === 'localhost' || host === '::1' || host === 'host.docker.internal' || PRIVATE_V4.test(host)
    || /^(?:fc|fd)[0-9a-f]{2}:/i.test(host) || /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host);
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
  Object.assign(env, {
    EDGE_HTTP_URL: agentEnv.EDGE_HTTP_URL,
    EDGE_WS_URL: agentEnv.EDGE_WS_URL || `${agentEnv.EDGE_HTTP_URL.replace(/^http/, 'ws').replace(/\/$/, '')}/_fastdog/tunnel`,
    AGENT_LOCAL_UPSTREAM: upstream,
  });
  const entries = Object.entries(env);
  if (platform === 'linux') return `curl -fsSL ${shellQuote(new URL('/install/agent.sh', portalOrigin).href)} -o /tmp/fastdog-agent-install.sh && sudo FASTDOG_AGENT_TOKEN=${shellQuote(env.AGENT_TOKEN)} bash /tmp/fastdog-agent-install.sh --edge ${shellQuote(env.EDGE_HTTP_URL)} --hostname ${shellQuote(env.AGENT_HOSTNAME)} --origin ${shellQuote(env.AGENT_LOCAL_UPSTREAM)}`;
  const run = `docker run -d --restart unless-stopped --env-file fastdog-agent.env ${AGENT_IMAGE}`;
  if (platform === 'windows') {
    return `Set-Content -LiteralPath fastdog-agent.env -Encoding ASCII -Value @(${entries.map(([key, value]) => powershellQuote(`${key}=${value}`)).join(', ')}) -ErrorAction Stop; ${run}`;
  }
  return `umask 077; printf '%s\\n' ${entries.map(([key, value]) => shellQuote(`${key}=${value}`)).join(' ')} > fastdog-agent.env && chmod 600 fastdog-agent.env && ${run}`;
}
const originInput = () => document.querySelector('#origin');
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
      ? 'Linux (recommended): run this command in your server’s terminal. It installs the connection software with administrator permission.'
      : `${platform === 'windows' ? 'Untested. Install Docker Desktop and use PowerShell.' : platform === 'macos' ? 'Install Docker Desktop and use Terminal.' : 'Install Docker and use a Linux or macOS terminal.'} Keep fastdog-agent.env private. It contains your connection token. Your website’s local address must be reachable from inside Docker. In Docker Desktop, use host.docker.internal to reach a website on the same computer; 127.0.0.1 refers to the container itself.`;
  };
  if (tabs) {
    tabs.replaceChildren();
    const choices = [['linux', 'Linux (recommended)'], ['docker', 'Docker'], ['macos', 'macOS'], ['windows', 'Windows (Untested)']];
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
    activate(0);
  } else render('linux'); // The hostname page also displays newly issued commands.
  document.querySelector('#credential').hidden = false;
  const input = originInput();
  if (input) input.oninput = () => { const selected = [...(tabs?.children ?? [])].findIndex((tab) => tab.attrs?.['aria-selected'] === 'true' || tab.getAttribute?.('aria-selected') === 'true'); render(['linux', 'docker', 'macos', 'windows'][Math.max(selected, 0)]); };
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
