import { api, button, copy, message } from './api.js';
const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
const powershellQuote = (value) => `'${String(value).replace(/'/g, "''")}'`;
export function connectionCommand(agentEnv, platform) {
  const env = Object.fromEntries(['AGENT_TOKEN', 'AGENT_HOSTNAME', 'AGENT_NAME']
    .filter((key) => typeof agentEnv[key] === 'string').map((key) => [key, agentEnv[key]]));
  Object.assign(env, {
    EDGE_HTTP_URL: '<EDGE_HTTP_URL>', EDGE_WS_URL: '<EDGE_WS_URL>',
    AGENT_LOCAL_UPSTREAM: '<LOCAL_UPSTREAM>',
  });
  const entries = Object.entries(env);
  if (platform === 'docker') return `docker run -d --restart unless-stopped ${entries.map(([key, value]) => `-e ${key}=${shellQuote(value)}`).join(' ')} <AGENT_IMAGE>`;
  if (platform === 'windows') return `${entries.map(([key, value]) => `$env:${key} = ${powershellQuote(value)}`).join('\n')}\nnode agent/index.js`;
  return `${entries.map(([key, value]) => `${key}=${shellQuote(value)}`).join(' ')} node agent/index.js`;
}
export function showCredential(credential) {
  const output = document.querySelector('#command');
  const copyButton = document.querySelector('#copy-command');
  const tabs = document.querySelector('#command-tabs');
  const panel = document.querySelector('#command-panel');
  const help = document.querySelector('#command-help');
  const render = (platform) => {
    output.textContent = connectionCommand(credential.agent_env, platform);
    copyButton.textContent = 'Copy command';
    if (help) help.textContent = platform === 'docker'
      ? 'Docker (recommended): install Docker first. Ask support for the agent image and replace <AGENT_IMAGE>. Your website’s local address must be reachable from inside the container; 127.0.0.1 points to the container itself. Run this command in a Linux or macOS terminal.'
      : `Use ${platform === 'windows' ? 'PowerShell' : 'a terminal'}. You need Node 18 or 20 and a copy of the FastDog agent with its dependencies installed (including ws). Ask support for these files. Run this command from the folder containing agent/. Keep this window open to stay connected.`;
  };
  if (tabs) {
    tabs.replaceChildren();
    const choices = [['docker', 'Docker (recommended)'], ['linux', 'Linux'], ['macos', 'macOS'], ['windows', 'Windows (PowerShell)']];
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
  } else render('docker'); // The hostname page also displays newly issued commands.
  document.querySelector('#credential').hidden = false;
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
export function watchAgent(hostname) {
  const path = `/api/hostnames/${encodeURIComponent(hostname)}`;
  const container = document.querySelector('#origin-actions');
  const warning = document.createElement('p');
  warning.textContent = 'Your old command will stop working. Any current connection will close until you run the new command.';
  container.replaceChildren(warning, button('Get a new connect command', async () => {
    const result = await api(`${path}/rotate`, 'POST');
    showCredential(result.credential);
    message('Your new command is ready. Run it on your server to connect again.');
  }));
  const status = document.querySelector('#connection');
  const link = document.querySelector('#visit');
  link.href = `https:${'//'}${hostname}/`;
  link.hidden = false;
  let stopped = false;
  let timer;
  const check = async () => {
    try {
      const agent = await api(`${path}/agent`);
      if (stopped) return;
      status.textContent = agent.connected ? 'Server connected. Open your website to check that it loads securely.' : 'Waiting for your server. Run your connect command on the server where your website runs.';
      status.classList.toggle('healthy', agent.connected);
    } catch (error) { if (!stopped) status.textContent = error.message; }
    if (!stopped) timer = setTimeout(check, 10000);
  };
  check();
  const stop = () => { stopped = true; clearTimeout(timer); };
  window.addEventListener('pagehide', stop, { once: true });
  return stop;
}
