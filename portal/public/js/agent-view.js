import { api, button, copy, message } from './api.js';
const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
export function showCredential(credential) {
  const output = document.querySelector('#command');
  const agentEnv = credential.agent_env;
  const values = ['AGENT_TOKEN', 'AGENT_HOSTNAME', 'AGENT_NAME'].filter((key) => typeof agentEnv[key] === 'string')
    .map((key) => `-e ${key}=${shellQuote(agentEnv[key])}`).join(' ');
  output.textContent = `docker run -d --restart unless-stopped ${values} -e EDGE_WS_URL='<EDGE_WS_URL>' -e AGENT_LOCAL_UPSTREAM='<LOCAL_UPSTREAM>' <AGENT_IMAGE>`;
  document.querySelector('#credential').hidden = false;
  document.querySelector('#copy-command').onclick = () => copy(output.textContent).catch(() => message('Copy was unavailable. Select the command to copy it.'));
  // Credentials stay only in this document, never in URLs or browser storage.
  window.addEventListener('pagehide', () => { output.textContent = ''; }, { once: true });
}
export function watchAgent(hostname) {
  const path = `/api/hostnames/${encodeURIComponent(hostname)}`;
  const container = document.querySelector('#origin-actions');
  container.replaceChildren(button('Rotate token', async () => {
    const result = await api(`${path}/rotate`, 'POST');
    showCredential(result.credential);
    message('The previous token has been revoked. Update the agent with this command.');
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
      status.textContent = agent.connected ? 'Origin connected. Open the hostname to check HTTPS and your service.' : 'Waiting for the origin to connect.';
      status.classList.toggle('healthy', agent.connected);
    } catch (error) { status.textContent = error.message; }
    if (!stopped) timer = setTimeout(check, 10000);
  };
  check();
  const stop = () => { stopped = true; clearTimeout(timer); };
  window.addEventListener('pagehide', stop, { once: true });
  return stop;
}
