import { api, init, message, copy } from './api.js';
import { watchAgent } from './agent-view.js';
let stop;
try {
  await init(true);
  const { hostnames } = await api('/api/hostnames');
  const select = document.querySelector('#hostname');
  const selected = new URLSearchParams(location.search).get('hostname');
  for (const record of hostnames.filter((host) => host.status === 'active')) {
    const option = document.createElement('option');
    option.value = record.hostname;
    option.textContent = record.hostname;
    option.selected = selected === record.hostname;
    select.append(option);
  }
  document.querySelector('#connect').hidden = !select.value;
  document.querySelector('#connect-empty').hidden = Boolean(select.value);
  const choose = () => {
    stop?.();
    stop = watchAgent(select.value, hostnames.find((record) => record.hostname === select.value));
  };
  select.addEventListener?.('change', choose);
  document.querySelector('#connect').addEventListener?.('submit', (event) => event.preventDefault());
  if (select.value) choose();
  wirePrompt(select);
} catch (error) { message(error.message); }

function wirePrompt(select) {
  const section = document.querySelector('#ai-prompt');
  if (!section || !select.value) return;
  section.hidden = false;
  const text = document.querySelector('#ai-text');
  const copyButton = document.querySelector('#ai-copy');
  const note = document.querySelector('#ai-note');
  const clear = () => { text.textContent = ''; text.hidden = true; copyButton.hidden = true; };
  select.addEventListener?.('change', () => { clear(); note.textContent = ''; });
  document.querySelector('#ai-create').onclick = async () => {
    try {
      const result = await api(`/api/hostnames/${encodeURIComponent(select.value)}/connect-token`, 'POST');
      text.textContent = result.prompt;
      text.hidden = false;
      copyButton.hidden = false;
      copyButton.textContent = 'Copy prompt';
      note.textContent = `Token expires at ${new Date(result.expires_at).toLocaleTimeString()}. It is shown only here.`;
    } catch (error) { message(error.message); }
  };
  document.querySelector('#ai-revoke').onclick = async () => {
    try {
      const result = await api(`/api/hostnames/${encodeURIComponent(select.value)}/connect-token`, 'DELETE');
      clear();
      note.textContent = result.revoked ? `Revoked ${result.revoked} prompt token${result.revoked === 1 ? '' : 's'}.` : 'No prompt tokens to revoke.';
    } catch (error) { message(error.message); }
  };
  copyButton.onclick = async () => {
    try { await copy(text.textContent); copyButton.textContent = 'Copied'; }
    catch { message('Copy was unavailable. Select the prompt to copy it.'); }
  };
  window.addEventListener?.('pagehide', clear, { once: true });
}
