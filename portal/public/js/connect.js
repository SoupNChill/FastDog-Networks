import { api, init, form, message } from './api.js';
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
  form('#connect', async ({ hostname }) => {
    if (!hostname) return message('Add and verify a hostname first.');
    stop?.();
    document.querySelector('#credential').hidden = true;
    document.querySelector('#command').textContent = '';
    stop = watchAgent(hostname);
  });
  if (select.value) stop = watchAgent(select.value);
} catch (error) { message(error.message); }
