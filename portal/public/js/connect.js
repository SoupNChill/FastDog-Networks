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
  form('#connect', async ({ hostname }) => {
    if (!hostname) return message('Add and verify a hostname first.');
    stop?.();
    document.querySelector('#credential').hidden = true;
    document.querySelector('#command').textContent = '';
    stop = watchAgent(hostname);
  });
  if (select.value) stop = watchAgent(select.value);
  else message('Add and verify a hostname first.');
} catch (error) { message(error.message); }
