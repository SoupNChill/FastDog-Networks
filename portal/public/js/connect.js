import { api, init, message } from './api.js';
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
} catch (error) { message(error.message); }
