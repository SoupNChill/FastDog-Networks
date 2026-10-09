import { api, init, message } from './api.js';
try {
  await init(true);
  const plan = await api('/api/plan');
  document.querySelector('#plan-name').textContent = plan.plan;
  document.querySelector('#hostname-limit').textContent = `${plan.hostname_limit} hostnames`;
} catch (error) { message(error.message); }
