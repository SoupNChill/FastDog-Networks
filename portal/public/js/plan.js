import { api, init, message } from './api.js';
try {
  await init(true);
  const plan = await api('/api/plan');
  document.querySelector('#plan-name').textContent = ({ assigned: 'Early access', hobby: 'Hobby', pro: 'Pro', agency: 'Agency' })[plan.plan] || plan.plan;
  document.querySelector('#hostname-limit').textContent = `Up to ${plan.hostname_limit} web ${plan.hostname_limit === 1 ? 'address' : 'addresses'}`;
} catch (error) { message(error.message); }
