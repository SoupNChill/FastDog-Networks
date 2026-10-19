import { api, init, message } from './api.js';
try {
  await init(true);
  const plan = await api('/api/plan');
  document.querySelector('#plan-name').textContent = ({ trial: 'Free trial', assigned: 'Early access', hobby: 'Hobby', pro: 'Pro', agency: 'Agency' })[plan.plan] || plan.plan;
  document.querySelector('#hostname-limit').textContent = `Up to ${plan.hostname_limit} web ${plan.hostname_limit === 1 ? 'address' : 'addresses'}`;
  const trial = document.querySelector('#trial-status');
  if (plan.trial && trial) {
    trial.textContent = plan.trial.paused
      ? 'Your trial has ended and your site is paused. Choose a plan to bring it back. Nothing was deleted.'
      : `${plan.trial.days_left} ${plan.trial.days_left === 1 ? 'day' : 'days'} left in your free trial`;
    trial.hidden = false;
  }
} catch (error) { message(error.message); }
