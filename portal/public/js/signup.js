import { api, init, form, message } from './api.js';
const toggle = document.querySelector('#show-password');
toggle.addEventListener('click', () => {
  const password = document.querySelector('#password');
  const showing = password.type === 'password';
  password.type = showing ? 'text' : 'password';
  toggle.textContent = showing ? 'Hide password' : 'Show password';
  toggle.setAttribute('aria-pressed', String(showing));
});
try {
  await init();
  form('#signup', async (data) => {
    await api('/api/signup', 'POST', { ...data, accept_terms: document.querySelector('#accept-terms').checked });
    document.querySelector('#signup').reset();
    document.querySelector('#password').type = 'password';
    toggle.textContent = 'Show password';
    toggle.setAttribute('aria-pressed', 'false');
    message(`Check your inbox. We sent a link to ${data.email}. It expires in one hour.`);
  });
} catch (error) { message(error.message); }
