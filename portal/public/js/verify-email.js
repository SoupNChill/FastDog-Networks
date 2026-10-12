import { api, init, form, message } from './api.js';
const token = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
form('#verify-email', async () => {
  if (!token) { message('Open the complete verification link from your email.'); return; }
  await init();
  await api('/api/verify-email', 'POST', { token });
  document.querySelector('#verify-email').hidden = true;
  message('Email verified. Continue to sign in.');
});
