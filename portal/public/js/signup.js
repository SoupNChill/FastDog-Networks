import { api, init, form, message } from './api.js';
try {
  await init();
  form('#signup', async (data) => {
    await api('/api/signup', 'POST', data);
    document.querySelector('#signup').reset();
    message('If the details match a valid invitation, a verification link will be sent. Check your email, then sign in.');
  });
} catch (error) { message(error.message); }
