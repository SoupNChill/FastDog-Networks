import { api, init, form, message } from './api.js';
import { showTermsUpdate } from './terms-update.js';
import { loginDestination } from './start-state.js';
const fragment = new URLSearchParams(location.hash.slice(1));
const linkToken = fragment.get('token');
const kind = fragment.get('kind');
history.replaceState(null, '', location.pathname);
try {
  await init();
  if (linkToken && kind === 'verify-email') {
    await api('/api/verify-email', 'POST', { token: linkToken });
    message('Email verified. You can now sign in and add a hostname.');
  }
  if (linkToken && kind === 'password-reset') {
    document.querySelector('#reset-confirm').hidden = false;
    form('#reset-confirm', async (data) => {
      await api('/api/password-reset/confirm', 'POST', { token: linkToken, password: data.password });
      document.querySelector('#reset-confirm').hidden = true;
      await init();
      message('Password changed. Sign in with your new password.');
    });
  }
  form('#login', async (data) => {
    try {
      await api('/api/login', 'POST', data);
      const destination = await loginDestination(api);
      try {
        await init(); // Refresh CSRF after login rotates the session.
        const status = await api('/api/terms/status');
        if (!showTermsUpdate(status.terms_update, api, () => location.assign(destination))) location.assign(destination);
      } catch { location.assign(destination); }
    } catch (error) {
      message(`${error.message} Check your email address and password. If you forgot your password, use the reset link below.`);
    }
  });
  form('#reset-request', async (data) => {
    await api('/api/password-reset', 'POST', data);
    message('If this email has an account, a password reset link will be sent.');
  });
} catch (error) { message(error.message); }
