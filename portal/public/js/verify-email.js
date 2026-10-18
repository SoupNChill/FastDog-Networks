import { api, init, form, message } from './api.js';
const fragment = new URLSearchParams(location.hash.slice(1));
let token = fragment.get('token');
const setup = fragment.get('setup') === '1';
history.replaceState(null, '', location.pathname);
const verification = document.querySelector('#verify-email');
const submit = verification.querySelector('button[type="submit"]');
const password = setup ? verification.querySelector('input[name="password"]') : null;
if (setup) { password.parentElement.hidden = false; password.required = true; }
let pending = false;
async function verify() {
  if (pending) return;
  if (!token) { message('Open the complete verification link from your email. If it has expired, email support for help.'); return; }
  pending = true;
  submit.disabled = true;
  message('Verifying your email…');
  try {
    const me = await init();
    await api('/api/verify-email', 'POST', { token, ...(setup ? { password: password.value } : {}) });
    token = null;
    verification.hidden = true;
    const next = document.querySelector('#continue');
    next.href = me.tenant && !setup ? '/hostname' : '/login';
    next.hidden = false;
    message(me.tenant && !setup ? 'Email verified. Continue to your account.' : 'Email verified. Continue to sign in.');
  } catch (error) {
    message(`${error.message} The link may have expired or already been used. You can try again below, sign in, or email support for help.`);
  } finally {
    pending = false;
    submit.disabled = false;
  }
}
form('#verify-email', verify);
if (token && setup) message('Choose a new password to verify your email and secure your account.');
else if (token) await verify();
else message('Open the complete verification link from your email.');
