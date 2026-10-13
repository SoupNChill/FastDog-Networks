import { api, init, form, message } from './api.js';
let token = new URLSearchParams(location.hash.slice(1)).get('token');
history.replaceState(null, '', location.pathname);
const verification = document.querySelector('#verify-email');
const submit = verification.querySelector('button[type="submit"]');
let pending = false;
async function verify() {
  if (pending) return;
  if (!token) { message('Open the complete verification link from your email. If it has expired, email support for help.'); return; }
  pending = true;
  submit.disabled = true;
  message('Verifying your email…');
  try {
    const me = await init();
    await api('/api/verify-email', 'POST', { token });
    token = null;
    verification.hidden = true;
    const next = document.querySelector('#continue');
    next.href = me.tenant ? '/hostname' : '/login';
    next.hidden = false;
    message(me.tenant ? 'Email verified. Continue to your account.' : 'Email verified. Continue to sign in.');
  } catch (error) {
    message(`${error.message} The link may have expired or already been used. You can try again below, sign in, or email support for help.`);
  } finally {
    pending = false;
    submit.disabled = false;
  }
}
form('#verify-email', verify);
if (token) await verify();
else message('Open the complete verification link from your email.');
