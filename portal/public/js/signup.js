import { api, init, form, message } from './api.js';
const toggle = document.querySelector('#show-password');
toggle.addEventListener('click', () => {
  const password = document.querySelector('#password');
  const showing = password.type === 'password';
  password.type = showing ? 'text' : 'password';
  toggle.textContent = showing ? 'Hide password' : 'Show password';
  toggle.setAttribute('aria-pressed', String(showing));
});
const invite = document.querySelector('#invite');
const inviteField = document.querySelector('#invite-field');
const inviteLabel = document.querySelector('#invite-label');
const inviteToggle = document.querySelector('#invite-toggle');
const intro = document.querySelector('#signup-intro');
const help = document.querySelector('#signup-help');
// The server is the real gate: with open sign-up on, an empty invite_code takes the open trial path.
const optionalInvite = () => {
  invite.required = false;
  invite.removeAttribute('required');
};
let me;
let initError;
try { me = await init(); } catch (error) { initError = error; }
const open = Boolean(me && me.open_signup === true);
if (open) {
  optionalInvite();
  inviteLabel.textContent = 'Invitation code (optional)';
  inviteField.hidden = true;
  inviteToggle.hidden = false;
  inviteToggle.setAttribute('aria-expanded', 'false');
  inviteToggle.addEventListener('click', () => {
    const show = inviteField.hidden;
    inviteField.hidden = !show;
    inviteToggle.setAttribute('aria-expanded', String(show));
    if (show) invite.focus();
    else invite.value = '';
  });
  intro.textContent = 'Start your 7-day free trial: 1 hostname, no card needed.';
  help.textContent = 'After you create your account, check your inbox and spam folder for a verification link. If you already have an account, sign in below.';
} else if (initError) {
  // Do not let a failed status check force a code: the server decides. (Without a CSRF token
  // from init() the POST itself still fails and shows an error; this only avoids a hard block.)
  optionalInvite();
  inviteLabel.textContent = 'Invitation code (optional)';
}
form('#signup', async (data) => {
  const body = { ...data, accept_terms: document.querySelector('#accept-terms').checked };
  const code = typeof body.invite_code === 'string' ? body.invite_code.trim() : '';
  if (open && (inviteField.hidden || !code)) delete body.invite_code;
  else if (typeof body.invite_code === 'string') body.invite_code = code;
  await api('/api/signup', 'POST', body);
  document.querySelector('#signup').reset();
  document.querySelector('#password').type = 'password';
  toggle.textContent = 'Show password';
  toggle.setAttribute('aria-pressed', 'false');
  message(`Check your inbox. We sent a link to ${data.email}. It expires in one hour.`);
});
if (initError) message(initError.message);
