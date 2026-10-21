import { api, init, message, copy, button } from './api.js';

const scopeLabels = { 'status:read': 'read status', 'hostnames:create': 'add websites', connect: 'connect command' };
const when = (iso) => (iso ? new Date(iso).toLocaleDateString([], { dateStyle: 'medium' }) : 'never');

function render(data) {
  const list = document.querySelector('#keys-list');
  list.replaceChildren();
  document.querySelector('#keys-empty').hidden = data.keys.length > 0;
  for (const key of data.keys) {
    const item = document.createElement('li');
    const title = document.createElement('strong');
    title.textContent = `${key.name || 'Unnamed key'} (${key.prefix}?)`;
    const detail = document.createElement('span');
    detail.textContent = ` ${key.scopes.map((s) => scopeLabels[s] || s).join(', ')}; ${key.hostnames ? key.hostnames.join(', ') : 'all your websites'}; `
      + (key.state === 'active' ? `expires ${when(key.expires_at)}; last used ${when(key.last_used_at)}` : key.state);
    item.append(title, detail);
    if (key.state === 'active') {
      item.append(' ', button('Revoke', async () => {
        if (!confirm('Revoke this key? Anything using it stops working right away.')) return;
        await api(`/api/keys/${encodeURIComponent(key.id)}`, 'DELETE');
        message('Key revoked.');
        await load();
      }));
    }
    list.append(item);
  }
}

// Set only when the API says trial limits apply (TRIAL_API_KEY_ENABLED); otherwise the page is unchanged.
let trial = null;
let liveKeys = 0;

function showTrial() {
  const note = document.querySelector('#keys-trial');
  note.hidden = !trial;
  if (!trial) return;
  note.textContent = `Trial key: ${trial.max_hostnames} hostname, expires when your trial ends (${when(trial.expires_at)}), ${trial.max_keys} key at a time.`;
  document.querySelector('label[for="key-hosts"]').textContent = 'The one website this key may use (required)';
  const hosts = document.querySelector('#key-hosts');
  hosts.required = true;
  hosts.rows = 1;
  for (const element of [document.querySelector('label[for="key-days"]'), document.querySelector('#key-days')]) element.hidden = true;
}

async function load() {
  const data = await api('/api/keys');
  trial = data.trial ?? null;
  liveKeys = data.keys.filter((key) => key.state === 'active').length;
  document.querySelector('#keys-unavailable').hidden = data.available;
  document.querySelector('#key-form').hidden = !data.available;
  showTrial();
  render(data);
}

async function main() {
  await init(true);
  await load();
  document.querySelector('#key-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const submit = form.querySelector('button[type="submit"]');
    submit.disabled = true;
    try {
      const scopes = [...form.querySelectorAll('input[name="scope"]:checked')].map((box) => box.value);
      const hostnames = form.hostnames.value.split(/\s+/).map((h) => h.trim()).filter(Boolean);
      if (trial && liveKeys >= trial.max_keys) throw new Error('A trial account can have 1 active key. Revoke it first.');
      if (trial && hostnames.length !== trial.max_hostnames) throw new Error('A trial key needs exactly one website address.');
      // A trial key always runs until the trial ends, so no lifetime is sent.
      const made = await api('/api/keys', 'POST', { name: form.name.value, scopes, hostnames,
        ...(trial ? {} : { expires_in_days: Number(form.expires_in_days.value) }), password: form.password.value });
      document.querySelector('#key-secret').textContent = made.key;
      document.querySelector('#key-new').hidden = false;
      document.querySelector('#key-copy').onclick = () => copy(made.key);
      form.reset();
      message('Key created. Copy it now.');
      await load();
    } catch (error) { message(error.message); }
    finally { submit.disabled = false; }
  });
}
main().catch((error) => message(error.message));
