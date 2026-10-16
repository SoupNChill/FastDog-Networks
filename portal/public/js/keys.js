import { api, init, message, copy, button } from './api.js';

const scopeText = { 'status:read': 'read status', 'hostnames:create': 'add websites', connect: 'connect command' };
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
    detail.textContent = ` ${key.scopes.map((s) => scopeText[s] || s).join(', ')}; ${key.hostnames ? key.hostnames.join(', ') : 'all your websites'}; `
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

async function load() {
  const data = await api('/api/keys');
  document.querySelector('#keys-unavailable').hidden = data.available;
  document.querySelector('#key-form').hidden = !data.available;
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
      const made = await api('/api/keys', 'POST', { name: form.name.value, scopes, hostnames,
        expires_in_days: Number(form.expires_in_days.value) });
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
