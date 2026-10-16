let csrf;
export const message = (text) => { document.querySelector('#message').textContent = text; };
const errors = {
  unauthorized: 'Please sign in, verify your email, or check the details and try again.',
  invalid_hostname: 'Enter a complete hostname, such as app.example.com.',
  reserved_hostname: 'This hostname is reserved. Choose another name.',
  hostname_unavailable: 'This hostname is unavailable.',
  hostname_not_found: 'This hostname was not found in your account.',
  hostname_limit_reached: 'Your plan’s hostname limit has been reached.',
  invalid_limit: 'You can have up to three open domain requests.',
  not_active: 'Verify the hostname before connecting an origin.',
  rate_limited: 'Please wait before trying again.',
  invalid_key: 'Pick at least one permission, a lifetime of up to 90 days, and full website addresses.',
  key_limit_reached: 'You already have 10 active keys. Revoke one first.',
  plan_required: 'API keys come with every paid plan.',
};
export async function api(path, method = 'GET', body) {
  const response = await fetch(path, { method, credentials: 'same-origin', headers: {
    ...(method === 'GET' ? {} : { 'Content-Type': 'application/json', 'x-fd-csrf': csrf }),
  }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const result = await response.json();
  if (!response.ok) throw new Error(errors[result.error] || 'The request could not be completed. Please try again.');
  return result;
}
export async function init(required = false) {
  const me = await api('/api/me');
  csrf = me.csrf;
  if (required && !me.tenant) { location.assign('/login'); throw new Error('Please sign in.'); }
  const nav = document.querySelector('nav');
  if (me.tenant && nav && !nav.querySelector('a[href="/start"]')) {
    const start = document.createElement('a');
    start.href = '/start';
    start.textContent = 'Start';
    nav.prepend(start);
  }
  const logout = document.querySelector('#logout');
  const signin = document.querySelector('#signin');
  if (logout) logout.hidden = !me.tenant;
  if (signin) signin.hidden = Boolean(me.tenant);
  if (logout) logout.onclick = async () => {
    try { await api('/api/logout', 'POST'); location.assign('/login'); } catch (error) { message(error.message); }
  };
  return me;
}
export function form(id, callback) {
  document.querySelector(id).addEventListener('submit', async (event) => {
    event.preventDefault();
    const button = event.currentTarget.querySelector('button[type="submit"]');
    button.disabled = true;
    try { await callback(Object.fromEntries(new FormData(event.currentTarget))); }
    catch (error) { message(error.message); }
    finally { button.disabled = false; }
  });
}
export function button(label, callback) {
  const element = document.createElement('button');
  element.type = 'button';
  element.textContent = label;
  element.addEventListener('click', async () => {
    element.disabled = true;
    try { await callback(); } catch (error) { message(error.message); }
    finally { element.disabled = false; }
  });
  return element;
}
export function copy(text) { return navigator.clipboard.writeText(text).then(() => message('Copied.')); }
