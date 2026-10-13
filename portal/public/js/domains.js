import { api, init, form, button, message } from './api.js';
async function requests() {
  const result = await api('/api/domain-requests');
  const list = document.querySelector('#requests');
  list.replaceChildren();
  for (const entry of result.requests) {
    const row = document.createElement('p');
    row.textContent = `${entry.name} — ${entry.status}`;
    list.append(row);
    if (entry.status === 'registered') {
      const link = document.createElement('a');
      link.href = '/hostname';
      link.textContent = 'Set up this web address';
      list.append(link);
    }
  }
  if (!result.requests.length) list.textContent = 'No requests yet. Search above to find a name.';
}
try {
  const me = await init();
  form('#search', async ({ q }) => {
    const data = await api(`/api/domains/search?${new URLSearchParams({ q })}`);
    const list = document.querySelector('#results');
    list.replaceChildren();
    for (const result of data.results || []) {
      const row = document.createElement('article');
      const label = document.createElement('p');
      label.textContent = `${result.domain} — ${result.status}. ${result.price_year == null ? 'Price unavailable' : `${result.price_year} ${result.currency} per year`}`;
      row.append(label);
      if (result.status === 'available') row.append(button('Request this name', async () => {
        if (!me.tenant) return location.assign('/login');
        await api('/api/domain-requests', 'POST', { name: result.domain, quoted_price: result.price_year });
        message('Request received. We will email you to confirm the price and next steps.');
        await requests();
      }));
      list.append(row);
    }
    message(data.degraded ? 'Some results are temporarily unavailable. Please try again later.' : 'Search complete. Prices are quotes and may change.');
  });
  if (me.tenant) await requests();
} catch (error) { message(error.message); }
