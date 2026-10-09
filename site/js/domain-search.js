(() => {
  const form = document.getElementById('domain-search-form');
  const input = document.getElementById('domain-name');
  const results = document.getElementById('domain-search-results');
  if (!form || !input || !results) return;
  const tlds = ['com', 'net', 'org', 'dev', 'app', 'io', 'co'];
  const unavailable = "Live availability is unavailable right now. Email us the name you want and we'll check it.";
  const normalize = (value) => {
    const name = value.toLowerCase().replace(/\.$/, '');
    const parts = name.split('.');
    const [label, tld = 'com'] = parts;
    if (name.length > 253 || parts.length > 2 || !tlds.includes(tld)
      || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)
      || label.slice(2, 4) === '--') return null;
    return `${label}.${tld}`;
  };
  const element = (tag, text, className) => {
    const node = document.createElement(tag);
    node.textContent = text;
    if (className) node.className = className;
    return node;
  };
  const message = (text) => results.append(element('p', text, 'domain-search-message'));
  const validPrice = (price) => typeof price === 'string' && /^\d{1,9}\.\d{2}$/.test(price);
  // Thousands separators without locale dependence: '2400.00' -> '2,400.00'.
  const formatPrice = (price) => price.replace(/^\d+/, (whole) => whole.replace(/\B(?=(\d{3})+$)/g, ','));

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const domain = normalize(input.value);
    results.replaceChildren();
    if (!domain) {
      input.setAttribute('aria-invalid', 'true');
      message('Enter a valid domain name using one of the supported endings.');
      input.focus();
      return;
    }
    input.removeAttribute('aria-invalid');
    const button = form.querySelector('button');
    button.disabled = true;
    results.setAttribute('aria-busy', 'true');
    message('Checking availability…');
    const controller = new AbortController();
    // Up to fifteen sequential upstream operations, each with an eight-second limit.
    const timeout = setTimeout(() => controller.abort(), 125_000);
    try {
      const response = await fetch(`/api/domains/search?q=${encodeURIComponent(domain)}`, {
        signal: controller.signal,
        credentials: 'same-origin',
        headers: { Accept: 'application/json' },
      });
      results.replaceChildren();
      if (response.status === 429) {
        message('Too many searches. Try again in a few minutes, or email us.');
        return;
      }
      if (!response.ok) throw new Error();
      const data = await response.json();
      if (!Array.isArray(data.results) || data.results.length > 5) throw new Error();
      if (data.degraded) message(unavailable);
      for (const result of data.results) {
        if (typeof result.domain !== 'string' || normalize(result.domain) !== result.domain
          || !['available', 'taken', 'unknown'].includes(result.status)) throw new Error();
        const row = element('div', '', 'domain-result');
        const name = element('div', '', 'domain-result-name');
        name.append(element('strong', result.domain));
        if (result.premium === true) name.append(element('span', 'Premium', 'domain-premium'));
        row.append(name, element('span', {
          available: 'Available', taken: 'Taken', unknown: 'Unknown',
        }[result.status], 'domain-result-status'));
        if (result.status === 'available') {
          const prices = element('div', '', 'domain-result-prices');
          prices.append(element('p', validPrice(result.price_year)
            ? `$${formatPrice(result.price_year)} / yr first year` : 'First-year price unavailable'));
          prices.append(element('p', validPrice(result.price_renewal)
            ? `Renews at $${formatPrice(result.price_renewal)} / yr` : 'Renewal price unavailable'));
          const link = element('a', 'Email us to register', 'text-link');
          link.href = `mailto:support@fastdognetworks.com?subject=${encodeURIComponent(`Register ${result.domain}`)}&body=${encodeURIComponent(`I'd like to register ${result.domain}. Please confirm availability and the registration and renewal prices.`)}`;
          row.append(prices, link);
        }
        results.append(row);
      }
    } catch {
      results.replaceChildren();
      message(unavailable);
    } finally {
      clearTimeout(timeout);
      button.disabled = false;
      results.removeAttribute('aria-busy');
    }
  });
  form.hidden = false;
  document.getElementById('domain-search-fallback').hidden = true;
})();
