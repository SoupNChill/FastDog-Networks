import { jsonClient } from './http-client.js';
export function createDomainClient({ baseUrl = 'http://127.0.0.1:8791', timeout = 5000 } = {}) {
  const call = jsonClient({ baseUrl, timeout, errorMap: { invalid_domain: 'invalid_hostname' } });
  return { search: (q, _ip) => call(`/api/domains/search?${new URLSearchParams({ q })}`) };
}
