export const username = 'private-test-username';
export const apiKey = 'private-test-key&<secret>';
export const escapeXml = (value) => String(value).replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
})[c]);
export function xml(value) {
  const encode = (entry) => {
    if (entry === null || typeof entry !== 'object') return escapeXml(entry);
    const tag = Array.isArray(entry) ? 'dt_array' : 'dt_assoc';
    return `<${tag}>${Object.entries(entry).map(([key, val]) =>
      `<item key="${escapeXml(key)}">${encode(val)}</item>`).join('')}</${tag}>`;
  };
  return `<?xml version='1.0' encoding='UTF-8' standalone='no' ?>\n<!DOCTYPE OPS_envelope SYSTEM 'ops.dtd'>\n<OPS_envelope><header><version>0.9</version></header><body><data_block>${encode(value)}</data_block></body></OPS_envelope>`;
}
export const available = { response_code: '210', is_success: '1', attributes: { status: 'available' } };
export const taken = { response_code: '211', is_success: '1', attributes: { status: 'taken' } };
export const invalid = { response_code: '465', is_success: '0', response_text: 'Invalid domain syntax', attributes: { status: 'invalid' } };
export const price = (value = '14.50', extra = {}) => ({ response_code: '200', is_success: '1', attributes: { price: value, ...extra } });
export function mockRegistrar({ lookup = () => available, getPrice = () => price() } = {}) {
  const calls = [];
  return { calls,
    async lookup(domain) { calls.push(['lookup', domain]); return lookup(domain); },
    async getPrice(domain, type) { calls.push(['getPrice', domain, type]); return getPrice(domain, type); },
  };
}
