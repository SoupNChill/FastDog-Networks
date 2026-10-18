// Port of the portal origin rules; keep parity covered by tests.
const PRIVATE_V4 = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;
// URL.hostname has already canonicalised numeric addresses (including mapped IPv4).
function blockedOriginHost(host) {
  if (!host.includes(':')) {
    const octets = host.split('.').map(Number);
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n))) return false;
    const ip = octets.reduce((value, n) => value * 256 + n, 0);
    // 0.0.0.0, 169.254.0.0/16 and 100.64.0.0/10.
    return ip === 0 || Math.floor(ip / 65536) === 0xa9fe || Math.floor(ip / 4194304) === 0x191;
  }
  const halves = host.split('::').map((part) => part ? part.split(':') : []);
  const words = halves.length === 2 ? [...halves[0], ...Array(8 - halves[0].length - halves[1].length).fill('0'), ...halves[1]] : halves[0];
  const ip = words.reduce((value, word) => (value << 16n) + BigInt(`0x${word}`), 0n);
  return ip >> 118n === 0x3fan // fe80::/10
    || ip >> 96n === 0xfd000ec2n // fd00:ec2::/32
    || ip >> 32n === 0x64ff9b0000000000000000n // 64:ff9b::/96
    || (ip >> 32n === 0xffffn && blockedOriginHost([24n, 16n, 8n, 0n].map((shift) => Number((ip >> shift) & 255n)).join('.')));
}
export function validOrigin(input) {
  const text = String(input ?? '').trim();
  if (!text || text.length > 200 || /[\s'"<>\\`$;|&]/.test(text)) return null;
  let url;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || (url.pathname && url.pathname !== '/') || !url.port) return null;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (blockedOriginHost(host)) return null;
  const local = host === 'localhost' || host === '::1' || host === 'host.docker.internal' || PRIVATE_V4.test(host)
    || /^(?:fc|fd)[0-9a-f]{2}:/i.test(host);
  return local ? `${url.protocol}//${url.host}` : null;
}

