import https from 'node:https';
import { createHash } from 'node:crypto';

const ALLOWED = Object.freeze({
  LOOKUP: Object.freeze(['domain']),
  GET_PRICE: Object.freeze(['domain', 'period', 'reg_type']),
});
const TIMEOUT = 8_000;
const MAX_RESPONSE = 1_048_576;
const escapeXml = (value) => String(value).replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&apos;',
})[c]);
const unescapeXml = (value) => value.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi,
  (_, entity) => entity[0] === '#'
    ? String.fromCodePoint(entity[1].toLowerCase() === 'x'
      ? parseInt(entity.slice(2), 16) : Number(entity.slice(1)))
    : ({ amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" })[entity]);
const md5 = (value) => createHash('md5').update(value, 'utf8').digest('hex');

function envelope(action, object, attributes) {
  const items = Object.entries({ protocol: 'XCP', action, object }).map(([key, value]) =>
    `<item key="${escapeXml(key)}">${escapeXml(value)}</item>`).join('');
  const attrs = Object.entries(attributes).map(([key, value]) =>
    `<item key="${escapeXml(key)}">${escapeXml(value)}</item>`).join('');
  return "<?xml version='1.0' encoding='UTF-8' standalone='no' ?>\n"
    + "<!DOCTYPE OPS_envelope SYSTEM 'ops.dtd'>\n"
    + '<OPS_envelope><header><version>0.9</version></header><body><data_block><dt_assoc>'
    + items + `<item key="attributes"><dt_assoc>${attrs}</dt_assoc></item>`
    + '</dt_assoc></data_block></body></OPS_envelope>';
}

// This deliberately supports only the OPS tree, never DTD/entity resolution.
function parseEnvelope(xml) {
  if (typeof xml !== 'string' || Buffer.byteLength(xml) > MAX_RESPONSE) throw new Error();
  const source = xml.replace(/^\s*<\?xml[^?]*\?>\s*/, '')
    .replace(/^\s*<!DOCTYPE OPS_envelope SYSTEM ['"]ops\.dtd['"]>\s*/, '');
  const tokens = source.match(/<[^>]*>|[^<]+/g) || [];
  let position = 0;
  function node(depth = 0) {
    if (depth > 32) throw new Error();
    const opening = tokens[position++]?.match(/^<(\w+)(?:\s+key=(?:"([^"]*)"|'([^']*)'))?\s*(\/?)>$/);
    if (!opening) throw new Error();
    const [, tag, doubleKey, singleKey, closed] = opening;
    const result = { tag, key: unescapeXml(doubleKey ?? singleKey ?? ''), children: [], text: '' };
    if (closed) return result;
    while (position < tokens.length && tokens[position] !== `</${tag}>`) {
      if (tokens[position].startsWith('<')) result.children.push(node(depth + 1));
      else result.text += unescapeXml(tokens[position++]);
    }
    if (tokens[position++] !== `</${tag}>`) throw new Error();
    return result;
  }
  function decode(tree) {
    if (tree.tag === 'item') {
      if (tree.children.length > 1) throw new Error();
      return tree.children.length ? decode(tree.children[0]) : tree.text;
    }
    if (!['dt_assoc', 'dt_array'].includes(tree.tag) || tree.text.trim()) throw new Error();
    const result = tree.tag === 'dt_array' ? [] : {};
    for (const item of tree.children) {
      if (item.tag !== 'item' || Object.hasOwn(result, item.key)) throw new Error();
      if (Array.isArray(result) && !/^(0|[1-9]\d{0,4})$/.test(item.key)) throw new Error();
      Object.defineProperty(result, item.key, { value: decode(item), enumerable: true });
    }
    return result;
  }
  const root = node();
  if (root.tag !== 'OPS_envelope' || tokens.slice(position).join('').trim()) throw new Error();
  const bodies = root.children.filter((child) => child.tag === 'body');
  const blocks = bodies[0]?.children.filter((child) => child.tag === 'data_block');
  if (bodies.length !== 1 || blocks?.length !== 1 || blocks[0].children.length !== 1) throw new Error();
  return decode(blocks[0].children[0]);
}

function transportHttps({ body, timeout, ...options }) {
  return new Promise((resolve, reject) => {
    const request = https.request(options, (response) => {
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > MAX_RESPONSE) request.destroy(new Error());
        else chunks.push(chunk);
      });
      response.on('error', reject);
      response.on('end', () => {
        if (response.statusCode !== 200) reject(new Error());
        else resolve(Buffer.concat(chunks).toString('utf8'));
      });
    });
    // A wall-clock deadline also bounds slow responses and connection setup.
    const timer = setTimeout(() => request.destroy(new Error()), timeout);
    request.on('close', () => clearTimeout(timer));
    request.on('error', reject);
    request.end(body);
  });
}

export function createRegistrar({ transport = transportHttps } = {}) {
  async function call(action, object, attributes) {
    // Validate before credentials, serialization, signing, or transport.
    const allowed = Object.hasOwn(ALLOWED, action) && ALLOWED[action];
    if (!allowed || object !== 'DOMAIN' || !attributes || typeof attributes !== 'object'
      || Reflect.ownKeys(attributes).length !== allowed.length
      || Reflect.ownKeys(attributes).some((key) => !allowed.includes(key))
      || allowed.some((key) => !Object.hasOwn(attributes, key) || typeof attributes[key] !== 'string')
      || !attributes.domain
      || (action === 'GET_PRICE' && (attributes.period !== '1'
        || !['new', 'renewal'].includes(attributes.reg_type)))) {
      throw new Error('Request not allowed');
    }
    try {
      const username = process.env.REGISTRAR_USERNAME || process.env.OPENSRS_USERNAME;
      const key = process.env.REGISTRAR_API_KEY || process.env.OPENSRS_API_KEY;
      if (!username || !key) throw new Error();
      const body = envelope(action, object, attributes);
      const response = await transport({
        hostname: process.env.REGISTRAR_HOST || 'rr-n1-tor.opensrs.net',
        port: 55443, path: '/', method: 'POST', timeout: TIMEOUT,
        headers: {
          'Content-Type': 'text/xml',
          'Content-Length': Buffer.byteLength(body),
          'X-Username': username,
          'X-Signature': md5(md5(body + key) + key),
        },
        body,
      });
      return parseEnvelope(response);
    } catch {
      throw new Error('Upstream unavailable');
    }
  }
  return Object.freeze({
    lookup: (domain) => call('LOOKUP', 'DOMAIN', { domain }),
    getPrice: (domain, regType) => call('GET_PRICE', 'DOMAIN', { domain, period: '1', reg_type: regType }),
    _callForTest: call,
  });
}

export const { lookup, getPrice } = createRegistrar();
