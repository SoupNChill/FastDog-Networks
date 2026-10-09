import http from 'node:http';
import https from 'node:https';
import { fail, statuses } from './errors.js';

export function jsonClient({ baseUrl, headers = {}, timeout = 5000, errorMap = {} }) {
  const base = new URL(baseUrl);
  if (!['http:', 'https:'].includes(base.protocol) || base.username || base.password || base.search || base.hash) throw new Error('Invalid service URL');
  return (path, method = 'GET', body) => new Promise((resolve, reject) => {
    const target = new URL(path, base);
    const transport = target.protocol === 'https:' ? https : http;
    const payload = body === undefined ? undefined : JSON.stringify(body);
    const request = transport.request(target, { method, headers: { ...headers, Accept: 'application/json',
      ...(payload === undefined ? {} : { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }) } }, (response) => {
      let size = 0;
      const chunks = [];
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 1024 * 1024) request.destroy(fail('internal_error'));
        else chunks.push(chunk);
      });
      response.on('error', () => reject(fail('internal_error')));
      response.on('end', () => {
        try {
          const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
          if (!data || typeof data !== 'object' || Array.isArray(data)) throw fail('internal_error');
          if (response.statusCode >= 200 && response.statusCode < 300 && !data.error) return resolve(data);
          const mapped = Object.hasOwn(errorMap, data.error) ? errorMap[data.error] : data.error;
          const code = Object.hasOwn(statuses, mapped) ? mapped : 'internal_error';
          const seconds = Number(data.retry_after ?? response.headers['retry-after']);
          reject(fail(code, code === 'rate_limited' ? (Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : 60) : undefined));
        } catch { reject(fail('internal_error')); }
      });
    });
    const timer = setTimeout(() => request.destroy(fail('internal_error')), timeout);
    request.on('close', () => clearTimeout(timer));
    request.on('error', () => reject(fail('internal_error')));
    request.end(payload);
  });
}
