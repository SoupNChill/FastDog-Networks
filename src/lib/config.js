import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ROOT = path.resolve(__dirname, '../..');

export function env(name, fallback) {
  const v = process.env[name];
  return v === undefined || v === '' ? fallback : v;
}

export function loadRoutes(filePath = env('ROUTES_FILE', path.join(ROOT, 'config/routes.yaml'))) {
  const abs = path.isAbsolute(filePath) ? filePath : path.join(ROOT, filePath);
  const raw = fs.readFileSync(abs, 'utf8');
  let data;
  if (abs.endsWith('.json')) {
    data = JSON.parse(raw);
  } else {
    data = require('js-yaml').load(raw) || {};
  }
  const routes = data.routes || data || {};
  const map = new Map();
  for (const [host, upstream] of Object.entries(routes)) {
    if (typeof upstream === 'string') {
      map.set(host.toLowerCase(), upstream.replace(/\/$/, ''));
    }
  }
  const tunnelHosts = new Set(
    (data.tunnel_hosts || []).map((h) => String(h).toLowerCase()),
  );
  const dataDir = env('DATA_DIR', path.join(ROOT, 'data'));
  const hostsFile = path.join(path.isAbsolute(dataDir) ? dataDir : path.join(ROOT, dataDir), 'tunnel_hosts.json');
  if (fs.existsSync(hostsFile)) {
    for (const host of JSON.parse(fs.readFileSync(hostsFile, 'utf8'))) tunnelHosts.add(String(host).toLowerCase());
  }
  return { file: abs, routes: map, tunnelHosts };
}

export function defaultUpstream() {
  return env('DEFAULT_UPSTREAM', 'http://127.0.0.1:9999').replace(/\/$/, '');
}

export function reservedSuffixes(attachTarget, altAttachTarget, configured = process.env.RESERVED_SUFFIXES) {
  if (configured !== undefined) return configured.split(',').map((s) => s.trim().toLowerCase().replace(/\.$/, '')).filter(Boolean);
  // Reserving the final two labels is conservative for multi-label public suffixes.
  const domains = [attachTarget, altAttachTarget].filter(Boolean).map((host) => host.toLowerCase().replace(/\.$/, '').split('.').slice(-2).join('.'));
  return [...new Set([...domains, 'localhost', 'local', 'lan', 'internal', 'test', 'invalid', 'example'])];
}
