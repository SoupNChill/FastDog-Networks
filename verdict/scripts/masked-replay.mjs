#!/usr/bin/env node
// Compare shadow scoring of the same unmasked access-log lines raw vs converted to the masked format
// written by the Caddy filter encoder. Usage: node masked-replay.mjs <raw|masked> <maxLines> <log>...
// Run each mode in its own process (heuristic velocity state is module-level). Prints counts only.
import { readFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { loadHostingAsns } from '../src/asn/lookup.js';
import { scoreAccessLogLine } from '../src/shadow/score.js';

const [mode, maxArg, ...logs] = process.argv.slice(2);
const maxLines = Number(maxArg);
if (!['raw', 'masked'].includes(mode) || !Number.isInteger(maxLines) || maxLines < 1 || !logs.length) {
  console.error('usage: node masked-replay.mjs <raw|masked> <maxLines> <log>...');
  process.exit(2);
}

// Same output shape as Caddy's ip_mask: IPv4 /24 "a.b.c.0", IPv6 /48 "x:y:z::".
function maskIp(ip) {
  if (isIP(ip) === 4) return ip.split('.').slice(0, 3).join('.') + '.0';
  if (isIP(ip) !== 6) return '';
  const value = ip.toLowerCase().split('%')[0];
  const [left, right] = value.split('::');
  const a = left ? left.split(':') : [], b = right ? right.split(':') : [];
  const words = (right !== undefined ? [...a, ...Array(8 - a.length - b.length).fill('0'), ...b] : a).slice(0, 3).map(x => parseInt(x, 16));
  while (words.length && words[words.length - 1] === 0) words.pop();
  return words.map(x => x.toString(16)).join(':') + '::';
}

function maskRow(row) {
  const req = { ...row.request };
  const ua = req.headers?.['User-Agent']?.[0] ?? req.headers?.['user-agent']?.[0];
  req.client_ip = maskIp(req.client_ip || req.remote_ip || '');
  for (const k of ['remote_ip', 'remote_port', 'proto', 'headers', 'cookies', 'tls']) delete req[k];
  if (typeof req.uri === 'string') req.uri = req.uri.split('?')[0];
  const out = { ...row, request: req };
  for (const k of Object.keys(out)) if (['resp_headers', 'size', 'bytes_read', 'user_id'].includes(k) || k.startsWith('err_')) delete out[k];
  for (const k of Object.keys(req)) if (k.startsWith('err_')) delete req[k];
  if (ua !== undefined) out.user_agent = ua;
  return out;
}

const hosting = loadHostingAsns();
const actions = { allow: 0, challenge: 0, block: 0 };
let scored = 0;
for (const log of logs) {
  const rows = [];
  for (const line of (await readFile(log, 'utf8')).split('\n')) {
    if (!line.trim()) continue;
    let row;
    try { row = JSON.parse(line); } catch { continue; }
    if (row?.request?.headers && typeof row.request.headers === 'object') rows.push(row);
  }
  for (const row of rows.slice(-maxLines)) {
    const result = await scoreAccessLogLine(mode === 'masked' ? maskRow(row) : row, { hosting, verifyBot: () => null });
    if (!result) continue;
    scored++;
    actions[result.action] = (actions[result.action] || 0) + 1;
  }
}
console.log(JSON.stringify({ mode, scored, actions }));
