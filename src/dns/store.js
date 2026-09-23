import fs from 'node:fs';
import path from 'node:path';
import { ROOT, env } from '../lib/config.js';

export function zonesDir() {
  const d = env('ZONES_DIR', path.join(ROOT, 'zones'));
  return path.isAbsolute(d) ? d : path.join(ROOT, d);
}

export function listZones() {
  const dir = zonesDir();
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((f) => f.endsWith('.json'))
    .map((f) => f.replace(/\.json$/, ''));
}

export function readZone(zone) {
  const file = path.join(zonesDir(), `${zone}.json`);
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

export function writeZone(zone, data) {
  const dir = zonesDir();
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, `${zone}.json`);
  const payload = {
    ...data,
    zone,
    updated_at: new Date().toISOString(),
  };
  fs.writeFileSync(file, `${JSON.stringify(payload, null, 2)}\n`, 'utf8');
  return payload;
}

export function upsertRecord(zone, record) {
  const data = readZone(zone) || { zone, ttl_default: 300, records: [] };
  if (!Array.isArray(data.records)) data.records = [];
  const idx = data.records.findIndex(
    (r) => r.name === record.name && r.type === record.type && r.content === record.content,
  );
  if (idx >= 0) data.records[idx] = { ...data.records[idx], ...record };
  else data.records.push(record);
  return writeZone(zone, data);
}

/**
 * Delete records matching name + type (and content if provided).
 */
export function deleteRecord(zone, { name, type, content } = {}) {
  const data = readZone(zone);
  if (!data) return null;
  if (!name || !type) {
    const err = new Error('name and type required to delete');
    err.status = 400;
    throw err;
  }
  data.records = (data.records || []).filter((r) => {
    if (r.name !== name || r.type !== type) return true;
    if (content !== undefined && content !== null && r.content !== content) return true;
    return false; // match -> drop
  });
  return writeZone(zone, data);
}

/** Export zone as BIND-ish zone file text (for later CoreDNS/PowerDNS feed). */
export function exportBind(zone) {
  const data = readZone(zone);
  if (!data) return null;
  const lines = [
    `; Fastdog Edge zone export — ${zone}`,
    `; generated ${new Date().toISOString()}`,
    `$ORIGIN ${zone}.`,
    `$TTL ${data.ttl_default || 300}`,
    '',
  ];
  for (const r of data.records || []) {
    const owner = r.name === '@' ? '@' : r.name;
    const ttl = r.ttl || data.ttl_default || 300;
    let content = r.content;
    if (r.type === 'TXT' && !content.startsWith('"')) {
      content = `"${content.replace(/"/g, '\\"')}"`;
    }
    lines.push(`${owner}\t${ttl}\tIN\t${r.type}\t${content}`);
  }
  lines.push('');
  return lines.join('\n');
}
