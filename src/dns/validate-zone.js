import { env } from '../lib/config.js';

function expectedNsHosts() {
  return [
    env('NS1_HOST', 'ns1.fastdognetworks.com'),
    env('NS2_HOST', 'ns2.fastdognetworks.com'),
  ].map((h) => h.replace(/\.$/, '').toLowerCase());
}

function normalizeNs(value) {
  return String(value || '').trim().replace(/\.$/, '').toLowerCase();
}

/** Validate zone JSON ({ records: [...] }) or BIND zone text. */
export function validateZone(input, { zone } = {}) {
  const errors = [];
  let records = [];

  if (input == null) {
    return { ok: false, errors: ['empty_zone'] };
  }

  if (typeof input === 'object' && !Buffer.isBuffer(input)) {
    records = Array.isArray(input.records) ? input.records : [];
    if (!records.length) errors.push('empty_zone');
  } else {
    const text = String(input);
    if (!text.trim()) {
      return { ok: false, errors: ['empty_zone'] };
    }
    for (const raw of text.split(/\r?\n/)) {
      const line = raw.replace(/;.*$/, '').trim();
      if (!line || line.startsWith('$')) continue;
      const parts = line.split(/\s+/);
      if (parts.length < 3) continue;
      let idx = 1;
      if (/^\d+$/.test(parts[1])) idx = 2;
      if (parts[idx]?.toUpperCase() === 'IN') idx += 1;
      const type = parts[idx]?.toUpperCase();
      const content = parts.slice(idx + 1).join(' ');
      if (type) records.push({ name: parts[0], type, content });
    }
    if (!records.length) errors.push('empty_zone');
  }

  const hasSoa = records.some((r) => String(r.type).toUpperCase() === 'SOA');
  const nsRecords = records.filter((r) => String(r.type).toUpperCase() === 'NS');
  if (!hasSoa) errors.push('missing_soa');
  if (!nsRecords.length) errors.push('missing_ns');

  const present = new Set(nsRecords.map((r) => normalizeNs(r.content)));
  for (const host of expectedNsHosts()) {
    if (!present.has(host)) errors.push('missing_ns:' + host);
  }

  if (zone) {
    const originHint = String(zone).replace(/\.$/, '').toLowerCase();
    if (typeof input === 'string' && input.includes('$ORIGIN')) {
      const m = input.match(/\$ORIGIN\s+([^\s;]+)/i);
      if (m && normalizeNs(m[1]) !== originHint) {
        errors.push('origin_mismatch:' + normalizeNs(m[1]));
      }
    }
  }

  return errors.length ? { ok: false, errors } : { ok: true, errors: [], record_count: records.length };
}