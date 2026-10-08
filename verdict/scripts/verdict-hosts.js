#!/usr/bin/env node
const base = process.env.VERDICT_URL || 'http://127.0.0.1:8089';
const key = process.env.VERDICT_API_KEY;
if (!key) { console.error('VERDICT_API_KEY required'); process.exit(1); }
const [cmd, host, ...rest] = process.argv.slice(2);
async function api(method, path, body) {
  const res = await fetch(base + path, {
    method,
    headers: { Authorization: `Bearer ${key}`, 'Content-Type': 'application/json', Accept: 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json; try { json = JSON.parse(text); } catch { json = { raw: text }; }
  if (!res.ok) { console.error(JSON.stringify(json)); process.exit(res.status); }
  console.log(JSON.stringify(json, null, 2));
}
if (cmd === 'list') await api('GET', '/v1/hosts');
else if (cmd === 'get' && host) await api('GET', `/v1/hosts/${encodeURIComponent(host)}`);
else if (cmd === 'set' && host) {
  const body = {};
  for (const arg of rest) {
    const [k, v] = arg.split('=');
    if (k === 'enable') body.enable = v === '1' || v === 'true';
    else if (k === 'mode') body.mode = v;
    else if (k === 'fail') body.fail = v;
    else if (k === 'difficulty') body.difficulty = Number(v);
  }
  await api('PUT', `/v1/hosts/${encodeURIComponent(host)}`, body);
}
else if (cmd === 'delete' && host) await api('DELETE', `/v1/hosts/${encodeURIComponent(host)}`);
else {
  console.error('Usage: verdict-hosts.js list|get <host>|set <host> enable=1 mode=shadow fail=open|delete <host>');
  process.exit(2);
}
