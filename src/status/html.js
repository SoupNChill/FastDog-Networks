function escape(value) {
  return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
}

export function renderStatus(data) {
  const rows = data.checks.map((check) => `<tr><th scope="row">${escape(check.name)}</th><td><span class="badge ${escape(check.status)}">${escape(check.status)}</span></td><td>${check.latencyMs == null ? '—' : `${escape(check.latencyMs)} ms`}</td><td>${escape(check.detail)}</td></tr>`).join('\n');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Fastdog public PoP status</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:850px;margin:3rem auto;padding:0 1rem;color:#17212b;background:#f8fafc}h1{margin-bottom:.25rem}p{color:#475569}.badge{display:inline-block;border-radius:999px;padding:.2rem .7rem;font-weight:700;text-transform:capitalize}.green{color:#14532d;background:#dcfce7}.yellow{color:#713f12;background:#fef08a}.red{color:#7f1d1d;background:#fecaca}table{width:100%;border-collapse:collapse;background:white}th,td{padding:.8rem;text-align:left;border-bottom:1px solid #dbe2ea}th{white-space:nowrap}td:last-child{overflow-wrap:anywhere}time{font-variant-numeric:tabular-nums}@media(max-width:600px){table{font-size:.85rem}th,td{padding:.45rem}}</style></head>
<body><main><h1>Fastdog public PoP status</h1><p>Edge HTTPS and authoritative DNS checks for Fastdog public PoPs.</p><p>Overall: <span class="badge ${escape(data.overall)}">${escape(data.overall)}</span></p><p>Last checked: <time datetime="${escape(data.lastChecked)}">${escape(data.lastChecked)}</time></p><table><thead><tr><th>Service</th><th>Status</th><th>Latency</th><th>Detail</th></tr></thead><tbody>${rows}</tbody></table><p><a href="/status?refresh=1">Refresh checks</a> · <a href="/status.json">JSON</a></p></main></body></html>`;
}
