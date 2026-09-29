// The public edge exposes /health. Read only the fields needed for the display.
const signals = {
  edge: document.querySelector('[data-signal="edge"]'),
  tunnel: document.querySelector('[data-signal="tunnel"]'),
  tls: document.querySelector('[data-signal="tls"]'),
};
const note = document.querySelector('#status-note');

function show(name, state, label) {
  const item = signals[name];
  item.classList.remove('healthy', 'unhealthy', 'unknown');
  item.classList.add(state);
  item.querySelector('strong').textContent = label;
}

async function check() {
  const timeout = AbortSignal.timeout(5000);
  try {
    // Relative URL keeps the request same-origin when mounted at /www/.
    const response = await fetch('/health', { signal: timeout, cache: 'no-store', credentials: 'omit' });
    if (!response.ok) throw new Error('health unavailable');
    const health = await response.json();
    const edgeUp = health.ok === true;
    show('edge', edgeUp ? 'healthy' : 'unhealthy', edgeUp ? 'Up' : 'Down');
    show('tunnel', edgeUp && Number(health.agents) >= 1 ? 'healthy' : 'unhealthy', edgeUp && Number(health.agents) >= 1 ? 'Connected' : 'None reported');
    const secure = location.protocol === 'https:';
    show('tls', secure ? 'healthy' : 'unknown', secure ? 'HTTPS' : 'Local preview');
    note.textContent = 'Checked just now via /health. Tunnel signal reflects the edge agent count.';
  } catch {
    show('edge', 'unknown', 'Unavailable');
    show('tunnel', 'unknown', 'Unknown');
    show('tls', 'unknown', 'Unknown');
    note.textContent = 'Live check unavailable in this preview. No status is inferred.';
  }
}

check();
