// Enhance the capture only after a successful same-origin health check.
(() => {
  const result = document.querySelector('#proof-result');
  const note = document.querySelector('#proof-note');
  if (!result || !note || location.protocol !== 'https:') return;

  async function check() {
    try {
      const started = performance.now();
      const response = await fetch('/health', {
        cache: 'no-store',
        credentials: 'omit',
        signal: AbortSignal.timeout(4000),
      });
      const health = await response.json();
      if (!response.ok || health.ok !== true) throw new Error('Unavailable');
      const elapsed = Math.round(performance.now() - started);
      const label = document.createElement('p');
      label.className = 'readout-label healthy';
      label.textContent = 'Live · same-origin health check';
      const readout = document.createElement('pre');
      readout.className = 'readout';
      readout.textContent = `GET https://${location.host}/health\n${response.status}  {"ok":true}  · ${elapsed} ms from your browser · checked ${new Date().toLocaleTimeString()}`;
      const detail = document.createElement('p');
      detail.className = 'small-note';
      detail.textContent = 'A point-in-time response from this edge, measured from your browser.';
      result.replaceChildren(label, readout, detail);
    } catch {
      note.textContent = 'Live check unavailable here; showing the capture above.';
    }
  }
  check();
})();
