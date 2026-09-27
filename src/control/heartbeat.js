import { touch } from './tunnels.js';

export function watchTunnel(ws, agentId, { intervalMs = 20000, staleMs = 60000, now = Date.now } = {}) {
  let lastFrame = now();
  const onMessage = (data) => {
    lastFrame = now();
    touch(agentId);
    try {
      if (JSON.parse(String(data)).type === 'ping' && ws.readyState === 1) ws.send(JSON.stringify({ type: 'pong' }));
    } catch { /* Other v0 frames still count as activity. */ }
  };
  const timer = setInterval(() => {
    if (ws.readyState === 1 && now() - lastFrame > staleMs) ws.terminate();
  }, intervalMs);
  timer.unref?.();
  const stop = () => { clearInterval(timer); ws.off('message', onMessage); };
  ws.on('message', onMessage);
  ws.once('close', stop);
  ws.once('error', stop);
  return stop;
}
