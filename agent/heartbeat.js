export function startHeartbeat(ws, { intervalMs = 20000, maxMissed = 2 } = {}) {
  let awaiting = 0;
  const onMessage = (data) => {
    try { if (JSON.parse(String(data)).type === 'pong') awaiting = 0; }
    catch { /* Ignore malformed frames. */ }
  };
  const timer = setInterval(() => {
    if (ws.readyState !== 1) return;
    if (awaiting >= maxMissed) { ws.terminate(); return; }
    awaiting += 1;
    ws.send(JSON.stringify({ type: 'ping' }));
  }, intervalMs);
  timer.unref?.();
  const stop = () => { clearInterval(timer); ws.off('message', onMessage); };
  ws.on('message', onMessage);
  ws.once('close', stop);
  ws.once('error', stop);
  return stop;
}
