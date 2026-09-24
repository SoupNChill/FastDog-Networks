import { execFile } from 'node:child_process';
import { performance } from 'node:perf_hooks';

function result(status, latencyMs, detail) {
  return { status, latencyMs: Math.round(latencyMs), detail };
}

async function httpGet(url, timeoutMs) {
  const started = performance.now();
  try {
    const response = await fetch(url, { method: 'GET', signal: AbortSignal.timeout(timeoutMs) });
    await response.body?.cancel();
    return { code: response.status, latencyMs: performance.now() - started };
  } catch (error) {
    return { error: error.message, latencyMs: performance.now() - started };
  }
}

export async function probeEdge(url, timeoutMs) {
  const first = await httpGet(url, timeoutMs);
  if (first.code >= 200 && first.code < 300) {
    return result(first.latencyMs > 1500 ? 'yellow' : 'green', first.latencyMs, `HTTP ${first.code}`);
  }
  // Older edge deployments may have no /health endpoint.
  if ((first.code === 404 || first.code === 405) && new URL(url).pathname === '/health') {
    const fallback = await httpGet(new URL('/', url), timeoutMs);
    if (fallback.code >= 200 && fallback.code < 300) return result('yellow', fallback.latencyMs, `HTTP ${first.code} at /health; / returned HTTP ${fallback.code}`);
    return result(fallback.code ? 'yellow' : 'red', fallback.latencyMs, fallback.code ? `HTTP ${first.code} at /health; / returned HTTP ${fallback.code}` : `HTTP ${first.code} at /health; / failed: ${fallback.error}`);
  }
  return result(first.code ? 'yellow' : 'red', first.latencyMs, first.code ? `HTTP ${first.code}` : first.error);
}

export function probeDns(ip, zone, timeoutMs) {
  return new Promise((resolve) => {
    const started = performance.now();
    execFile('dig', [`@${ip}`, zone, 'SOA', '+comments', '+answer', '+tries=1', `+time=${Math.max(1, Math.ceil(timeoutMs / 1000))}`],
      { timeout: timeoutMs, maxBuffer: 64 * 1024 }, (error, stdout) => {
        const latency = performance.now() - started;
        if (error) return resolve(result('red', latency, error.killed ? 'DNS probe timed out' : error.message));
        const header = stdout.match(/;; ->>HEADER<<-.*status: (\w+)/);
        const flags = stdout.match(/;; flags: ([^;]+);/);
        const hasAnswer = stdout.split('\n').some((line) => line && !line.startsWith(';') && /\sSOA\s/.test(line));
        if (!header || header[1] !== 'NOERROR' || !hasAnswer) return resolve(result('red', latency, `DNS ${header?.[1] || 'no response'}${hasAnswer ? '' : '; no SOA answer'}`));
        const authoritative = flags?.[1].split(/\s+/).includes('aa');
        resolve(result(authoritative ? 'green' : 'yellow', latency, authoritative ? 'NOERROR; authoritative SOA' : 'NOERROR; SOA response without AA'));
      });
  });
}
