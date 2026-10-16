import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApp } from './src/app.js';
import { createEdgeClient } from './src/edge-client.js';
import { createDomainClient } from './src/domain-client.js';
import { createFileMailer } from './src/mailer-file.js';

export function start(env = process.env) {
  const port = Number(env.PORTAL_PORT || 8790);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid portal port');
  if (!env.STATE_DIRECTORY || !env.PORTAL_ORIGIN) throw new Error('State directory and portal origin required');
  const dataDir = resolve(env.STATE_DIRECTORY);
  const outboxDir = env.OUTBOX_DIR ? resolve(env.OUTBOX_DIR) : join(dataDir, 'outbox');
  const app = createApp({ dataDir,
    edge: createEdgeClient({ baseUrl: env.EDGE_INTERNAL_URL || 'http://127.0.0.1:8789', portalKey: env.PORTAL_KEY }),
    domainSearch: createDomainClient({ baseUrl: env.DOMAIN_SEARCH_URL || 'http://127.0.0.1:8791' }),
    mailer: createFileMailer({ outboxDir }),
    config: { origin: env.PORTAL_ORIGIN, edgeUrl: env.PORTAL_EDGE_URL, outboxDir, trustProxy: env.TRUST_PROXY === '1',
      defaultPlan: env.DEFAULT_PLAN || 'assigned', defaultHostnameLimit: Number(env.DEFAULT_HOSTNAME_LIMIT || 3),
      logger: (entry) => console.log(JSON.stringify(entry)) },
  });
  app.listen(port, '127.0.0.1');
  return app;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { start(); } catch { process.stderr.write('Portal configuration is invalid. Check the documented settings.\n'); process.exitCode = 1; }
}
