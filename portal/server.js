import { resolve, join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createApp } from './src/app.js';
import { createEdgeClient } from './src/edge-client.js';
import { createDomainClient } from './src/domain-client.js';
import { createFileMailer, scheduleOutboxPurge } from './src/mailer-file.js';
import { createSmtpMailer } from './src/mailer-smtp.js';
import { supportEmail } from './src/static.js';
import { createStore } from './src/store.js';
import { createIssuerCheckServer } from './src/issuer-check.js';
import { createIssuerValidator } from './src/agent-bootstrap.js';

const logJson = (entry) => console.log(JSON.stringify(entry));
// MAIL_TRANSPORT=file (default) queues private outbox files; smtp submits via STARTTLS and retains redacted audit records.
// Errors are deliberately generic so configured values (including credentials) never reach logs.
export function selectMailer(env, { outboxDir, logger = logJson, tlsOptions } = {}) {
  const transport = env.MAIL_TRANSPORT || 'file';
  if (transport !== 'file' && transport !== 'smtp') throw new Error('Invalid mail configuration');
  const outbox = createFileMailer({ outboxDir, logger });
  if (transport === 'file') return outbox;
  const integer = (value, fallback) => (value === undefined || value === '' ? fallback : /^\d{1,6}$/.test(value) ? Number(value) : NaN);
  const replyTo = env.MAIL_REPLY_TO || (env.PORTAL_SUPPORT_EMAIL ? supportEmail(env) : undefined);
  return createSmtpMailer({ host: env.SMTP_HOST, port: integer(env.SMTP_PORT, 2525), user: env.SMTP_USER, pass: env.SMTP_PASS,
    from: env.MAIL_FROM || 'noreply@example.invalid', replyTo, maxPerHour: integer(env.MAIL_MAX_PER_HOUR, 300),
    fallback: outbox, logger, tlsOptions });
}

export function start(env = process.env) {
  const port = Number(env.PORTAL_PORT || 8790);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid portal port');
  if (!env.STATE_DIRECTORY || !env.PORTAL_ORIGIN) throw new Error('State directory and portal origin required');
  const dataDir = resolve(env.STATE_DIRECTORY);
  const outboxDir = env.OUTBOX_DIR ? resolve(env.OUTBOX_DIR) : join(dataDir, 'outbox');
  const mailer = selectMailer(env, { outboxDir });

  // Agent bootstrap is off unless PORTAL_AGENT_BOOTSTRAP_ENABLED=1. The issuer-check listener additionally needs its own
  // per-environment PORTAL_ISSUER_CHECK_KEY (never PORTAL_KEY) and binds loopback only; without the key the edge's checks
  // fail closed.
  const agentBootstrap = env.PORTAL_AGENT_BOOTSTRAP_ENABLED === '1';
  const issuerCheckKey = agentBootstrap ? env.PORTAL_ISSUER_CHECK_KEY : undefined;
  const issuerCheckPort = Number(env.PORTAL_ISSUER_CHECK_PORT || 8792);
  if (issuerCheckKey !== undefined && (issuerCheckKey.length < 32 || issuerCheckKey === env.PORTAL_KEY || !Number.isInteger(issuerCheckPort) || issuerCheckPort < 1 || issuerCheckPort > 65535 || issuerCheckPort === port)) {
    throw new Error('Invalid issuer check configuration');
  }
  const app = createApp({ dataDir,
    edge: createEdgeClient({ baseUrl: env.EDGE_INTERNAL_URL || 'http://127.0.0.1:8789', portalKey: env.PORTAL_KEY }),
    domainSearch: createDomainClient({ baseUrl: env.DOMAIN_SEARCH_URL || 'http://127.0.0.1:8791' }),
    mailer,
    config: { origin: env.PORTAL_ORIGIN, edgeUrl: env.PORTAL_EDGE_URL, docsUrl: env.PORTAL_DOCS_URL, outboxDir, trustProxy: env.TRUST_PROXY === '1',
      defaultPlan: env.DEFAULT_PLAN || 'assigned', defaultHostnameLimit: Number(env.DEFAULT_HOSTNAME_LIMIT || 3),
      openSignup: env.OPEN_SIGNUP === '1', openSignupPlan: env.OPEN_SIGNUP_PLAN || 'trial',
      openSignupHostnameLimit: Number(env.OPEN_SIGNUP_HOSTNAME_LIMIT || 1), openConnectTokensPerHour: Number(env.OPEN_CONNECT_TOKENS_PER_HOUR || 3),
      signupIpPerHour: Number(env.SIGNUP_IP_PER_HOUR || 3), signupDomainPerDay: Number(env.SIGNUP_DOMAIN_PER_DAY || 5),
      signupBigmailPerDay: Number(env.SIGNUP_BIGMAIL_PER_DAY || 200), signupGlobalPerDay: Number(env.SIGNUP_GLOBAL_PER_DAY || 100),
      logger: logJson, ...(agentBootstrap ? { agentBootstrap: true } : {}) },
  });
  const purgeTimer = scheduleOutboxPurge(outboxDir);
  app.once('close', () => clearInterval(purgeTimer));
  if (issuerCheckKey !== undefined) {
    const issuerCheck = createIssuerCheckServer({ secret: issuerCheckKey, validate: createIssuerValidator({ store: createStore(dataDir) }), logger: logJson });
    app.once('close', () => issuerCheck.close());
    issuerCheck.listen(issuerCheckPort, '127.0.0.1');
  }
  app.listen(port, '127.0.0.1');
  return app;
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  try { start(); } catch { process.stderr.write('Portal configuration is invalid. Check the documented settings.\n'); process.exitCode = 1; }
}
