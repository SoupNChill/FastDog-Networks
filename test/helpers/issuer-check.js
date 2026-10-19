// Loopback issuer-check fixture: the portal's real listener (portal/src/issuer-check.js) with an injected validator,
// so edge tests exercise the authenticated request/reply protocol. The secret is random per test and never logged.
import { randomBytes } from 'node:crypto';
import { once } from 'node:events';
import { createIssuerCheckServer, ISSUER_CHECK_PATH } from '../../portal/src/issuer-check.js';

export async function issuerCheckFixture(t, { validate = () => true, now } = {}) {
  const secret = randomBytes(32).toString('hex');
  const seen = [];
  const server = createIssuerCheckServer({ secret, now, validate: (issuer) => { seen.push(issuer); return validate(issuer); } });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(() => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }));
  return { secret, seen, server, url: `http://127.0.0.1:${server.address().port}${ISSUER_CHECK_PATH}` };
}
