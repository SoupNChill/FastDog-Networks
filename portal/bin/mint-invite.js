import { resolve, join } from 'node:path';
import { createInvites } from '../src/invites.js';
import { normalizeEmail } from '../src/tokens.js';
import { selectMailer } from '../server.js';
const args = process.argv.slice(2);
const sendMail = args.includes('--send');
const [email, plan, limit, expiresAt] = args.filter((arg) => arg !== '--send');
try {
  if (!email || !process.env.STATE_DIRECTORY || (sendMail && !/^https:\/\/[A-Za-z0-9.:-]+$/.test(process.env.PORTAL_ORIGIN || ''))) throw new Error('Arguments required');
  // Build the mailer first so invalid mail settings fail before an invite is minted.
  const mailer = sendMail && selectMailer(process.env, {
    outboxDir: process.env.OUTBOX_DIR ? resolve(process.env.OUTBOX_DIR) : join(resolve(process.env.STATE_DIRECTORY), 'outbox'),
    logger: (entry) => process.stderr.write(`${JSON.stringify(entry)}\n`) });
  const code = createInvites({ dataDir: process.env.STATE_DIRECTORY }).mint({
    email, plan, hostnameLimit: limit === undefined ? undefined : Number(limit), expiresAt,
  });
  if (!mailer) process.stdout.write(`${code}\n`);
  else {
    // --send never prints the code; on fallback it stays in the private outbox.
    const result = await mailer.send({ to: normalizeEmail(email), kind: 'invite', link: `${process.env.PORTAL_ORIGIN}/signup`, code });
    process.stdout.write(`${JSON.stringify({ delivered: result?.delivered || 'outbox', ...(result?.reason ? { reason: result.reason } : {}) })}\n`);
  }
} catch {
  process.stderr.write('Usage: STATE_DIRECTORY=<state directory> node portal/bin/mint-invite.js <email> [plan] [hostname limit] [expiry ISO date] [--send]\n'
    + '  --send mails the code with the configured MAIL_TRANSPORT (needs PORTAL_ORIGIN) instead of printing it.\n');
  process.exitCode = 1;
}
