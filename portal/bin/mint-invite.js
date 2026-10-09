import { createInvites } from '../src/invites.js';
const [email, plan, limit, expiresAt] = process.argv.slice(2);
try {
  if (!email || !process.env.STATE_DIRECTORY) throw new Error('Arguments required');
  const code = createInvites({ dataDir: process.env.STATE_DIRECTORY }).mint({
    email, plan, hostnameLimit: limit === undefined ? undefined : Number(limit), expiresAt,
  });
  process.stdout.write(`${code}\n`);
} catch {
  process.stderr.write('Usage: STATE_DIRECTORY=<state directory> node portal/bin/mint-invite.js <email> [plan] [hostname limit] [expiry ISO date]\n');
  process.exitCode = 1;
}
