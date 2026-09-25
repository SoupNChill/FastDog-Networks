#!/usr/bin/env node
import { createZone, nsInstructions, issueCredential, mapHost } from '../src/onboard/store.js';
import { generateInvite, listInvites, redeemInvite } from '../src/onboard/invites.js';

const [command, ...args] = process.argv.slice(2);
const usage = 'Usage: npm run onboard -- create-zone <zone> [--edge-ip <IPv4>] [--force] [--invite <code>] | generate-invite [--max-uses N] [--expires-in-hours H] [--expires-at ISO] [--note TEXT] | list-invites | redeem-invite <code> [--redeemed-by NAME] | ns-instructions <zone> | issue-credential [--name <name>] [--hostname <host>] | map-host <zone> <hostname> [--origin-hint <URL>]';
function option(name) { const index = args.indexOf(name); return index < 0 ? undefined : args[index + 1]; }
function warnSync(result) {
  const sync = result?.coredns_sync;
  if (!sync) return;
  if (sync.skipped) console.error(`[coredns-sync] skipped (${sync.reason || 'disabled'})`);
  else if (sync.dry_run) console.error(`[coredns-sync] dry-run ok for ${sync.zone}`);
  else if (sync.ok) console.error(`[coredns-sync] ok for ${sync.zone}`);
  else {
    console.error(`[coredns-sync] FAILED for ${sync.zone}: ${sync.error || 'unknown'} (zone/host changes were still saved)`);
    if (['1', 'true', 'yes', 'on'].includes(String(process.env.COREDNS_SYNC_STRICT || '').toLowerCase())) process.exitCode = 1;
  }
}

try {
  let result;
  if (command === 'create-zone' && args[0]) result = createZone({ zone: args[0], edge_ip: option('--edge-ip'), force: args.includes('--force'), invite_code: option('--invite') });
  else if (command === 'generate-invite') result = generateInvite({ max_uses: option('--max-uses') === undefined ? 1 : Number(option('--max-uses')), expires_in_hours: option('--expires-in-hours') === undefined ? undefined : Number(option('--expires-in-hours')), expires_at: option('--expires-at'), note: option('--note') });
  else if (command === 'list-invites') result = listInvites();
  else if (command === 'redeem-invite' && args[0]) result = redeemInvite({ code: args[0], redeemed_by: option('--redeemed-by') });
  else if (command === 'ns-instructions' && args[0]) result = nsInstructions(args[0]);
  else if (command === 'issue-credential') result = issueCredential({ name: option('--name'), hostname: option('--hostname') });
  else if (command === 'map-host' && args[0] && args[1]) result = mapHost({ zone: args[0], hostname: args[1], origin_hint: option('--origin-hint') });
  else throw new Error(usage);
  console.log(JSON.stringify(result, null, 2));
  if (command === 'map-host') console.error('Reload a running edge with POST /_fastdog/routes/reload.');
  if (command === 'create-zone' || command === 'map-host') warnSync(result);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
