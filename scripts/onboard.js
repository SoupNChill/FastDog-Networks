#!/usr/bin/env node
import { createZone, nsInstructions, issueCredential, mapHost } from '../src/onboard/store.js';
import { generateInvite, listInvites, redeemInvite } from '../src/onboard/invites.js';
import { editTestTenants } from '../src/internal/test-labels.js';
import { attachHost, verifyHost, listAttachedHosts, detachHost } from '../src/onboard/attach.js';

import { resetTlsApprovals } from '../src/internal/tls-approval-state.js';

const [command, ...args] = process.argv.slice(2);
const usage = `Usage: npm run onboard -- <command>

TLS issuance recovery:
  tls-reset <hostname>               Reset persisted approval budgets for one host

CNAME/Attach (default onboarding):
  attach-host <hostname>              Attach hostname via CNAME (returns instructions)
  verify-host <hostname>              Verify DNS and activate (issues credential)
  list-attached-hosts                 List all attached hostnames
  detach-host <hostname>              Remove attached hostname

Internal test tenants (may claim e2e-<label>.<attach-domain>):
  test-tenant add <tenant-id>         Mark tenant (DATA_DIR/test_tenants.json, mode 0600)
  test-tenant remove <tenant-id>      Unmark tenant (existing claims stay; new claims/verify refused)
  test-tenant list                    List marked tenants

NS cut (advanced):
  create-zone <zone> [options]        Create authoritative zone
    --edge-ip <IPv4>                  Set apex A record
    --force                           Overwrite existing zone
    --invite <code>                   Invite code for zone creation
  ns-instructions <zone>              Show NS delegation instructions
  map-host <zone> <hostname>          Map hostname to edge (after zone created)
    --origin-hint <URL>               Origin server URL hint

Credentials:
  issue-credential                    Issue agent credential
    --name <name>                     Agent name
    --hostname <host>                 Bind credential to hostname

Invites:
  generate-invite [options]           Generate invite code
    --max-uses N                      Maximum uses (default: 1)
    --expires-in-hours H              Expiry in hours
    --expires-at ISO                  Expiry timestamp
    --note TEXT                       Note for invite
  list-invites                        List all invites
  redeem-invite <code>                Redeem invite code
    --redeemed-by NAME                Redemption label`;

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

async function main() {
  let result;
  if (command === 'tls-reset' && args.length === 1) {
    console.log(JSON.stringify(resetTlsApprovals(args[0])));
  } else if (command === 'attach-host' && args[0]) {
    result = attachHost({ hostname: args[0] });
    console.log(JSON.stringify(result, null, 2));
    console.error('\nNext: Add the CNAME record at your registrar, then run:');
    console.error(`  npm run onboard -- verify-host ${args[0]}`);
  } else if (command === 'verify-host' && args[0]) {
    result = await verifyHost({ hostname: args[0] });
    console.log(JSON.stringify(result, null, 2));
    if (result.verified) {
      console.error('\nHostname verified and activated.');
      console.error('Reload a running edge with POST /_fastdog/routes/reload.');
      console.error('\nCaddy setup (operator): Add the caddy_block to Caddyfile and reload Caddy.');
      console.error('Credential: Save the agent_env values; token is shown once.');
    } else {
      console.error('\nVerification failed. Check your DNS records and try again.');
    }
  } else if (command === 'list-attached-hosts') {
    result = listAttachedHosts();
    console.log(JSON.stringify({ hosts: result }, null, 2));
  } else if (command === 'detach-host' && args[0]) {
    result = detachHost({ hostname: args[0] });
    console.log(JSON.stringify(result, null, 2));
    console.error('Reload a running edge with POST /_fastdog/routes/reload.');
  } else if (command === 'test-tenant' && (args[0] === 'list' || (['add', 'remove'].includes(args[0]) && args[1]))) {
    result = editTestTenants(args[0], args[1]);
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'create-zone' && args[0]) {
    result = createZone({ zone: args[0], edge_ip: option('--edge-ip'), force: args.includes('--force'), invite_code: option('--invite') });
    console.log(JSON.stringify(result, null, 2));
    warnSync(result);
  } else if (command === 'generate-invite') {
    result = generateInvite({ max_uses: option('--max-uses') === undefined ? 1 : Number(option('--max-uses')), expires_in_hours: option('--expires-in-hours') === undefined ? undefined : Number(option('--expires-in-hours')), expires_at: option('--expires-at'), note: option('--note') });
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'list-invites') {
    result = listInvites();
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'redeem-invite' && args[0]) {
    result = redeemInvite({ code: args[0], redeemed_by: option('--redeemed-by') });
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'ns-instructions' && args[0]) {
    result = nsInstructions(args[0]);
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'issue-credential') {
    result = issueCredential({ name: option('--name'), hostname: option('--hostname') });
    console.log(JSON.stringify(result, null, 2));
  } else if (command === 'map-host' && args[0] && args[1]) {
    result = mapHost({ zone: args[0], hostname: args[1], origin_hint: option('--origin-hint') });
    console.log(JSON.stringify(result, null, 2));
    console.error('Reload a running edge with POST /_fastdog/routes/reload.');
    warnSync(result);
  } else {
    throw new Error(usage);
  }
}

main().catch((error) => {
  console.error(error.message);
  process.exitCode = 1;
});
