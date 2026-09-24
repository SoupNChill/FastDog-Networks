#!/usr/bin/env node
import { createZone, nsInstructions, issueCredential, mapHost } from '../src/onboard/store.js';

const [command, ...args] = process.argv.slice(2);
const usage = 'Usage: npm run onboard -- create-zone <zone> [--edge-ip <IPv4>] [--force] | ns-instructions <zone> | issue-credential [--name <name>] [--hostname <host>] | map-host <zone> <hostname> [--origin-hint <URL>]';
function option(name) { const index = args.indexOf(name); return index < 0 ? undefined : args[index + 1]; }

try {
  let result;
  if (command === 'create-zone' && args[0]) result = createZone({ zone: args[0], edge_ip: option('--edge-ip'), force: args.includes('--force') });
  else if (command === 'ns-instructions' && args[0]) result = nsInstructions(args[0]);
  else if (command === 'issue-credential') result = issueCredential({ name: option('--name'), hostname: option('--hostname') });
  else if (command === 'map-host' && args[0] && args[1]) result = mapHost({ zone: args[0], hostname: args[1], origin_hint: option('--origin-hint') });
  else throw new Error(usage);
  console.log(JSON.stringify(result, null, 2));
  if (command === 'map-host') console.error('Reload a running edge with POST /_fastdog/routes/reload.');
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
