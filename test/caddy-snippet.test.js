import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

test('access log snippet strips sensitive fields and bounds retention', () => {
  const text = readFileSync(new URL('../deploy/caddy/access-logs.snippet', import.meta.url), 'utf8');
  for (const required of ['(fdlog)', 'format filter', 'wrap json', 'roll_size 5MiB', 'roll_keep 5', 'roll_keep_for 168h',
    'request>headers delete', 'resp_headers delete', 'request>tls delete', 'request>cookies delete',
    'request>remote_ip delete', 'request>remote_port delete', 'request>client_ip ip_mask', 'ipv4 24', 'ipv6 48',
    'request>uri regexp "[?].*$" ""', '/var/log/caddy/{args[0]}.log']) assert.ok(text.includes(required), required);
  assert.doesNotMatch(text, /log_credentials|format console|\bappend\b/);
  for (const line of text.split('\n').filter((line) => /headers|cookies|tls/.test(line))) assert.match(line, / delete\s*$/);
  assert.doesNotMatch(text, /(?:method|status|duration) delete/);
});
