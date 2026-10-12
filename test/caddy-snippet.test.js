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

test('parsed access-log fields remove query tokens and all request headers including Authorization', () => {
  const source = readFileSync(new URL('../deploy/caddy/access-logs.snippet', import.meta.url), 'utf8');
  const tokens = source.replace(/^\s*#.*$/gm, '').match(/"(?:\\.|[^"\\])*"|[^\s{}]+|[{}]/g);
  let index = 0;
  function block() {
    const nodes = [];
    while (index < tokens.length && tokens[index] !== '}') {
      const name = tokens[index++];
      if (tokens[index] === '{') { index++; nodes.push({ name, children: block() }); index++; }
      else nodes.push({ name });
    }
    return nodes;
  }
  const tree = block();
  const find = (nodes, name) => nodes.find((node) => node.name === name);
  const log = find(tree[0].children, 'log');
  const formatIndex = log.children.findIndex((node) => node.name === 'format');
  const filter = log.children[formatIndex + 1];
  assert.equal(filter.name, 'filter');
  const fields = find(filter.children, 'fields').children;
  for (const field of ['request>headers', 'request>cookies', 'resp_headers']) {
    assert.equal(fields[fields.findIndex((node) => node.name === field) + 1].name, 'delete');
  }
  // Deleting the whole header object necessarily covers Cookie, Authorization and token headers.
  const uri = fields.findIndex((node) => node.name === 'request>uri');
  assert.equal(fields[uri + 1].name, 'regexp');
  const pattern = new RegExp(JSON.parse(fields[uri + 2].name));
  assert.equal('/path?token=synthetic&other=value'.replace(pattern, JSON.parse(fields[uri + 3].name)), '/path');
  const mask = fields[fields.findIndex((node) => node.name === 'request>client_ip') + 1];
  assert.equal(mask.name, 'ip_mask');
  assert.deepEqual(mask.children.map((node) => node.name), ['ipv4', '24', 'ipv6', '48']);
});
