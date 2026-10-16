import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { agentStatusText } from '../public/js/agent-view.js';

const source = readFileSync(new URL('../public/js/hostname.js', import.meta.url), 'utf8');
const context = vm.createContext({ URL });
vm.runInContext(source.slice(source.indexOf('const TWO_PART'), source.indexOf('const providerNotes')).replaceAll('export ', ''), context);
const realm = vm.runInContext('({ providerFields, zoneOf, relativeName })', context);
const { zoneOf, relativeName } = realm;
const providerFields = (...args) => JSON.parse(JSON.stringify(realm.providerFields(...args)));
const cname = { type: 'CNAME', name: 'app.example.test', value: 'attach.example-edge.test', ttl: 300 };
const txt = { type: 'TXT', name: '_fastdog-challenge.app.example.test', value: 'proof', ttl: 300 };

test('provider tabs use each provider form field names and relative names', () => {
  assert.equal(zoneOf('app.example.co.uk'), 'example.co.uk');
  assert.equal(relativeName('example.test', 'example.test'), '@');
  const labels = (provider, record) => providerFields(provider, record, 'example.test').map(([label]) => label);
  assert.deepEqual(labels('cloudflare', cname), ['Type', 'Name', 'Target', 'Proxy status', 'TTL']);
  assert.deepEqual(labels('cloudflare', txt), ['Type', 'Name', 'Content', 'TTL']);
  assert.deepEqual(labels('namecheap', cname), ['Type', 'Host', 'Value', 'TTL']);
  assert.deepEqual(labels('godaddy', cname), ['Type', 'Name', 'Value', 'TTL']);
  assert.deepEqual(labels('route53', cname), ['Record name', 'Record type', 'Value', 'TTL (seconds)', 'Routing policy']);
  assert.deepEqual(labels('porkbun', cname), ['Type', 'Host', 'Answer', 'TTL']);
  assert.deepEqual(Object.fromEntries(providerFields('cloudflare', cname, 'example.test')), { Type: 'CNAME', Name: 'app', Target: 'attach.example-edge.test', 'Proxy status': 'DNS only (grey cloud)', TTL: 'Auto' });
  assert.equal(Object.fromEntries(providerFields('namecheap', txt, 'example.test')).Host, '_fastdog-challenge.app');
  assert.equal(Object.fromEntries(providerFields('other', txt, 'example.test')).Name, txt.name);
});

test('hostname page states the Cloudflare grey-cloud rule and explains proxied records', () => {
  assert.match(source, /If your DNS is on Cloudflare, set Proxy status to DNS only \(grey cloud\)\./);
  assert.match(source, /dns_proxied[^\n]*proxied by Cloudflare \(orange cloud\)/);
  assert.match(source, /Zone file format \(advanced\)/);
});

test('Connect status explains a connected agent whose app is not answering', () => {
  assert.match(agentStatusText({ connected: true, origin_reachable: false, origin_address: '127.0.0.1:5000' }), /^Agent connected, but your app at 127\.0\.0\.1:5000 isn't answering\./);
  assert.match(agentStatusText({ connected: true, origin_reachable: false }), /your app at the address you entered/);
  assert.match(agentStatusText({ connected: true, origin_reachable: null }), /^Server connected/);
  assert.match(agentStatusText({ connected: true, origin_reachable: true }), /^Server connected/);
  assert.match(agentStatusText({ connected: false }), /^Waiting for your server/);
});
