import { randomBytes, randomUUID, createHash, timingSafeEqual } from 'node:crypto';
import { isIP } from 'node:net';
import { env } from '../lib/config.js';
import { readZone, writeZone } from '../dns/store.js';
import { syncAfterOnboard } from '../dns/sync-coredns.js';
import { readJson, writeJson } from './json.js';
import { inviteRequired, assertInvite, redeemInvite } from './invites.js';

export const ns = () => [env('NS1_HOST', 'ns1.fastdognetworks.com'), env('NS2_HOST', 'ns2.fastdognetworks.com')].map((h) => `${h.replace(/\.$/, '').toLowerCase()}.`);
export const edgeIp = () => env('EDGE_PUBLIC_IP', '157.230.57.32');
export { dataDir } from './json.js';
const domainPattern = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

export function domain(value) {
  const result = String(value || '').replace(/\.$/, '').toLowerCase();
  if (!domainPattern.test(result)) throw Object.assign(new Error('invalid_domain'), { status: 400 });
  return result;
}

export function createZone({ zone, edge_ip, force = false, invite_code } = {}) {
  zone = domain(zone);
  if (readZone(zone) && force !== true) throw Object.assign(new Error('zone_exists'), { status: 409 });
  const ip = edge_ip || edgeIp();
  if (edge_ip && isIP(ip) !== 4) throw Object.assign(new Error('invalid_edge_ip'), { status: 400 });
  const needsInvite = inviteRequired();
  if (needsInvite) assertInvite(invite_code);
  const nameservers = ns();
  const serial = `${new Date().toISOString().slice(0, 10).replaceAll('-', '')}01`;
  const records = [
    { name: '@', type: 'SOA', ttl: 3600, content: `${nameservers[0]} hostmaster.${zone}. ${serial} 3600 600 604800 300` },
    ...nameservers.map((content) => ({ name: '@', type: 'NS', ttl: 3600, content })),
  ];
  if (edge_ip) records.push({ name: '@', type: 'A', ttl: 300, content: ip });
  writeZone(zone, { ttl_default: 300, records });
  if (needsInvite) redeemInvite({ code: invite_code, redeemed_by: zone });
  const coredns_sync = syncAfterOnboard(zone, 'create-zone');
  return { zone, ns: nameservers, dig_verify: digChecks(zone), coredns_sync };
}

export function digChecks(zone) {
  return [`dig ${zone} NS`, `dig ${zone} SOA`, `dig +trace ${zone} NS`, ...ns().map((_, i) => `dig @${env(i ? 'NS2_IP' : 'NS1_IP', i ? '2.29.58.90' : '157.230.57.32')} ${zone} SOA +norecurse`)];
}

export function nsInstructions(zone) {
  zone = domain(zone);
  if (!readZone(zone)) throw Object.assign(new Error('zone_not_found'), { status: 404 });
  return { zone, ns: ns(), registrar_instructions: `At the registrar for ${zone}, set custom nameservers to ${ns().join(' and ')} after the zone is served and verified on both servers.`, glue: ns().filter((h) => h.endsWith(`${zone}.`)).map((host) => ({ host, ip: host === ns()[0] ? env('NS1_IP', '157.230.57.32') : env('NS2_IP', '2.29.58.90') })), dig_verify: digChecks(zone) };
}

export function issueCredential({ name, hostname } = {}) {
  const host = hostname ? domain(hostname) : undefined;
  const token = randomBytes(32).toString('hex');
  const id = randomUUID();
  const credentials = readJson('agent-credentials.json', []);
  credentials.push({ id, name: name || undefined, hostname: host, token_hash: createHash('sha256').update(token).digest('hex'), created_at: new Date().toISOString() });
  writeJson('agent-credentials.json', credentials, 0o600);
  return { id, token, agent_env: { AGENT_TOKEN: token, ...(name ? { AGENT_NAME: name } : {}), ...(host ? { AGENT_HOSTNAME: host } : {}) } };
}

export function validCredential(token, hostname) {
  if (typeof token !== 'string' || !token) return false;
  const hash = createHash('sha256').update(token).digest();
  return readJson('agent-credentials.json', []).some((item) => {
    const stored = Buffer.from(item.token_hash, 'hex');
    return (!item.hostname || item.hostname === String(hostname).toLowerCase()) && stored.length === hash.length && timingSafeEqual(stored, hash);
  });
}

export function tunnelHosts() { return readJson('tunnel_hosts.json', []); }

export function mapHost({ zone, hostname, origin_hint }) {
  zone = domain(zone);
  hostname = domain(hostname);
  if (hostname !== zone && !hostname.endsWith(`.${zone}`)) throw Object.assign(new Error('hostname_outside_zone'), { status: 400 });
  const data = readZone(zone);
  if (!data) throw Object.assign(new Error('zone_not_found'), { status: 404 });
  const ip = edgeIp();
  if (isIP(ip) !== 4) throw Object.assign(new Error('invalid_edge_public_ip'), { status: 400 });
  const name = hostname === zone ? '@' : hostname.slice(0, -(zone.length + 1));
  data.records = (data.records || []).filter((r) => !(r.name === name && r.type === 'A'));
  data.records.push({ name, type: 'A', ttl: 300, content: ip });
  const soa = data.records.find((r) => r.name === '@' && r.type === 'SOA');
  if (soa) {
    const fields = soa.content.split(/\s+/);
    const current = Number(fields[2]);
    const today = Number(`${new Date().toISOString().slice(0, 10).replaceAll('-', '')}00`);
    if (Number.isSafeInteger(current) && fields.length >= 7) {
      fields[2] = String(Math.max(current + 1, today + 1));
      soa.content = fields.join(' ');
    }
  }
  writeZone(zone, data);
  const hosts = tunnelHosts();
  if (!hosts.includes(hostname)) writeJson('tunnel_hosts.json', [...hosts, hostname]);
  const coredns_sync = syncAfterOnboard(zone, 'map-host');
  return { zone, hostname, edge_ip: ip, agent_run: { AGENT_HOSTNAME: hostname, AGENT_LOCAL_UPSTREAM: origin_hint || 'http://127.0.0.1:9999', command: 'npm run agent' }, coredns_sync };
}
