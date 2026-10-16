import dns from 'node:dns/promises';
import { env } from '../lib/config.js';
import { domain, issueCredential, tunnelHosts, edgeIp } from './store.js';
import { readJson, writeJson } from './json.js';

const ATTACH_FILE = 'attached_hosts.json';

export const attachTarget = () => env('ATTACH_TARGET', 'attach.fastdognetworks.com');
export const altAttachTarget = () => env('ALT_ATTACH_TARGET', 'edge.fastdognetworks.com');

const badRequest = (message) => Object.assign(new Error(message), { status: 400 });
const notFound = (message) => Object.assign(new Error(message), { status: 404 });
const conflict = (message) => Object.assign(new Error(message), { status: 409 });

export function listAttachedHosts() {
  return readJson(ATTACH_FILE, []);
}

function findAttachment(hostname) {
  const hosts = listAttachedHosts();
  return hosts.find((h) => h.hostname === hostname);
}

function saveAttachments(hosts) {
  writeJson(ATTACH_FILE, hosts, 0o644);
}

export function cnameInstructions(hostname) {
  const target = attachTarget();
  return {
    cname_target: target,
    cname_instructions: `Add this CNAME record at your registrar:\n\n${hostname}.  300  IN  CNAME  ${target}.\n\nThen run: npm run onboard -- verify-host ${hostname}`,
    apex_note: hostname.split('.').length === 2
      ? 'This appears to be an apex domain. CNAME at apex is not supported by standard DNS. Use a subdomain (www, app) or ALIAS/ANAME if your registrar supports it.'
      : undefined,
  };
}

export function attachHost({ hostname } = {}) {
  hostname = domain(hostname);
  const existing = findAttachment(hostname);
  if (existing) {
    if (existing.status === 'active') {
      throw conflict('hostname_already_active');
    }
    return {
      hostname,
      status: existing.status,
      created_at: existing.created_at,
      ...cnameInstructions(hostname),
    };
  }
  const hosts = listAttachedHosts();
  const record = {
    hostname,
    status: 'pending',
    created_at: new Date().toISOString(),
  };
  hosts.push(record);
  saveAttachments(hosts);
  return {
    hostname,
    status: 'pending',
    created_at: record.created_at,
    ...cnameInstructions(hostname),
  };
}

async function resolveCname(hostname, resolver) {
  try {
    const records = await resolver.resolveCname(hostname);
    return { type: 'cname', records };
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return { type: 'none', error: error.code };
    }
    throw error;
  }
}

async function resolveA(hostname, resolver) {
  try {
    const records = await resolver.resolve4(hostname);
    return { type: 'a', records };
  } catch (error) {
    if (error.code === 'ENODATA' || error.code === 'ENOTFOUND') {
      return { type: 'none', error: error.code };
    }
    throw error;
  }
}

// Cloudflare's published proxy ranges (https://www.cloudflare.com/ips-v4). A proxied ("orange cloud") CNAME
// hides the record and answers with these addresses instead of our target.
const CLOUDFLARE_V4 = ['173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
  '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15',
  '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22'];
const ipv4 = (ip) => String(ip).split('.').reduce((n, part) => (n * 256) + Number(part), 0);
export function isCloudflareProxyIp(ip) {
  if (!/^\d{1,3}(\.\d{1,3}){3}$/.test(String(ip))) return false;
  const value = ipv4(ip);
  return CLOUDFLARE_V4.some((range) => {
    const [base, bits] = range.split('/');
    const size = 2 ** (32 - Number(bits));
    const start = ipv4(base);
    return value >= start && value < start + size;
  });
}

export async function checkDnsVerification(hostname, opts = {}) {
  const resolver = opts.resolver || dns;
  const target = (opts.attachTarget ?? attachTarget()).toLowerCase().replace(/\.$/, '');
  const altTarget = (opts.altAttachTarget ?? altAttachTarget()).toLowerCase().replace(/\.$/, '');
  const edgeAddress = opts.edgePublicIp ?? edgeIp();
  const cname = await resolveCname(hostname, resolver);
  if (cname.type === 'cname' && cname.records.length > 0) {
    const found = cname.records[0].toLowerCase().replace(/\.$/, '');
    if (found === target || found === altTarget) {
      return { verified: true, method: 'cname', target: found };
    }
    let chainTarget = found;
    for (let i = 0; i < 4; i++) {
      const chain = await resolveCname(chainTarget, resolver);
      if (chain.type !== 'cname' || chain.records.length === 0) break;
      chainTarget = chain.records[0].toLowerCase().replace(/\.$/, '');
      if (chainTarget === target || chainTarget === altTarget) {
        return { verified: true, method: 'cname_chain', target: chainTarget };
      }
    }
    return { verified: false, error: 'cname_wrong_target', found, expected: target };
  }
  const aRecord = await resolveA(hostname, resolver);
  if (aRecord.type === 'a' && aRecord.records.length > 0) {
    if (aRecord.records.includes(edgeAddress)) {
      return { verified: true, method: 'a_record', target: edgeAddress };
    }
    if (aRecord.records.every(isCloudflareProxyIp)) return { verified: false, error: 'dns_proxied', expected: target };
    return { verified: false, error: 'a_wrong_target', found: aRecord.records.join(', '), expected: edgeAddress };
  }
  return { verified: false, error: 'no_dns_record', expected: target };
}

// Requires the filtered `fdlog` snippet (deploy/caddy/access-logs.snippet) to be imported once at the top of the Caddyfile.
// Without it Caddy refuses the config, so a block can never fall back to the default logger (which records ?token= and headers).
export function generateCaddyBlock(hostname) {
  return `${hostname} {
    import fdlog ${hostname}
    reverse_proxy localhost:8787
}`;
}

function addToTunnelHosts(hostname) {
  const hosts = tunnelHosts();
  if (!hosts.includes(hostname)) {
    writeJson('tunnel_hosts.json', [...hosts, hostname]);
  }
}

function removeFromTunnelHosts(hostname) {
  const hosts = tunnelHosts();
  const filtered = hosts.filter((h) => h !== hostname);
  if (filtered.length !== hosts.length) {
    writeJson('tunnel_hosts.json', filtered);
  }
}

export async function verifyHost({ hostname } = {}) {
  hostname = domain(hostname);
  const attachment = findAttachment(hostname);
  if (!attachment) {
    throw notFound('hostname_not_attached');
  }
  if (attachment.status === 'active') {
    return {
      hostname,
      status: 'active',
      verified: true,
      verified_at: attachment.verified_at,
      caddy_block: generateCaddyBlock(hostname),
    };
  }
  const check = await checkDnsVerification(hostname);
  if (!check.verified) {
    return {
      hostname,
      status: 'pending',
      verified: false,
      error: check.error,
      found: check.found,
      expected: check.expected,
      ...cnameInstructions(hostname),
    };
  }
  addToTunnelHosts(hostname);
  const credential = issueCredential({ hostname, name: `attach-${hostname}` });
  const hosts = listAttachedHosts();
  const record = hosts.find((h) => h.hostname === hostname);
  if (record) {
    record.status = 'active';
    record.verified_at = new Date().toISOString();
    record.verification_method = check.method;
    record.verification_target = check.target;
    saveAttachments(hosts);
  }
  return {
    hostname,
    status: 'active',
    verified: true,
    method: check.method,
    target: check.target,
    credential,
    caddy_block: generateCaddyBlock(hostname),
  };
}

export function detachHost({ hostname } = {}) {
  hostname = domain(hostname);
  const hosts = listAttachedHosts();
  const index = hosts.findIndex((h) => h.hostname === hostname);
  if (index < 0) {
    throw notFound('hostname_not_attached');
  }
  const removed = hosts.splice(index, 1)[0];
  saveAttachments(hosts);
  removeFromTunnelHosts(hostname);
  return {
    hostname,
    detached: true,
    previous_status: removed.status,
  };
}

export function getAttachedHost(hostname) {
  hostname = domain(hostname);
  const attachment = findAttachment(hostname);
  if (!attachment) {
    throw notFound('hostname_not_attached');
  }
  return attachment;
}
