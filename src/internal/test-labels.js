import fs from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { ENFORCE_DENYLIST } from '../../verdict/src/config/hosts.js';
import { dataDir as defaultDataDir } from '../onboard/json.js';

// Internal operator test labels: e2e-<label>.<attach-domain>, claimable only by tenants
// listed in DATA_DIR/test_tenants.json (operator-controlled; missing or malformed = nobody).
export const TEST_TENANTS_FILE = 'test_tenants.json';
export const TENANT_ID = /^t_[a-z2-7]{20}$/;
const LABEL = /^e2e-[a-z0-9-]{1,40}$/;

const clean = (host) => String(host ?? '').toLowerCase().replace(/\.$/, '');

// Conservative registrable domain: the final two labels, as in reservedSuffixes().
export const attachDomain = (attachTarget) => clean(attachTarget).split('.').slice(-2).join('.');

// Hosts that are never claimable by anyone, whatever their shape.
const neverClaimable = (host, targets) => ENFORCE_DENYLIST.includes(host) || targets.some((target) => host === clean(target));

// Guardrail hosts (and their subdomains) are never claimed or approved for on-demand certificates.
// Exception: an operator test label directly under the attach domain is not made a guardrail by the
// attach domain's own denylist entry; every other entry (and exact names) still applies.
export const isGuardrailHost = (host, attachTarget, ...otherTargets) => {
  const name = clean(host);
  const domain = attachTarget ? attachDomain(attachTarget) : '';
  const testLabel = Boolean(domain) && isTestLabelHost(name, attachTarget, ...otherTargets);
  return ENFORCE_DENYLIST.some((guard) => name === guard || (name.endsWith(`.${guard}`) && !(testLabel && guard === domain)));
};

export function isTestLabelHost(host, attachTarget, ...otherTargets) {
  const domain = attachDomain(attachTarget);
  const name = clean(host);
  if (!domain.includes('.') || !name.endsWith(`.${domain}`)) return false;
  const label = name.slice(0, -domain.length - 1);
  return LABEL.test(label) && !neverClaimable(name, [attachTarget, ...otherTargets]);
}

const tenantCache = new Map();
export function testTenants(directory = defaultDataDir()) {
  const file = path.join(directory, TEST_TENANTS_FILE);
  try {
    const stat = fs.statSync(file);
    const stamp = `${stat.mtimeMs}:${stat.ctimeMs}:${stat.ino}:${stat.size}`;
    if (tenantCache.get(file)?.stamp === stamp) return new Set(tenantCache.get(file).tenants);
    const list = JSON.parse(fs.readFileSync(file, 'utf8'));
    const tenants = Array.isArray(list) && list.every((id) => typeof id === 'string' && TENANT_ID.test(id)) ? new Set(list) : new Set();
    tenantCache.set(file, { stamp, tenants });
    return new Set(tenants);
  } catch { tenantCache.delete(file); return new Set(); }
}

export const mayClaimTestLabel = (tid, host, attachTarget, altAttachTarget, directory) =>
  isTestLabelHost(host, attachTarget, altAttachTarget) && testTenants(directory).has(tid);

// Operator CLI helper. Strict about the stored file so a malformed file is never silently overwritten.
export function editTestTenants(action, tid, directory = defaultDataDir()) {
  const file = path.join(directory, TEST_TENANTS_FILE);
  let list = [];
  if (fs.existsSync(file)) {
    try { list = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { list = null; }
    if (!Array.isArray(list) || !list.every((id) => typeof id === 'string' && TENANT_ID.test(id))) throw new Error(`${TEST_TENANTS_FILE} is malformed; fix it manually`);
  }
  if (action !== 'list') {
    if (!TENANT_ID.test(String(tid))) throw new Error('invalid tenant id');
    list = action === 'add' ? [...new Set([...list, tid])].sort() : list.filter((id) => id !== tid);
    fs.mkdirSync(directory, { recursive: true });
    const temp = `${file}.${process.pid}.${randomUUID()}.tmp`;
    fs.writeFileSync(temp, `${JSON.stringify(list, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temp, file);
    fs.chmodSync(file, 0o600);
  }
  return { test_tenants: list };
}
