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

export function isTestLabelHost(host, attachTarget, ...otherTargets) {
  const domain = attachDomain(attachTarget);
  const name = clean(host);
  if (!domain.includes('.') || !name.endsWith(`.${domain}`)) return false;
  const label = name.slice(0, -domain.length - 1);
  return LABEL.test(label) && !neverClaimable(name, [attachTarget, ...otherTargets]);
}

export function testTenants(directory = defaultDataDir()) {
  try {
    const list = JSON.parse(fs.readFileSync(path.join(directory, TEST_TENANTS_FILE), 'utf8'));
    return Array.isArray(list) && list.every((id) => typeof id === 'string' && TENANT_ID.test(id)) ? new Set(list) : new Set();
  } catch { return new Set(); }
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
