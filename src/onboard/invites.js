import { randomBytes } from 'node:crypto';
import { env } from '../lib/config.js';
import { readJson, writeJson } from './json.js';

const file = 'invites.json';
const badRequest = (message) => Object.assign(new Error(message), { status: 400 });

export const inviteRequired = () => ['1', 'true', 'yes', 'on'].includes(String(env('INVITE_REQUIRED', 'true')).toLowerCase());
export const listInvites = () => readJson(file, []);

export function generateInvite({ max_uses = 1, expires_at, expires_in_hours, note } = {}) {
  if (!Number.isSafeInteger(max_uses) || max_uses < 1) throw badRequest('invalid_max_uses');
  if (expires_at !== undefined && expires_in_hours !== undefined) throw badRequest('conflicting_expiry');
  if (expires_at !== undefined) {
    if (typeof expires_at !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)$/.test(expires_at) || !Number.isFinite(Date.parse(expires_at))) throw badRequest('invalid_expires_at');
    expires_at = new Date(expires_at).toISOString();
  }
  if (expires_in_hours !== undefined) {
    if (typeof expires_in_hours !== 'number' || !Number.isFinite(expires_in_hours) || expires_in_hours <= 0) throw badRequest('invalid_expires_in_hours');
    const timestamp = Date.now() + expires_in_hours * 3600000;
    if (!Number.isFinite(timestamp) || timestamp > 8.64e15) throw badRequest('invalid_expires_in_hours');
    expires_at = new Date(timestamp).toISOString();
  }
  if (expires_at && Date.parse(expires_at) <= Date.now()) throw badRequest('expired_invite');
  if (note !== undefined && typeof note !== 'string') throw badRequest('invalid_note');
  const invites = listInvites();
  const invite = { code: `fd-${randomBytes(24).toString('hex')}`, max_uses, remaining_uses: max_uses, created_at: new Date().toISOString(), ...(expires_at ? { expires_at } : {}), ...(note ? { note } : {}), redemptions: [] };
  invites.push(invite);
  writeJson(file, invites, 0o600);
  return invite;
}

function validInvite(invites, code) {
  if (typeof code !== 'string' || !code) throw badRequest('invite_code_required');
  const invite = invites.find((item) => item.code === code);
  if (!invite) throw Object.assign(new Error('invalid_invite_code'), { status: 403 });
  if (invite.expires_at && Date.parse(invite.expires_at) <= Date.now()) throw Object.assign(new Error('invite_expired'), { status: 403 });
  if (invite.remaining_uses < 1) throw Object.assign(new Error('invite_exhausted'), { status: 409 });
  return invite;
}

export const assertInvite = (code) => validInvite(listInvites(), code);

export function redeemInvite({ code, redeemed_by } = {}) {
  if (redeemed_by !== undefined && (typeof redeemed_by !== 'string' || !redeemed_by.trim())) throw badRequest('invalid_redeemed_by');
  const invites = listInvites();
  const invite = validInvite(invites, code);
  const redemption = { redeemed_at: new Date().toISOString(), ...(redeemed_by ? { redeemed_by } : {}) };
  invite.remaining_uses -= 1;
  invite.redemptions.push(redemption);
  writeJson(file, invites, 0o600);
  return invite;
}
