// Abuse limits for open (no-invite) sign-up. Invite sign-ups never reach this module.
// Every refusal is reported to the caller as a reason code only; the HTTP response stays the
// generic success so limits cannot be used to enumerate accounts or domains.
import { readFileSync } from 'node:fs';
import { domainToASCII } from 'node:url';

const DAY = 86400000;
// Large free providers share one address space across millions of people, so they get a higher
// per-domain budget. Matching is exact (no parent domains).
export const BIGMAIL = new Set(['gmail.com', 'googlemail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com',
  'yahoo.com', 'ymail.com', 'icloud.com', 'me.com', 'mac.com', 'aol.com', 'proton.me', 'protonmail.com', 'pm.me',
  'gmx.com', 'gmx.net', 'gmx.de', 'web.de', 'mail.com', 'yandex.com', 'yandex.ru', 'zoho.com', 'fastmail.com']);
// Second-level labels under country codes that act as public suffixes (co.uk, com.au, ...).
const SECOND_LEVEL = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'ne', 'or', 'go']);

export function loadDisposable(file = new URL('./data/disposable-domains.txt', import.meta.url)) {
  return new Set(readFileSync(file, 'utf8').split('\n').map((line) => line.trim().toLowerCase())
    .filter((line) => line && !line.startsWith('#')));
}
// ASCII (punycode) form of the email's domain, or null when it is not a usable hostname.
export function emailDomain(email) {
  const at = typeof email === 'string' ? email.lastIndexOf('@') : -1;
  if (at < 1) return null;
  const domain = domainToASCII(email.slice(at + 1).replace(/\.$/, '')).toLowerCase();
  return /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(domain) && domain.length <= 253 ? domain : null;
}
// The domain and each parent, most specific first: a.b.example.test, b.example.test, example.test.
export function parentDomains(domain) {
  const labels = domain.split('.');
  return labels.slice(0, -1).map((_, i) => labels.slice(i).join('.'));
}
// Approximate registrable domain for limit keys, so subdomains of one domain share a budget.
export function baseDomain(domain) {
  const labels = domain.split('.');
  const take = labels.length > 2 && labels.at(-1).length === 2 && SECOND_LEVEL.has(labels.at(-2)) ? 3 : 2;
  return labels.slice(-take).join('.');
}

export function createSignupGuard({ limits, config, disposable = loadDisposable() }) {
  return {
    // Returns null when the open sign-up may proceed, else a reason code. Budgets are spent by
    // every attempt that passes validation, including ones for addresses that already exist.
    check(email) {
      const domain = emailDomain(email);
      if (!domain) return 'invalid_domain';
      if (parentDomains(domain).some((name) => disposable.has(name))) return 'disposable';
      const base = baseDomain(domain);
      const domainKey = `signup-domain:${base}`;
      const perDay = BIGMAIL.has(domain) ? config.signupBigmailPerDay : config.signupDomainPerDay;
      try { limits.take(domainKey, perDay, DAY, true); }
      catch (error) { if (error.code === 'rate_limited') return 'domain_limit'; throw error; }
      try { limits.take('signup-global', config.signupGlobalPerDay, DAY, true); }
      catch (error) {
        limits.refund(domainKey, true);
        if (error.code === 'rate_limited') return 'global_limit';
        throw error;
      }
      return null;
    },
  };
}
