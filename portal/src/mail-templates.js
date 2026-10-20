// Plain-text transactional templates. Subjects are fixed per kind; only the link/code (or owner lines) vary.
const footer = '\n\nIf you did not expect this message, you can ignore it.\n\n-- FastDog Networks\n';
const ownerFooter = '\n\nOperator notice from the FastDog portal (owner notifications).\n\n-- FastDog Networks\n';
const templates = {
  'verify-email': ({ link }) => ({ subject: 'Confirm your FastDog email address',
    text: `Confirm your email address to finish setting up your FastDog account:\n\n${link}\n\nThis link expires in one hour and works once.${footer}` }),
  'password-reset': ({ link }) => ({ subject: 'Reset your FastDog password',
    text: `Someone asked to reset the password for this FastDog account. To choose a new password, open:\n\n${link}\n\nThis link expires in one hour and works once. Resetting signs out every session.${footer}` }),
  invite: ({ link, code }) => ({ subject: 'Your FastDog invitation',
    text: `You have been invited to FastDog. Sign up with this email address at:\n\n${link}\n\nInvite code: ${code}\n\nThe code works once and expires; contact support if it has lapsed.${footer}` }),
  'domain-request': ({ link }) => ({ subject: 'New FastDog domain request',
    text: `A tenant submitted a domain request. Review it in the portal:\n\n${link}\n\nNo purchase has been made.${footer}` }),
  'owner-event': ({ lines, count }) => ({ subject: count > 1 ? `FastDog: ${count} new events` : 'FastDog: new account activity',
    text: `${lines.join('\n')}${ownerFooter}` }),
  'owner-digest': ({ lines, date }) => ({ subject: `FastDog daily summary${date ? ` ${date}` : ''}`, text: `${lines.join('\n')}${ownerFooter}` }),
};
export const mailKinds = Object.keys(templates);
// Operator-only kinds carry rendered lines instead of a link and are never budget-reserved.
export const OWNER_KINDS = new Set(['owner-event', 'owner-digest']);
// One printable line: no control, format (bidi) or line/paragraph separator characters.
const ownerLine = (line) => typeof line === 'string' && line.length <= 200 && /^[^\p{Cc}\p{Cf}\p{Zl}\p{Zp}]*$/u.test(line);
export function renderMail({ kind, link, code, lines, count, date }) {
  if (!Object.hasOwn(templates, kind)) throw new Error('Unknown mail kind');
  if (OWNER_KINDS.has(kind)) {
    if (!Array.isArray(lines) || lines.length < 1 || lines.length > 300 || !lines.every(ownerLine)
      || (count !== undefined && (!Number.isInteger(count) || count < 1 || count > 300))
      || (date !== undefined && (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date)))) throw new Error('Invalid mail content');
    return templates[kind]({ lines, count, date });
  }
  if (typeof link !== 'string' || !link || (kind === 'invite' && (typeof code !== 'string' || !code))) throw new Error('Invalid mail content');
  return templates[kind]({ link, code });
}
