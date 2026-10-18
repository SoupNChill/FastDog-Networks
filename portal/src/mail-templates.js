// Plain-text transactional templates. Subjects are fixed per kind; only the link/code vary.
const footer = '\n\nIf you did not expect this message, you can ignore it.\n\n-- FastDog Networks\n';
const templates = {
  'verify-email': ({ link }) => ({ subject: 'Confirm your FastDog email address',
    text: `Confirm your email address to finish setting up your FastDog account:\n\n${link}\n\nThis link expires in one hour and works once.${footer}` }),
  'password-reset': ({ link }) => ({ subject: 'Reset your FastDog password',
    text: `Someone asked to reset the password for this FastDog account. To choose a new password, open:\n\n${link}\n\nThis link expires in one hour and works once. Resetting signs out every session.${footer}` }),
  invite: ({ link, code }) => ({ subject: 'Your FastDog invitation',
    text: `You have been invited to FastDog. Sign up with this email address at:\n\n${link}\n\nInvite code: ${code}\n\nThe code works once and expires; contact support if it has lapsed.${footer}` }),
  'domain-request': ({ link }) => ({ subject: 'New FastDog domain request',
    text: `A tenant submitted a domain request. Review it in the portal:\n\n${link}\n\nNo purchase has been made.${footer}` }),
};
export const mailKinds = Object.keys(templates);
export function renderMail({ kind, link, code }) {
  if (!Object.hasOwn(templates, kind)) throw new Error('Unknown mail kind');
  if (typeof link !== 'string' || !link || (kind === 'invite' && (typeof code !== 'string' || !code))) throw new Error('Invalid mail content');
  return templates[kind]({ link, code });
}
