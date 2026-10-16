// Match the Website page: live means a verified claim with a connected agent,
// not an independent HTTPS or application health probe.
export function startState(hostnames) {
  const live = hostnames.some((host) => host.status === 'active' && host.agent?.connected === true);
  const connected = hostnames.some((host) => host.agent?.connected === true);
  const current = live ? 3 : connected ? 2 : hostnames.length ? 1 : 0;
  return { live, steps: [0, 1, 2].map((index) => index < current ? 'done' : index === current ? 'current' : 'next') };
}
export async function loginDestination(api) {
  try {
    const { hostnames } = await api('/api/hostnames');
    return startState(hostnames).live ? '/hostname' : '/start';
  } catch { return '/start'; } // A status outage must not strand a successful login.
}
