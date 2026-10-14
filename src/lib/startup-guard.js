export const DEFAULT_AGENT_TOKEN = 'fastdog-local-dev-token';

// Development credentials require an explicit opt-in, including in tests.
export function assertSafeStartup(env = process.env) {
  if (env.FASTDOG_ALLOW_DEV_TOKEN === '1') return;
  const token = env.AGENT_TOKEN;
  if (typeof token !== 'string' || token.trim() === '') throw new Error('AGENT_TOKEN must be set');
  if (token === DEFAULT_AGENT_TOKEN) throw new Error('AGENT_TOKEN must not be the built-in default');
}
