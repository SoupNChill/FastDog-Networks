export const DEFAULT_AGENT_TOKEN = 'fastdog-local-dev-token';

// Refuse to serve with a missing or well-known operator token. NODE_ENV=test never reaches this (no listeners).
export function assertSafeStartup(env = process.env) {
  const token = env.AGENT_TOKEN;
  if (typeof token !== 'string' || token.trim() === '') throw new Error('AGENT_TOKEN must be set');
  if (token === DEFAULT_AGENT_TOKEN) throw new Error('AGENT_TOKEN must not be the built-in default');
}
