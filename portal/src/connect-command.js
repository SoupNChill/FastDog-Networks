// Server-side twin of the browser connect command (portal/public/js/agent-view.js), used by the
// connect-token API so an AI assistant gets the same command a person would copy.
const AGENT_IMAGE = 'ghcr.io/soupnchill/fastdog-agent:0.1.0@sha256:9597421f707d048d6f904b239ac7e7e536cbd06959999cdc4e5c4ee44092a5a1';
const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
const PRIVATE_V4 = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)/;

export function validOrigin(input) {
  const text = String(input ?? '').trim();
  if (!text || text.length > 200 || /[\s'"<>\\`$;|&]/.test(text)) return null;
  let url;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || (url.pathname && url.pathname !== '/') || !url.port) return null;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const local = host === 'localhost' || host === '::1' || host === 'host.docker.internal' || PRIVATE_V4.test(host)
    || /^(?:fc|fd)[0-9a-f]{2}:/i.test(host) || /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(host);
  return local ? `${url.protocol}//${url.host}` : null;
}

export function buildCommand(agentEnv, { platform = 'linux', portalOrigin, origin }) {
  const upstream = validOrigin(origin);
  if (!agentEnv?.AGENT_TOKEN || !agentEnv.AGENT_HOSTNAME || !agentEnv.EDGE_HTTP_URL || !upstream) return null;
  const env = { AGENT_TOKEN: agentEnv.AGENT_TOKEN, AGENT_HOSTNAME: agentEnv.AGENT_HOSTNAME, AGENT_NAME: agentEnv.AGENT_NAME || agentEnv.AGENT_HOSTNAME,
    EDGE_HTTP_URL: agentEnv.EDGE_HTTP_URL,
    EDGE_WS_URL: agentEnv.EDGE_WS_URL || `${agentEnv.EDGE_HTTP_URL.replace(/^http/, 'ws').replace(/\/$/, '')}/_fastdog/tunnel`,
    AGENT_LOCAL_UPSTREAM: upstream };
  if (platform === 'linux') {
    return `curl -fsSL ${shellQuote(new URL('/install/agent.sh', portalOrigin).href)} -o /tmp/fastdog-agent-install.sh && sudo FASTDOG_AGENT_TOKEN=${shellQuote(env.AGENT_TOKEN)} bash /tmp/fastdog-agent-install.sh --edge ${shellQuote(env.EDGE_HTTP_URL)} --hostname ${shellQuote(env.AGENT_HOSTNAME)} --origin ${shellQuote(env.AGENT_LOCAL_UPSTREAM)}`;
  }
  if (platform === 'docker') {
    return `umask 077; printf '%s\\n' ${Object.entries(env).map(([k, v]) => shellQuote(`${k}=${v}`)).join(' ')} > fastdog-agent.env && chmod 600 fastdog-agent.env && docker run -d --restart unless-stopped --env-file fastdog-agent.env ${AGENT_IMAGE}`;
  }
  return null;
}
