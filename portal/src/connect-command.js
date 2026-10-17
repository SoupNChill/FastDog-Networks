// Server-side twin of the browser connect command (portal/public/js/agent-view.js), used by the
// connect-token API so an AI assistant gets the same command a person would copy.
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';

// Single source of truth: the pinned image in the browser command builder.
export const AGENT_IMAGE = (() => {
  const source = readFileSync(new URL('../public/js/agent-view.js', import.meta.url), 'utf8');
  const match = source.match(/const AGENT_IMAGE = '([a-z0-9./:@_-]+)';/);
  if (!match) throw new Error('Agent image pin not found');
  return match[1];
})();
const shellQuote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
const PRIVATE_V4 = /^(?:127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.)/;
// Link-local (cloud metadata 169.254.0.0/16, fe80::/10, and the IPv4-mapped form) is never a valid origin: host networking would expose it to the agent.
const LINK_LOCAL = /^(?:169\.254\.|fe[89ab][0-9a-f]:|::ffff:(?:169\.254\.|a9fe:))/i;
export const LINK_LOCAL_ERROR = "Link-local addresses (169.254.0.0/16, fe80::/10) are not allowed as an origin. Use 127.0.0.1 or your app's private address.";
export function originError(input) {
  const text = String(input ?? '').trim();
  try {
    const host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`).hostname.replace(/^\[|\]$/g, '');
    if (LINK_LOCAL.test(host)) return LINK_LOCAL_ERROR;
  } catch { /* generic error */ }
  return null;
}
// Same suffix as the browser builder: sanitised hostname plus 6 hex of sha256(hostname), so lookalike hostnames never share a name.
export function agentSuffix(hostname) {
  const full = String(hostname).toLowerCase();
  const slug = full.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
  return `${slug}-${createHash('sha256').update(full).digest('hex').slice(0, 6)}`;
}

export function validOrigin(input) {
  const text = String(input ?? '').trim();
  if (!text || text.length > 200 || /[\s'"<>\\`$;|&]/.test(text)) return null;
  let url;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || (url.pathname && url.pathname !== '/') || !url.port) return null;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (LINK_LOCAL.test(host)) return null;
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
    // Identical to the browser's Docker tab: host networking reaches an app on 127.0.0.1; the stable name lets a re-run replace the agent.
    const name = `fastdog-agent-${agentSuffix(env.AGENT_HOSTNAME)}`;
    const envFile = `${name}.env`;
    return `umask 077; printf '%s\\n' ${Object.entries(env).map(([k, v]) => shellQuote(`${k}=${v}`)).join(' ')} > ${envFile} && chmod 600 ${envFile} && docker pull ${AGENT_IMAGE} && { docker rm -f ${name} >/dev/null 2>&1; true; } && docker run -d --name ${name} --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file ${envFile} ${AGENT_IMAGE}`;
  }
  return null;
}
