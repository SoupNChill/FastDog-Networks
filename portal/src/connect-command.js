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
// URL.hostname has already canonicalised numeric addresses (including mapped IPv4).
function blockedOriginHost(host) {
  if (!host.includes(':')) {
    const octets = host.split('.').map(Number);
    if (octets.length !== 4 || octets.some((n) => !Number.isInteger(n))) return false;
    const ip = octets.reduce((value, n) => value * 256 + n, 0);
    // 0.0.0.0, 169.254.0.0/16 and 100.64.0.0/10.
    return ip === 0 || Math.floor(ip / 65536) === 0xa9fe || Math.floor(ip / 4194304) === 0x191;
  }
  const halves = host.split('::').map((part) => part ? part.split(':') : []);
  const words = halves.length === 2 ? [...halves[0], ...Array(8 - halves[0].length - halves[1].length).fill('0'), ...halves[1]] : halves[0];
  const ip = words.reduce((value, word) => (value << 16n) + BigInt(`0x${word}`), 0n);
  return ip >> 118n === 0x3fan // fe80::/10
    || ip >> 96n === 0xfd000ec2n // fd00:ec2::/32
    || ip >> 32n === 0x64ff9b0000000000000000n // 64:ff9b::/96
    || (ip >> 32n === 0xffffn && blockedOriginHost([24n, 16n, 8n, 0n].map((shift) => Number((ip >> shift) & 255n)).join('.')));
}
export const LINK_LOCAL_ERROR = "Link-local and restricted addresses (169.254.0.0/16, fe80::/10, fd00:ec2::/32, 64:ff9b::/96, 100.64.0.0/10, 0.0.0.0, including IPv4-mapped forms) are not allowed as an origin. Use 127.0.0.1 or your app's private address.";
export function originError(input) {
  const text = String(input ?? '').trim();
  try {
    const host = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`).hostname.replace(/^\[|\]$/g, '');
    if (blockedOriginHost(host)) return LINK_LOCAL_ERROR;
  } catch { /* generic error */ }
  return null;
}
// Same suffix as the browser builder: sanitised hostname plus 10 hex of sha256(hostname), so lookalike hostnames never share a name.
export function agentSuffix(hostname) {
  const full = String(hostname).toLowerCase();
  const slug = full.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40).replace(/-+$/, '');
  return `${slug}-${createHash('sha256').update(full).digest('hex').slice(0, 10)}`;
}

export function validOrigin(input) {
  const text = String(input ?? '').trim();
  if (!text || text.length > 200 || /[\s'"<>\\`$;|&]/.test(text)) return null;
  let url;
  try { url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : `http://${text}`); } catch { return null; }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || (url.pathname && url.pathname !== '/') || !url.port) return null;
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (blockedOriginHost(host)) return null;
  const local = host === 'localhost' || host === '::1' || host === 'host.docker.internal' || PRIVATE_V4.test(host)
    || /^(?:fc|fd)[0-9a-f]{2}:/i.test(host);
  return local ? `${url.protocol}//${url.host}` : null;
}

export const dockerEnvFile = (hostname) => `fastdog-agent-${agentSuffix(hostname)}.env`;

function commandEnv(agentEnv, origin) {
  const upstream = validOrigin(origin);
  if (!agentEnv?.AGENT_TOKEN || !agentEnv.AGENT_HOSTNAME || !agentEnv.EDGE_HTTP_URL || !upstream) return null;
  const env = { AGENT_TOKEN: agentEnv.AGENT_TOKEN, AGENT_HOSTNAME: agentEnv.AGENT_HOSTNAME, AGENT_NAME: agentEnv.AGENT_NAME || agentEnv.AGENT_HOSTNAME,
    EDGE_HTTP_URL: agentEnv.EDGE_HTTP_URL,
    EDGE_WS_URL: agentEnv.EDGE_WS_URL || `${agentEnv.EDGE_HTTP_URL.replace(/^http/, 'ws').replace(/\/$/, '')}/_fastdog/tunnel`,
    AGENT_LOCAL_UPSTREAM: upstream };
  return Object.values(env).every((value) => typeof value === 'string' && !/[\r\n\0]/.test(value)) ? env : null;
}

export function serializeDockerEnv(agentEnv, origin) {
  const env = commandEnv(agentEnv, origin);
  return env ? Object.entries(env).map(([key, value]) => `${key}=${value}\n`).join('') : null;
}

export function dockerRun(hostname, envFilePath = 'ENV_FILE') {
  if (envFilePath !== 'ENV_FILE' && !/^\/[a-zA-Z0-9/_.-]+$/.test(envFilePath)) throw new Error('Invalid env file path');
  return `docker run -d --name fastdog-agent-${agentSuffix(hostname)} --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file ${envFilePath} ${AGENT_IMAGE}`;
}

export function dockerDetails(hostname) {
  return { container_name: `fastdog-agent-${agentSuffix(hostname)}`, image: AGENT_IMAGE, run: dockerRun(hostname) };
}

export function buildCommand(agentEnv, { platform = 'linux', portalOrigin, origin }) {
  const env = commandEnv(agentEnv, origin);
  if (!env) return null;
  if (platform === 'linux') {
    return `curl -fsSL ${shellQuote(new URL('/install/agent.sh', portalOrigin).href)} -o /tmp/fastdog-agent-install.sh && sudo FASTDOG_AGENT_TOKEN=${shellQuote(env.AGENT_TOKEN)} bash /tmp/fastdog-agent-install.sh --edge ${shellQuote(env.EDGE_HTTP_URL)} --hostname ${shellQuote(env.AGENT_HOSTNAME)} --origin ${shellQuote(env.AGENT_LOCAL_UPSTREAM)}`;
  }
  if (platform === 'docker') {
    // Identical to the browser's Docker tab: host networking reaches an app on 127.0.0.1; the stable name lets a re-run replace the agent.
    const name = `fastdog-agent-${agentSuffix(env.AGENT_HOSTNAME)}`;
    const envFile = dockerEnvFile(env.AGENT_HOSTNAME);
    // Pull first so a failed pull never leaves the token file on disk.
    return `umask 077; docker pull ${AGENT_IMAGE} && rm -f ${envFile} && (set -C; printf '%s\\n' ${Object.entries(env).map(([k, v]) => shellQuote(`${k}=${v}`)).join(' ')} > ${envFile}) && chmod 600 ${envFile} && { docker rm -f ${name} >/dev/null 2>&1; true; } && docker run -d --name ${name} --network host --cap-drop ALL --security-opt no-new-privileges --restart unless-stopped --env-file ${envFile} ${AGENT_IMAGE} || { rm -f ${envFile}; false; }`;
  }
  return null;
}
