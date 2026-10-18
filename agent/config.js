// Environment schema and image-pinned edge selection. Error messages name settings, never their values.
import { readFileSync } from 'node:fs';

export const KNOWN_AGENT_ENV = ['AGENT_BOOTSTRAP', 'AGENT_DEPLOYMENT_ID', 'AGENT_ENV_FORMAT', 'AGENT_HOSTNAME', 'AGENT_LOCAL_UPSTREAM', 'AGENT_NAME', 'AGENT_TOKEN'];
export const ENV_FORMATS = ['1'];
export const TUNNEL_PATH = '/_fastdog/tunnel';
const AUDIENCE = /^https:\/\/[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+(:[1-9][0-9]{0,4})?$/;

export class ConfigError extends Error {
  constructor(code, message) { super(message); this.code = code; }
}

// Immutable edge audiences baked into the image. Env may select one of these; it can never add a host.
export function loadPins(file = new URL('./edge-pins.json', import.meta.url)) {
  const pins = JSON.parse(readFileSync(file, 'utf8'));
  if (pins?.version !== 1 || !Array.isArray(pins.audiences) || Object.keys(pins).length !== 2 || !pins.audiences.every((a) => typeof a === 'string' && AUDIENCE.test(a))) {
    throw new ConfigError('pins_invalid', 'The image edge pin list is invalid.');
  }
  return Object.freeze([...pins.audiences]);
}

export function readSettings(env = process.env) {
  const unknown = Object.keys(env).filter((k) => k.startsWith('AGENT_') && !KNOWN_AGENT_ENV.includes(k)).sort();
  if (unknown.length) throw new ConfigError('unknown_env', `Unsupported agent settings: ${unknown.join(', ')}. Remove them or use an image that supports them.`);
  const value = (name) => (env[name] === undefined || env[name] === '' ? undefined : env[name]);
  const format = value('AGENT_ENV_FORMAT');
  if (format !== undefined && !ENV_FORMATS.includes(format)) throw new ConfigError('unsupported_format', 'AGENT_ENV_FORMAT is not supported by this agent image.');
  return {
    token: value('AGENT_TOKEN'), bootstrap: value('AGENT_BOOTSTRAP'), deploymentId: value('AGENT_DEPLOYMENT_ID'),
    name: value('AGENT_NAME') ?? '', hostname: value('AGENT_HOSTNAME') ?? '',
    localUpstream: (value('AGENT_LOCAL_UPSTREAM') ?? 'http://127.0.0.1:9999').replace(/\/$/, ''),
    edgeHttpRaw: value('EDGE_HTTP_URL'), edgeWsRaw: value('EDGE_WS_URL'),
    // Legacy defaults are unchanged from 0.1.2.
    edgeHttp: value('EDGE_HTTP_URL') ?? 'http://127.0.0.1:8787', edgeWs: value('EDGE_WS_URL') ?? 'ws://127.0.0.1:8787/_fastdog/tunnel',
  };
}

// Key-bound modes: HTTPS/WSS on exactly one pinned authority. Returns the audience and the two endpoints.
export function pinnedEdge(settings, pins) {
  const http = settings.edgeHttpRaw?.replace(/\/$/, '');
  if (!http || !pins.includes(http)) throw new ConfigError('edge_not_pinned', 'EDGE_HTTP_URL is not an edge allowed by this agent image.');
  const ws = `${http.replace(/^https:/, 'wss:')}${TUNNEL_PATH}`;
  if (settings.edgeWsRaw !== undefined && settings.edgeWsRaw !== ws) throw new ConfigError('edge_not_pinned', 'EDGE_WS_URL must be the tunnel address of the selected edge.');
  return { audience: http, http, ws };
}

export function bootstrapBinding(settings) {
  if (!/^fdab_[A-Za-z0-9_-]{43}$/.test(settings.bootstrap ?? '')) throw new ConfigError('bootstrap_malformed', 'AGENT_BOOTSTRAP is malformed. Request a fresh connect command.');
  return requiredBinding(settings);
}

export function requiredBinding(settings) {
  if (!/^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(settings.hostname)) throw new ConfigError('hostname_invalid', 'AGENT_HOSTNAME is missing or invalid.');
  if (!/^[A-Za-z0-9_-]{1,128}$/.test(settings.deploymentId ?? '')) throw new ConfigError('deployment_invalid', 'AGENT_DEPLOYMENT_ID is missing or invalid.');
  let url;
  try { url = new URL(settings.localUpstream); } catch { url = null; }
  if (!url || !['http:', 'https:'].includes(url.protocol) || `${url.protocol}//${url.host}` !== settings.localUpstream) throw new ConfigError('origin_invalid', 'AGENT_LOCAL_UPSTREAM is missing or invalid.');
  return { hostname: settings.hostname, origin: settings.localUpstream, deployment_id: settings.deploymentId };
}
