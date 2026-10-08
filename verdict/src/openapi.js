const error = { type: 'object', properties: { error: { type: 'string' } } };
const state = { type: 'object', additionalProperties: true, properties: {
  ip: { type: 'string' }, asn: { oneOf: [{ type: 'string' }, { type: 'number' }] }, ja3: { type: 'string' },
  path: { type: 'string' }, method: { type: 'string' }, ua: { type: 'string' }, headers: { type: 'object', additionalProperties: { type: 'string' } },
  account_age_hours: { type: 'number', minimum: 0 }, prior_score: { type: 'number', minimum: 0, maximum: 1 },
  signals: { type: 'array', items: { type: 'string' } }, notes: { type: 'string' },
} };
const json = schema => ({ 'application/json': { schema } });
export const openapi = {
  openapi: '3.0.3', info: { title: 'Verdict API', version: '0.2.0', description: 'Threat decisions and demo edge clearance.' },
  servers: [{ url: '/' }],
  components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } }, schemas: { State: state, Error: error } },
  paths: {
    '/v1/keys/{id}/revoke': { post: { summary: 'Soft revoke API key', security: [{ bearerAuth: [] }], parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'string' } }], responses: { 200: { description: 'Revoked' }, 401: { description: 'Unauthorized' }, 404: { description: 'Key not found' } } } },
    '/v1/edge-auth': { get: { summary: 'Local forward auth (no bearer required)', description: 'Uses X-Forwarded-For, User-Agent, X-Forwarded-Method and X-Forwarded-Uri. Accept application/json for a debug decision. Valid clearance allows.', responses: { 200: { description: 'Allow' }, 401: { description: 'Challenge; Location and X-Verdict-Action headers' }, 403: { description: 'Block' } } } },
    '/challenge': { get: { summary: 'Demo JS challenge', parameters: [{ name: 'next', in: 'query', schema: { type: 'string' }, description: 'Local relative path only' }], responses: { 200: { description: 'HTML page' }, 503: { description: 'Clearance secret unset' } } } },
    '/challenge/verify': { post: { summary: 'Issue demo clearance cookie', responses: { 200: { description: 'ok: true; HttpOnly Secure SameSite=Lax cookie' }, 503: { description: 'Clearance secret unset' } } } },
    '/health': { get: { summary: 'Health check', responses: { 200: { description: 'Healthy', content: json({ type: 'object' }) } } } },
    '/v1/keys': { post: { summary: 'Create API key', description: 'The first key requires socket loopback or VERDICT_ALLOW_BOOTSTRAP=1 while no keys exist; otherwise 403 bootstrap_disabled. All later requests require a valid Bearer key. Plaintext is returned once.', security: [{ bearerAuth: [] }], requestBody: { content: json({ type: 'object', properties: { name: { type: 'string' } } }) }, responses: { 201: { description: 'Created', content: json({ type: 'object', required: ['key', 'id'], properties: { key: { type: 'string' }, id: { type: 'string' }, name: { type: 'string' } } }) }, 401: { description: 'Unauthorized', content: json(error) } } } },
    '/v1/usage': { get: { summary: 'Persistent usage for calling key', security: [{ bearerAuth: [] }], responses: { 200: { description: 'Usage', content: json({ type: 'object', properties: { key_id: { type: 'string' }, decisions: { type: 'integer' }, engines: { type: 'object', additionalProperties: { type: 'integer' } }, period: { type: 'string' } } }) }, 401: { description: 'Unauthorized', content: json(error) } } } },
    '/v1/decide': { post: { summary: 'Decide allow, challenge or block', security: [{ bearerAuth: [] }], requestBody: { required: true, content: json({ oneOf: [{ $ref: '#/components/schemas/State' }, { type: 'object', required: ['state'], properties: { state: { oneOf: [{ $ref: '#/components/schemas/State' }, { type: 'string' }] } } }] }) }, responses: { 200: { description: 'Decision', content: json({ type: 'object', required: ['action', 'confidence', 'reason', 'engine', 'request_id'], properties: { action: { type: 'string', enum: ['allow', 'challenge', 'block'] }, confidence: { type: 'number', minimum: 0, maximum: 1 }, reason: { type: 'string' }, engine: { type: 'string' }, request_id: { type: 'string', format: 'uuid' } } }) }, 400: { description: 'Invalid body', content: json(error) }, 401: { description: 'Unauthorized', content: json(error) } } } },
  },
};
