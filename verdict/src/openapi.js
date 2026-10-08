const error = { type: 'object', properties: { error: { type: 'string' } } };
const state = { type: 'object', additionalProperties: true, properties: {
  ip: { type: 'string' }, asn: { oneOf: [{ type: 'string' }, { type: 'number' }] }, ja3: { type: 'string' },
  path: { type: 'string' }, method: { type: 'string' }, ua: { type: 'string' }, headers: { type: 'object', additionalProperties: { type: 'string' } },
  account_age_hours: { type: 'number', minimum: 0 }, prior_score: { type: 'number', minimum: 0, maximum: 1 },
  signals: { type: 'array', items: { type: 'string' } }, notes: { type: 'string' },
} };
const json = schema => ({ 'application/json': { schema } });
export const openapi = {
  openapi: '3.0.3', info: { title: 'Verdict API', version: '0.1.0', description: 'Gray-zone threat decisions. Billing coming soon.' },
  servers: [{ url: '/' }],
  components: { securitySchemes: { bearerAuth: { type: 'http', scheme: 'bearer' } }, schemas: { State: state, Error: error } },
  paths: {
    '/health': { get: { summary: 'Health check', responses: { 200: { description: 'Healthy', content: json({ type: 'object' }) } } } },
    '/v1/keys': { post: { summary: 'Create API key', description: 'The first key can be created without authentication only while no keys exist. All later requests require a valid Bearer key. Plaintext is returned once.', security: [{ bearerAuth: [] }], requestBody: { content: json({ type: 'object', properties: { name: { type: 'string' } } }) }, responses: { 201: { description: 'Created', content: json({ type: 'object', required: ['key', 'id'], properties: { key: { type: 'string' }, id: { type: 'string' }, name: { type: 'string' } } }) }, 401: { description: 'Unauthorized', content: json(error) } } } },
    '/v1/usage': { get: { summary: 'Usage for calling key since process start', security: [{ bearerAuth: [] }], responses: { 200: { description: 'Usage', content: json({ type: 'object', properties: { key_id: { type: 'string' }, decisions: { type: 'integer' }, engines: { type: 'object', additionalProperties: { type: 'integer' } }, period: { type: 'string' } } }) }, 401: { description: 'Unauthorized', content: json(error) } } } },
    '/v1/decide': { post: { summary: 'Decide allow, challenge or block', security: [{ bearerAuth: [] }], requestBody: { required: true, content: json({ oneOf: [{ $ref: '#/components/schemas/State' }, { type: 'object', required: ['state'], properties: { state: { oneOf: [{ $ref: '#/components/schemas/State' }, { type: 'string' }] } } }] }) }, responses: { 200: { description: 'Decision', content: json({ type: 'object', required: ['action', 'confidence', 'reason', 'engine', 'request_id'], properties: { action: { type: 'string', enum: ['allow', 'challenge', 'block'] }, confidence: { type: 'number', minimum: 0, maximum: 1 }, reason: { type: 'string' }, engine: { type: 'string' }, request_id: { type: 'string', format: 'uuid' } } }) }, 400: { description: 'Invalid body', content: json(error) }, 401: { description: 'Unauthorized', content: json(error) } } } },
  },
};
