import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRoutes, defaultUpstream, ROOT } from '../src/lib/config.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

describe('config', () => {
  it('loads routes.yaml with demo host', () => {
    const { routes, file } = loadRoutes(path.join(ROOT, 'config/routes.yaml'));
    assert.ok(file.endsWith('routes.yaml'));
    assert.equal(routes.get('demo.fastdog.local'), 'http://127.0.0.1:9999');
  });

  it('defaultUpstream falls back to mock', () => {
    const prev = process.env.DEFAULT_UPSTREAM;
    delete process.env.DEFAULT_UPSTREAM;
    assert.equal(defaultUpstream(), 'http://127.0.0.1:9999');
    if (prev !== undefined) process.env.DEFAULT_UPSTREAM = prev;
  });
});
