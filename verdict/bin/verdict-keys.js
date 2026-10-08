#!/usr/bin/env node
import { createKeyStore } from '../src/auth/keys.js';

try {
  const [command, value, ...extra] = process.argv.slice(2);
  if (!['create', 'revoke', 'list'].includes(command) || extra.length || (command === 'list' && value) || (command === 'revoke' && !value)) {
    throw new Error('Usage: node bin/verdict-keys.js create [name] | revoke <id> | list');
  }
  const store = createKeyStore(process.env.VERDICT_KEY_FILE || 'data/keys.json');
  await store.load();
  if (command === 'create') {
    if (value !== undefined && (!value.length || value.length > 80)) throw new Error('Name must contain 1–80 characters');
    const result = await store.create(value);
    console.log(result.key);
  } else if (command === 'revoke') {
    if (!await store.revoke(value)) throw new Error('Key not found');
    console.log('Revoked');
  } else console.log(JSON.stringify(store.list(), null, 2));
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}
