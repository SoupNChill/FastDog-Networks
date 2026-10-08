#!/usr/bin/env node
import { asnDb } from '../src/asn/lookup.js';
const file = process.argv[2] || process.env.VERDICT_ASN_FILE || 'fixtures/asn-fixture.tsv';
const before = process.memoryUsage().rss;
await asnDb.loadFile(file);
const after = process.memoryUsage().rss;
console.log(JSON.stringify({ file, rows: asnDb.rows, rss_before_bytes: before, rss_after_bytes: after, rss_delta_bytes: after - before }));
