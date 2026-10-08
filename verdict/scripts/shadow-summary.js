#!/usr/bin/env node
import { writeShadowSummary, buildShadowSummary } from '../src/shadow/summary.js';
const file = process.env.VERDICT_SHADOW_FILE || 'data/shadow.jsonl';
const outDir = process.env.VERDICT_SHADOW_SUMMARY_DIR || 'data';
if (process.argv.includes('--stdout')) {
  console.log(JSON.stringify(await buildShadowSummary(file), null, 2));
} else {
  const { out, summary } = await writeShadowSummary(file, outDir);
  console.log(JSON.stringify({ wrote: out, counts: summary.counts }));
}
