#!/usr/bin/env node
// One-time maintenance for shadow data written before 0.3.3. Run with the tailer STOPPED.
// Usage: node shadow-cleanup.mjs plan|apply <shadow.jsonl> <summary-dir> [--dedupe latest|all]
// - shadow.jsonl: strips the query string from every row's path and drops re-scan duplicate blocks.
//   A row is a duplicate when (ts, host, path without query, method, ip_prefix) matches an earlier
//   row; only contiguous runs of >= 50 duplicates are dropped (isolated matches may be real bursts).
//   --dedupe latest (default) drops the last such run, --dedupe all drops every run. Untouched
//   rows keep their exact bytes; order is preserved.
// - summary-dir: strips query strings from every "path" in shadow-summary-*.json.
// NUL bytes are stripped from every line (NUL-only lines are removed).
// Prints counts only (never IPs, user agents or paths). apply writes temp file + fsync + rename.
import { readFile, readdir, stat, open, rename, unlink } from 'node:fs/promises';
import { basename, dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { stripQuery } from '../src/shadow/summary.js';
import { cleanLine } from '../src/shadow/lines.js';

const MIN_RUN = 50;
const usage = () => {
  console.error('usage: node shadow-cleanup.mjs plan|apply <shadow.jsonl> <summary-dir> [--dedupe latest|all]');
  process.exit(2);
};
const [mode, shadowFile, summaryDir, ...rest] = process.argv.slice(2);
let dedupe = 'latest';
if (!['plan', 'apply'].includes(mode) || !shadowFile || !summaryDir) usage();
if (rest.length) {
  if (rest.length !== 2 || rest[0] !== '--dedupe' || !['latest', 'all'].includes(rest[1])) usage();
  dedupe = rest[1];
}

if (mode === 'apply' && Date.now() - (await stat(shadowFile)).mtimeMs < 5000) {
  console.error('refusing: shadow file modified in the last 5 s (is the tailer running?)');
  process.exit(2);
}

// Shadow rows.
const text = await readFile(shadowFile, 'utf8');
const trailingNewline = text.endsWith('\n');
const lines = text.split('\n');
if (trailingNewline) lines.pop();
const out = lines.slice();
const dup = new Array(lines.length).fill(false);
const ts = [];
const seen = new Set();
const emptied = new Set(); // lines that were only NUL bytes: removed
let rows = 0, rowsWithQuery = 0, linesCleaned = 0;
lines.forEach((raw, i) => {
  const line = cleanLine(raw);
  if (line !== raw) {
    linesCleaned++;
    out[i] = line;
    if (!line.trim()) { emptied.add(i); return; }
  }
  let row;
  try { row = JSON.parse(line); } catch { return; }
  if (!row || typeof row !== 'object' || Array.isArray(row)) return;
  rows++;
  ts[i] = row.ts ?? null;
  const path = stripQuery(row.path);
  if (path !== row.path) { rowsWithQuery++; out[i] = JSON.stringify({ ...row, path }); }
  const key = JSON.stringify([row.ts, row.host, path, row.method, row.ip_prefix]);
  if (seen.has(key)) dup[i] = true;
  else seen.add(key);
});

const runs = [];
for (let i = 0; i < lines.length;) {
  if (!dup[i]) { i++; continue; }
  let j = i;
  while (j + 1 < lines.length && dup[j + 1]) j++;
  const count = j - i + 1;
  if (count >= MIN_RUN) runs.push({ start_index: i, end_index: j, count, first_ts: ts[i], last_ts: ts[j] });
  i = j + 1;
}
const drop = new Set();
for (const run of dedupe === 'all' ? runs : runs.slice(-1)) {
  for (let k = run.start_index; k <= run.end_index; k++) drop.add(k);
}
const kept = out.filter((_, i) => !drop.has(i) && !emptied.has(i));
const shadowText = kept.length ? kept.join('\n') + (trailingNewline ? '\n' : '') : '';

// Summaries.
let summaryPathsChanged = 0;
const summariesWithQuery = [];
const summaryWrites = [];
function stripPaths(value) {
  let n = 0;
  const walk = (v) => {
    if (Array.isArray(v)) { v.forEach(walk); return; }
    if (!v || typeof v !== 'object') return;
    for (const [k, val] of Object.entries(v)) {
      if (k === 'path' && typeof val === 'string') {
        const clean = stripQuery(val);
        if (clean !== val) { v[k] = clean; n++; }
      } else walk(val);
    }
  };
  walk(value);
  return n;
}
let names = [];
try { names = (await readdir(summaryDir)).filter(n => /^shadow-summary-.*\.json$/.test(n)).sort(); }
catch (error) { if (error.code !== 'ENOENT') throw error; }
let summariesUnreadable = 0;
for (const name of names) {
  let summary;
  try { summary = JSON.parse(await readFile(join(summaryDir, name), 'utf8')); } catch { summariesUnreadable++; continue; }
  const n = stripPaths(summary);
  if (!n) continue;
  summaryPathsChanged += n;
  summariesWithQuery.push(name);
  summaryWrites.push([join(summaryDir, name), JSON.stringify(summary, null, 2)]);
}

const result = {
  rows,
  rows_with_query: rowsWithQuery,
  lines_cleaned: linesCleaned,
  dedupe,
  dup_runs: runs,
  would_drop: drop.size,
  summaries_with_query: summariesWithQuery,
  summary_paths_changed: summaryPathsChanged,
  summaries_unreadable: summariesUnreadable,
};

async function replaceFile(file, content) {
  const dir = dirname(file);
  const temp = join(dir, `.${basename(file)}.${randomUUID()}.tmp`);
  const handle = await open(temp, 'wx', 0o600);
  try {
    await handle.writeFile(content);
    await handle.sync();
  } finally { await handle.close(); }
  try { await rename(temp, file); } catch (error) { await unlink(temp).catch(() => {}); throw error; }
  const dirHandle = await open(dir, 'r');
  try { await dirHandle.sync(); } catch { /* Directory fsync is best effort. */ } finally { await dirHandle.close(); }
}

if (mode === 'apply') {
  if (shadowText !== text) await replaceFile(shadowFile, shadowText);
  for (const [file, content] of summaryWrites) await replaceFile(file, content);
  result.applied = true;
}
console.log(JSON.stringify(result));
