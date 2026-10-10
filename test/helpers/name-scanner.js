import { existsSync, readdirSync, readFileSync, lstatSync } from 'node:fs';
import { join, relative, sep, basename } from 'node:path';
import { createHash } from 'node:crypto';

export const scanRoots = ['portal', 'src/onboard', 'src/control', 'src/edge', 'src/internal',
  'test', 'deploy/caddy', 'docs/TENANT_API.md', 'docs/INTERNAL_API_OPS.md', 'docs/SELF_SERVE_PLAN.md'];
const sensitiveFile = /(?:^|\.)env(?:\.|$)|\.(?:pem|key|p12|pfx)$/i;
export const lineHash = (line) => createHash('sha256').update(line).digest('hex');

export function* filesUnder(root, path = root) {
  if (!existsSync(path)) return;
  const stat = lstatSync(path);
  if (stat.isSymbolicLink()) return;
  if (stat.isDirectory()) {
    if (['node_modules', '.git'].includes(basename(path)) || basename(path).startsWith('.tmp-')) return;
    for (const name of readdirSync(path).sort()) yield* filesUnder(root, join(path, name));
  } else if (stat.isFile() && !sensitiveFile.test(basename(path))) yield path;
}

export function deniedLines(source, denyNames) {
  return source.split(/\r?\n/).flatMap((line, index) => {
    const lowered = line.toLowerCase();
    return denyNames.some((name) => lowered.includes(name)) ? [{ line: index + 1, hash: lineHash(line) }] : [];
  });
}

export function scanText(path, source, denyNames, allow = {}) {
  const hits = deniedLines(source, denyNames);
  const rule = allow[path];
  if (rule?.data || rule?.documentation) return [];
  const remaining = { ...rule?.lines };
  return hits.filter(({ hash }) => {
    if (remaining[hash] > 0) { remaining[hash]--; return false; }
    return true;
  }).map(({ line }) => ({ path, line }));
}

export function scanRepository(root, denyNames, allow) {
  const errors = [];
  for (const base of scanRoots) for (const file of filesUnder(root, join(root, base))) {
    const buffer = readFileSync(file);
    if (buffer.includes(0)) continue;
    const path = relative(root, file).split(sep).join('/');
    errors.push(...scanText(path, buffer.toString('utf8'), denyNames, allow));
  }
  return errors;
}

export function hostnameViolations(source) {
  const violations = new Set();
  // Inspect literal text, skipping comments and template expressions with balanced braces.
  const literals = [];
  let index = 0;
  function code(inExpression = false) {
    let depth = 0;
    while (index < source.length) {
      const char = source[index];
      if (source.startsWith('//', index)) {
        const end = source.indexOf('\n', index);
        index = end < 0 ? source.length : end + 1;
      } else if (source.startsWith('/*', index)) {
        const end = source.indexOf('*/', index + 2);
        index = end < 0 ? source.length : end + 2;
      } else if (["'", '"', '`'].includes(char)) {
        index++;
        literal(char);
      } else if (char === '{') { depth++; index++; }
      else if (char === '}') {
        index++;
        if (inExpression && depth === 0) return;
        depth--;
      } else index++;
    }
  }
  function literal(quote) {
    let value = '';
    while (index < source.length) {
      const char = source[index++];
      if (char === '\\') { value += char + (source[index++] || ''); continue; }
      if (char === quote) break;
      if (quote === '`' && char === '$' && source[index] === '{') {
        literals.push(value);
        value = '';
        index++;
        code(true);
      } else value += char;
    }
    literals.push(value);
  }
  code();
  for (const literal of literals) {
    const text = literal.replace(/\\u([0-9a-f]{4})/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16))).replace(/%[0-9a-f]{2}/gi, '.');
    const domains = text.match(/(?:[a-z0-9*][a-z0-9*-]*\.)+[a-z]{2,63}\.?/gi) || [];
    for (const domain of domains) {
      const host = domain.toLowerCase().replace(/\.$/, '');
      if (/\.(?:js|cjs|mjs|json|md|css|html|txt|yaml|yml|snippet)$/.test(host)) continue;
      if (['example.com', 'example.test', 'example-edge.test'].some((suffix) => host === suffix || host.endsWith(`.${suffix}`)) || /\.(?:invalid|test|example|local|lan|internal|localhost)$/.test(host)) continue; // RFC 6761 / reserved-suffix names never resolve publicly
      violations.add(host);
    }
  }
  return [...violations];
}
