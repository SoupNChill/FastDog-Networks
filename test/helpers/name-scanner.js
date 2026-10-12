import { existsSync, readdirSync, readFileSync, lstatSync } from 'node:fs';
import { join, relative, sep, basename } from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const sensitiveFile = /^\.env(?:\.|$)|\.(?:pem|key|p12|pfx)$/i;
// Exact paths only; each unscannable exemption must explain why it is required.
export const unscannableAllow = Object.freeze({
  '.env.example': 'Existing environment template; never read environment files.',
  'deploy/prod1-fastdog-agent/.env.example': 'Existing agent environment template; never read environment files.',
  'site/apple-touch-icon.png': 'Existing PNG touch icon used by the site.',
  'site/favicon-32.png': 'Existing PNG favicon used by the site.',
  'site/fonts/Mulish-Regular.ttf': 'Existing binary font used by the site typography.',
  'site/fonts/Mulish-SemiBold.ttf': 'Existing binary font used by the site typography.',
  'site/fonts/SpaceGrotesk-Bold.ttf': 'Existing binary font used by the site typography.',
  'site/fonts/SpaceGrotesk-Medium.ttf': 'Existing binary font used by the site typography.',
  'portal/public/fonts/Mulish-Regular.ttf': 'Portal copy of the site font.',
  'portal/public/fonts/Mulish-SemiBold.ttf': 'Portal copy of the site font.',
  'portal/public/fonts/SpaceGrotesk-Bold.ttf': 'Portal copy of the site font.',
  'portal/public/fonts/SpaceGrotesk-Medium.ttf': 'Portal copy of the site font.',
  'site/og/og.png': 'Existing PNG social preview image used by the site.',
  'verdict/.env.example': 'Existing service environment template; never read environment files.',
});
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
  if (path === 'test/deny-names.json' && rule?.data === true) return [];
  const remaining = { ...rule?.lines };
  return hits.filter(({ hash }) => {
    if (remaining[hash] > 0) { remaining[hash]--; return false; }
    return true;
  }).map(({ line }) => ({ path, line }));
}

export function scanRepository(root, denyNames, allow, fileAllow = unscannableAllow) {
  const errors = [];
  const remaining = new Map(Object.entries(allow).filter(([, rule]) => rule.lines)
    .map(([path, rule]) => [path, { ...rule.lines }]));
  for (const name of execFileSync('git', ['ls-files', '-z'], { cwd: root, encoding: 'utf8' }).split('\0').filter(Boolean)) {
    const file = join(root, name);
    const path = relative(root, file).split(sep).join('/');
    const stat = lstatSync(file, { throwIfNoEntry: false });
    let reason = stat?.isSymbolicLink() ? 'symlink' :
      sensitiveFile.test(basename(file)) ? 'sensitive file' : null;
    let source;
    if (!reason && stat?.isFile()) {
      const buffer = readFileSync(file);
      if (buffer.includes(0)) reason = 'binary/NUL file';
      else {
        try { source = new TextDecoder('utf-8', { fatal: true }).decode(buffer); }
        catch { reason = 'binary/invalid UTF-8 file'; }
      }
    }
    if (reason) {
      if (!Object.hasOwn(fileAllow, path)) errors.push({ path, reason });
      continue;
    }
    if (source === undefined) continue;
    const counts = remaining.get(path);
    if (counts) for (const { hash } of deniedLines(source, denyNames)) {
      if (counts[hash] > 0) counts[hash]--;
    }
    errors.push(...scanText(path, source, denyNames, allow));
  }
  for (const [path, counts] of remaining) for (const [hash, count] of Object.entries(counts)) {
    if (count > 0) errors.push({ path, hash, unused: count });
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
