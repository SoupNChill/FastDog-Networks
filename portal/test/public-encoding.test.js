import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';

// Guards against copy that lost its encoding on the way in: an apostrophe turned into "?" (doesn?t),
// the U+FFFD replacement character, or UTF-8 read as Latin-1 (â€™, Ã©, Â ).
const root = fileURLToPath(new URL('../', import.meta.url));
const htmlUnder = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory()
  ? htmlUnder(join(dir, entry.name)) : entry.name.endsWith('.html') ? [join(dir, entry.name)] : []);
// Visible text only: tags and their attributes (mailto:...?subject=) are dropped.
const htmlText = (html) => html.replace(/<!--[\s\S]*?-->/g, ' ').replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]*>/g, ' ');
const encodingProblems = (text) => [
  ...[...text.matchAll(/\p{L}\?\p{L}/gu)].map(([match]) => `"?" between letters: ${match}`),
  ...(text.includes('�') ? ['U+FFFD replacement character'] : []),
  ...[...text.matchAll(/â[€\u0080]|Ã|Â/g)].map(([match]) => `UTF-8 read as Latin-1: ${JSON.stringify(match)}`),
];

test('the encoding check catches broken apostrophes and mojibake but not punctuation', () => {
  assert.equal(encodingProblems(htmlText('<p>It won?t be shown</p>')).length, 1);
  assert.equal(encodingProblems('It�s').length, 1);
  assert.equal(encodingProblems('Itâ€™s cafÃ©Â ').length, 3);
  assert.deepEqual(encodingProblems(htmlText('<a href="/login?next=keys">Stuck? Email us.</a> It’s fine.')), []);
});

test('every portal public page is free of "?" apostrophes and mojibake', () => {
  const files = htmlUnder(join(root, 'public'));
  assert.ok(files.some((file) => file.endsWith('keys.html')));
  assert.deepEqual(files.flatMap((file) => encodingProblems(htmlText(readFileSync(file, 'utf8')))
    .map((problem) => `${relative(root, file)}: ${problem}`)), []);
});
