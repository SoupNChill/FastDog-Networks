import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join, relative } from 'node:path';

// Guards against copy that lost its encoding on the way in: an apostrophe turned into "?" (portal?s),
// the U+FFFD replacement character, or UTF-8 read as Latin-1 (â€™, Ã©, Â ).
const root = fileURLToPath(new URL('../', import.meta.url));
const site = join(root, 'site');
const htmlUnder = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((entry) => entry.isDirectory()
  ? htmlUnder(join(dir, entry.name)) : entry.name.endsWith('.html') ? [join(dir, entry.name)] : []);
// Visible text only: tags and their attributes (mailto:...?subject=) are dropped, and so are bare URLs in plain text.
const htmlText = (html) => html.replace(/<!--[\s\S]*?-->/g, ' ').replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ').replace(/<[^>]*>/g, ' ');
const plainText = (text) => text.replace(/\b(?:[a-z][a-z0-9+.-]*:\/\/|mailto:)\S+/gi, ' ');
const encodingProblems = (text) => [
  ...[...text.matchAll(/\p{L}\?\p{L}/gu)].map(([match]) => `"?" between letters: ${match}`),
  ...(text.includes('�') ? ['U+FFFD replacement character'] : []),
  ...[...text.matchAll(/â[€\u0080]|Ã|Â/g)].map(([match]) => `UTF-8 read as Latin-1: ${JSON.stringify(match)}`),
];

test('the encoding check catches broken apostrophes and mojibake but not punctuation', () => {
  assert.equal(encodingProblems(htmlText('<p>The portal?s page</p>')).length, 1);
  assert.equal(encodingProblems('It�s').length, 1);
  // Windows-1252 and strict Latin-1 readings of "It’s café" plus a no-break space.
  assert.equal(encodingProblems('Itâ€™s cafÃ©Â ').length, 3);
  assert.equal(encodingProblems(Buffer.from('It’s café ', 'utf8').toString('latin1')).length, 3);
  assert.deepEqual(encodingProblems('It’s café, naïve — fine.'), []);
  assert.deepEqual(encodingProblems(htmlText('<a href="mailto:a@example.test?subject=Hi">Questions? Email us.</a>')), []);
  assert.deepEqual(encodingProblems(plainText('GET https://portal.example.test/x?q=1 then dns?, agent?')), []);
});

test('every site page and llms.txt is free of "?" apostrophes and mojibake', () => {
  const files = htmlUnder(site);
  assert.ok(files.some((file) => file.endsWith(join('privacy', 'index.html'))), 'legal pages are scanned too');
  const problems = [
    ...files.flatMap((file) => encodingProblems(htmlText(readFileSync(file, 'utf8'))).map((problem) => `${relative(root, file)}: ${problem}`)),
    ...encodingProblems(plainText(readFileSync(join(site, 'llms.txt'), 'utf8'))).map((problem) => `site/llms.txt: ${problem}`),
  ];
  assert.deepEqual(problems, []);
});
