import { mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export function tempDir(t) {
  const dir = mkdtempSync(fileURLToPath(new URL('./.tmp-', import.meta.url)));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}
