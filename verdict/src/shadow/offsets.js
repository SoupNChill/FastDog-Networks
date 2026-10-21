// Per-log tail offsets for scripts/shadow-tail.js, persisted so a restart neither replays history
// nor writes duplicate shadow rows. State file: {"<path>": {"ino": <inode>, "offset": <bytes>}}.
import { mkdir, readFile, writeFile, rename, unlink, stat } from 'node:fs/promises';
import { createReadStream } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { cleanLine } from './lines.js';

export function offsetsFile(env = process.env) {
  return env.VERDICT_SHADOW_OFFSETS_FILE || join(dirname(env.VERDICT_SHADOW_FILE || 'data/shadow.jsonl'), 'shadow-offsets.json');
}

// Where to start reading a log. saved: the stored {ino, offset} or undefined; current: stat {ino, size}.
// No saved entry: start at the end (never rescan history). Different inode (rotation) or a file
// shorter than the offset (truncation): start at 0. Otherwise resume.
export function resumeOffset(saved, { ino, size }) {
  if (!saved || !Number.isFinite(saved.offset)) return size;
  if (saved.ino !== ino) return 0;
  if (size < saved.offset) return 0;
  return saved.offset;
}

// Read one poll's worth of a log: from resumeOffset() up to the size seen by stat, complete lines only
// (a line still being written is left for the next poll, so it is never scored twice or in halves).
// onLine gets each NUL-cleaned, non-blank line. Returns the new {ino, offset}; throws ENOENT if absent.
export async function consumeLog(path, prev, onLine) {
  const info = await stat(path);
  let offset = resumeOffset(prev, info);
  if (info.size > offset) {
    let pending = [];
    for await (const chunk of createReadStream(path, { start: offset, end: info.size - 1 })) {
      let from = 0, nl;
      while ((nl = chunk.indexOf(10, from)) !== -1) {
        const piece = chunk.subarray(from, nl);
        const bytes = pending.length ? Buffer.concat([...pending, piece]) : piece;
        pending = [];
        offset += bytes.length + 1;
        from = nl + 1;
        const line = cleanLine(bytes.toString('utf8'));
        if (line.trim()) await onLine(line);
      }
      if (from < chunk.length) pending.push(Buffer.from(chunk.subarray(from)));
    }
  }
  return { ino: info.ino, offset };
}

export async function loadOffsets(file) {
  try {
    const parsed = JSON.parse(await readFile(file, 'utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch { /* Missing or corrupt: every log starts at its end. */ }
  return {};
}

export async function saveOffsets(file, state) {
  const temp = `${file}.${randomUUID()}.tmp`;
  await mkdir(dirname(file), { recursive: true });
  try {
    await writeFile(temp, JSON.stringify(state), { flag: 'wx', mode: 0o600 });
    await rename(temp, file);
  } finally {
    await unlink(temp).catch(() => {});
  }
}
