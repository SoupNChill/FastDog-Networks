// Per-log tail offsets for scripts/shadow-tail.js, persisted so a restart neither replays history
// nor writes duplicate shadow rows. State file: {"<path>": {"ino": <inode>, "offset": <bytes>, "head": <sha256>}}.
// head fingerprints the first min(256, offset) bytes so a same-inode truncate + regrow is detected.
import { mkdir, open, readFile, writeFile, rename, unlink } from 'node:fs/promises';
import { createHash, randomUUID } from 'node:crypto';
import { dirname, join } from 'node:path';
import { cleanLine } from './lines.js';

const HEAD_BYTES = 256;
const CHUNK = 64 * 1024;
export const CHECKPOINT_LINES = 64;

export function offsetsFile(env = process.env) {
  return env.VERDICT_SHADOW_OFFSETS_FILE || join(dirname(env.VERDICT_SHADOW_FILE || 'data/shadow.jsonl'), 'shadow-offsets.json');
}

// Where to start reading a log. saved: the stored {ino, offset, head} or undefined; current: fstat
// {ino, size} plus head (fingerprint of the first min(256, saved.offset) bytes) and lineEnd (offset just
// after the last newline). No saved entry: start at the last complete line (never rescan history, never
// start inside a half-written row). Different inode (rotation), a file shorter than the offset, or a
// changed head (same inode truncated and regrown): start at 0. Otherwise resume. Entries saved without
// a head (0.3.3) skip the head check.
export function resumeOffset(saved, { ino, size, head, lineEnd = size }) {
  if (!saved || !Number.isFinite(saved.offset)) return lineEnd;
  if (saved.ino !== ino) return 0;
  if (size < saved.offset) return 0;
  if (typeof saved.head === 'string' && saved.head !== head) return 0;
  return saved.offset;
}

async function readAt(fh, length, position) {
  const buffer = Buffer.alloc(length);
  const { bytesRead } = await fh.read(buffer, 0, length, position);
  return buffer.subarray(0, bytesRead);
}

async function headOf(fh, offset) {
  return createHash('sha256').update(await readAt(fh, Math.min(HEAD_BYTES, offset), 0)).digest('hex');
}

async function lastLineEnd(fh, size) {
  for (let end = size; end > 0;) {
    const start = Math.max(0, end - CHUNK);
    const nl = (await readAt(fh, end - start, start)).lastIndexOf(10);
    if (nl !== -1) return start + nl + 1;
    end = start;
  }
  return 0;
}

// Read one descriptor from its resume point up to the fstat size, complete lines only. onLine gets each
// NUL-cleaned, non-blank line; a line counts as consumed only once onLine resolves. checkpoint gets the
// acknowledged {ino, offset, head} every CHECKPOINT_LINES lines, at the end, and before a failure from
// onLine is rethrown, so a failed write is retried on the next poll instead of being skipped.
async function drain(fh, prev, onLine, checkpoint) {
  const info = await fh.stat();
  const usable = prev && Number.isFinite(prev.offset) && prev.ino === info.ino && info.size >= prev.offset;
  let offset = resumeOffset(prev, {
    ino: info.ino,
    size: info.size,
    head: usable ? await headOf(fh, prev.offset) : undefined,
    lineEnd: prev && Number.isFinite(prev.offset) ? info.size : await lastLineEnd(fh, info.size),
  });
  const snapshot = async () => ({ ino: info.ino, offset, head: await headOf(fh, offset) });
  let pending = [], position = offset, sinceCheckpoint = 0;
  try {
    while (position < info.size) {
      const chunk = await readAt(fh, Math.min(CHUNK, info.size - position), position);
      if (!chunk.length) break; // truncated while reading
      position += chunk.length;
      let from = 0, nl;
      while ((nl = chunk.indexOf(10, from)) !== -1) {
        const piece = chunk.subarray(from, nl);
        const bytes = pending.length ? Buffer.concat([...pending, piece]) : piece;
        pending = [];
        from = nl + 1;
        const line = cleanLine(bytes.toString('utf8'));
        if (line.trim()) await onLine(line);
        offset += bytes.length + 1;
        if (checkpoint && ++sinceCheckpoint >= CHECKPOINT_LINES) { sinceCheckpoint = 0; await checkpoint(await snapshot()); }
      }
      if (from < chunk.length) pending.push(Buffer.from(chunk.subarray(from)));
    }
  } catch (error) {
    if (checkpoint) await checkpoint(await snapshot());
    throw error;
  }
  const next = await snapshot();
  if (checkpoint) await checkpoint(next);
  return next;
}

// Read one poll's worth of a log. The path is opened first and the descriptor fstat'ed, so a rotation
// between the two can never pair the new file with the old offset. With a handles Map (one per tailer),
// the descriptor is retained between polls; when the path is rotated or removed, the retained descriptor
// is drained to its end before the replacement is read from 0. Returns the new {ino, offset, head};
// throws ENOENT if the log is absent and no descriptor is retained.
export async function consumeLog(path, prev, onLine, { handles, checkpoint } = {}) {
  const retained = handles?.get(path);
  let fh = null;
  try { fh = await open(path, 'r'); } catch (error) { if (error.code !== 'ENOENT' || !retained) throw error; }
  try {
    let state = prev;
    const ino = fh ? (await fh.stat()).ino : null;
    if (retained && ino === retained.ino) {
      await fh.close();
      fh = null;
      return await drain(retained.fh, state, onLine, checkpoint);
    }
    if (retained) {
      if (prev?.ino === retained.ino) state = await drain(retained.fh, prev, onLine, checkpoint);
      if (!fh) return state; // replacement not created yet: keep the old descriptor
      handles.delete(path);
      await retained.fh.close().catch(() => {});
    }
    if (handles) { handles.set(path, { fh, ino }); fh = null; } // retained from here on, even if drain throws
    return await drain(handles ? handles.get(path).fh : fh, state, onLine, checkpoint);
  } finally {
    if (fh) await fh.close().catch(() => {});
  }
}

export async function loadOffsets(file) {
  try {
    const parsed = JSON.parse(await readFile(file, 'utf8'));
    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) return parsed;
  } catch { /* Missing or corrupt: every log starts at its last complete line. */ }
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
