import { open, mkdir, rename, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomUUID } from 'node:crypto';

// Parent directories are operator-owned and must not be writable by untrusted users.
export async function readConfig(file, maxBytes = 1024 * 1024) {
  const handle = await open(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > maxBytes) throw new Error('invalid_config_size');
    const buffer = Buffer.alloc(maxBytes + 1);
    let length = 0;
    while (length < buffer.length) {
      const { bytesRead } = await handle.read(buffer, length, buffer.length - length, null);
      if (!bytesRead) break;
      length += bytesRead;
    }
    if (length > maxBytes) throw new Error('invalid_config_size');
    try { return JSON.parse(buffer.toString('utf8', 0, length)); }
    catch { throw new Error('invalid_config_json'); }
  } finally { await handle.close(); }
}
export async function writeConfig(file, text) {
  if (Buffer.byteLength(text) > 1024 * 1024) throw new Error('invalid_config_size');
  await mkdir(dirname(file), { recursive: true });
  const temp = join(dirname(file), `.verdict-${randomUUID()}.tmp`);
  try {
    const handle = await open(temp, 'wx', 0o600);
    try { await handle.writeFile(text); } finally { await handle.close(); }
    // Replaces a destination symlink itself, never writes through it.
    await rename(temp, file);
  } finally { await unlink(temp).catch(error => { if (error.code !== 'ENOENT') throw error; }); }
}
