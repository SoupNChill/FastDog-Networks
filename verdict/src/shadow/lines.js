// Access-log line cleanup shared by the shadow tailer and the offline scripts. After an in-place
// rewrite Caddy kept writing at its old offset, leaving a sparse hole of NUL bytes glued to the front
// of the next real line. Strip NULs (and a trailing CR); a line of only NULs becomes ''.
export function cleanLine(line) {
  let out = typeof line === 'string' ? line : '';
  if (out.includes('\0')) out = out.replaceAll('\0', '');
  return out.endsWith('\r') ? out.slice(0, -1) : out;
}
