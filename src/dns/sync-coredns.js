import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { ROOT, env } from '../lib/config.js';
import { exportBind, readZone } from './store.js';
import { validateZone } from './validate-zone.js';
import { appendAudit } from '../lib/audit.js';

function truthy(v) {
  return ['1', 'true', 'yes', 'on'].includes(String(v || '').toLowerCase());
}

function syncEnabled() {
  return truthy(env('COREDNS_SYNC_ENABLED', 'false'));
}

function dryRun() {
  return truthy(env('COREDNS_SYNC_DRY_RUN', 'false'));
}

/** Parse COREDNS_POP_TARGETS like ns1=157.230.57.32,ns2=2.29.58.90 */
export function parsePopTargets(raw = env('COREDNS_POP_TARGETS', '')) {
  const text = String(raw || '').trim();
  if (!text) return [];
  return text.split(',').map((part) => part.trim()).filter(Boolean).map((part) => {
    const eq = part.indexOf('=');
    if (eq > 0) return { name: part.slice(0, eq).trim(), host: part.slice(eq + 1).trim() };
    return { name: part, host: part };
  });
}

function localZonesDir() {
  const d = env('COREDNS_ZONES_DIR', '/etc/coredns/zones');
  return path.isAbsolute(d) ? d : path.join(ROOT, d);
}

function sshBaseArgs() {
  const args = ['-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10'];
  const key = env('COREDNS_SSH_KEY', '');
  if (key) args.push('-i', key);
  const extra = env('COREDNS_SSH_OPTS', '');
  if (extra) args.push(...extra.split(/\s+/).filter(Boolean));
  return args;
}

function sshUser() {
  return env('COREDNS_SSH_USER', 'root');
}

function run(cmd, args, opts = {}) {
  const result = spawnSync(cmd, args, { encoding: 'utf8', ...opts });
  return {
    ok: result.status === 0,
    status: result.status,
    stdout: result.stdout || '',
    stderr: result.stderr || '',
    error: result.error && result.error.message,
  };
}

function writeLocalZone(zone, text) {
  const dir = localZonesDir();
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, zone + '.zone');
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, text, 'utf8');
  fs.renameSync(tmp, file);
  return file;
}

function reloadLocal() {
  const pgrep = run('pgrep', ['-x', 'coredns']);
  if (pgrep.ok) {
    run('pkill', ['-USR1', '-x', 'coredns']);
    return { method: 'sigusr1' };
  }
  const active = run('systemctl', ['is-active', '--quiet', 'fastdog-coredns']);
  if (active.ok) {
    run('systemctl', ['reload', 'fastdog-coredns']);
    return { method: 'systemctl-reload' };
  }
  return { method: 'skip', reason: 'coredns_not_running' };
}

function syncRemote(pop, zone, localFile) {
  const user = sshUser();
  const remoteDir = env('COREDNS_REMOTE_ZONES_DIR', '/etc/coredns/zones');
  const remoteFile = remoteDir + '/' + zone + '.zone';
  const base = sshBaseArgs();
  const target = user + '@' + pop.host;
  const scp = run('scp', [...base, localFile, target + ':' + remoteFile]);
  if (!scp.ok) {
    return { ok: false, pop: pop.name, host: pop.host, error: scp.stderr || scp.error || 'scp_failed' };
  }
  const reloadCmd = env(
    'COREDNS_REMOTE_RELOAD_CMD',
    'pkill -USR1 -x coredns 2>/dev/null || systemctl reload fastdog-coredns 2>/dev/null || true',
  );
  const ssh = run('ssh', [...base, target, reloadCmd]);
  if (!ssh.ok) {
    return { ok: false, pop: pop.name, host: pop.host, error: ssh.stderr || ssh.error || 'reload_failed' };
  }
  return { ok: true, pop: pop.name, host: pop.host };
}

/**
 * Export, validate, optionally write local + SSH to PoPs, always audit.
 * Never throws for remote failures — returns structured result.
 */
export function syncZone(zone, { action = 'sync' } = {}) {
  const pops = parsePopTargets();
  const enabled = syncEnabled();
  const isDry = dryRun();
  const baseEvent = { zone, action, pops: pops.map((p) => p.host), dry_run: isDry };

  const data = readZone(zone);
  if (!data) {
    const error = 'zone_not_found';
    appendAudit({ ...baseEvent, success: false, error });
    return { ok: false, skipped: false, error, zone };
  }

  const text = exportBind(zone);
  const jsonCheck = validateZone(data, { zone });
  const bindCheck = validateZone(text, { zone });
  if (!jsonCheck.ok || !bindCheck.ok) {
    const errors = [...new Set([...(jsonCheck.errors || []), ...(bindCheck.errors || [])])];
    const error = 'validation_failed:' + errors.join(',');
    appendAudit({ ...baseEvent, success: false, error });
    return { ok: false, skipped: false, error, errors, zone };
  }

  if (!enabled) {
    appendAudit({ ...baseEvent, success: true, skipped: true, reason: 'COREDNS_SYNC_ENABLED_off' });
    return { ok: true, skipped: true, reason: 'disabled', zone, validated: true };
  }

  if (!pops.length && !isDry) {
    appendAudit({ ...baseEvent, success: true, skipped: true, reason: 'no_pop_targets' });
  }

  if (isDry) {
    appendAudit({ ...baseEvent, success: true, dry_run: true, validated: true, local: false });
    return {
      ok: true,
      skipped: false,
      dry_run: true,
      zone,
      validated: true,
      pops: pops.map((p) => p.host),
      message: 'dry-run: validation ok; remote/local write skipped',
    };
  }

  const result = {
    ok: true,
    skipped: false,
    dry_run: false,
    zone,
    validated: true,
    local: null,
    remotes: [],
    error: undefined,
  };

  let stagingFile;
  try {
    const file = writeLocalZone(zone, text);
    const reload = reloadLocal();
    result.local = { file, reload };
    stagingFile = file;
  } catch (error) {
    result.local = { error: error.message };
    stagingFile = path.join(env('TMPDIR', '/tmp'), 'fastdog-' + zone + '.' + process.pid + '.zone');
    fs.writeFileSync(stagingFile, text, 'utf8');
    result.local.staging = stagingFile;
  }

  for (const pop of pops) {
    const remote = syncRemote(pop, zone, stagingFile);
    result.remotes.push(remote);
    if (!remote.ok) result.ok = false;
  }
  if (result.local && result.local.staging && result.local.staging !== result.local.file) {
    try { fs.unlinkSync(result.local.staging); } catch { /* ignore */ }
  }

  if (!result.ok) {
    result.error = result.remotes.filter((r) => !r.ok).map((r) => r.pop + ':' + r.error).join('; ') || 'sync_failed';
  }

  if (!pops.length) {
    result.ok = true;
    result.skipped = !(result.local && result.local.file);
    if (result.skipped) result.reason = 'no_pop_targets';
  }

  appendAudit({
    ...baseEvent,
    success: result.ok,
    error: result.error,
    local: Boolean(result.local && result.local.file),
    remotes: result.remotes.map((r) => ({ pop: r.pop, ok: r.ok, error: r.error })),
  });

  return result;
}

/** Safe wrapper for onboard: never throws; surfaces sync status. */
export function syncAfterOnboard(zone, action = 'onboard') {
  try {
    return syncZone(zone, { action });
  } catch (error) {
    const payload = { ok: false, skipped: false, zone, error: error.message };
    appendAudit({ zone, action, pops: parsePopTargets().map((p) => p.host), success: false, error: error.message });
    return payload;
  }
}