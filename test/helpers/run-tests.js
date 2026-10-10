import { mkdtempSync, rmSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

const root = fileURLToPath(new URL('../../', import.meta.url));
const temporary = mkdtempSync(join(root, 'test/helpers/.tmp-suite-'));
const laneFiles = ['tenant-isolation', 'tenant-abuse', 'portal-isolation', 'hostname-table', 'no-hardcoded-names'];
try {
  const lane = process.argv.includes('--lane');
  const result = spawnSync(lane ? process.execPath : 'npm', lane
    ? ['--test', ...laneFiles.map((name) => `test/${name}.test.js`)] : ['test'], {
    cwd: root,
    env: { ...process.env, TMPDIR: temporary, npm_config_cache: join(temporary, 'npm-cache'),
      NODE_OPTIONS: `--require=${join(root, 'test/helpers/offline.cjs')}` },
    stdio: 'inherit',
  });
  if (result.error) throw result.error;
  process.exitCode = result.status ?? 1;
} finally {
  rmSync(temporary, { recursive: true, force: true });
}
