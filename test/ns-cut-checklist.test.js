import { it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

it('prints SAFE_TO_FLIP only when both mocked PoPs agree on required mail records and SOA', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fastdog-dig-'));
  try {
    const dig = path.join(dir, 'dig');
    fs.writeFileSync(dig, `#!/usr/bin/env bash
server="$4"
host="$5"
type="$6"
case "$host:$type" in
  fastdognetworks.com:MX) echo '10 chocobo.mxrouting.net.' ;;
  fastdognetworks.com:TXT) echo '"v=spf1 include:mxroute.com -all"' ;;
  _dmarc.fastdognetworks.com:TXT) echo '"v=DMARC1; p=none;"' ;;
  x._domainkey.fastdognetworks.com:TXT) echo '"v=DKIM1; k=rsa; p=abc123"' ;;
  fastdognetworks.com:SOA)
    if [[ "$server" == '@2.29.58.90' && "$MISMATCH" == 'yes' ]]; then
      echo 'ns1.fastdognetworks.com. hostmaster.fastdognetworks.com. 22 3600 600 604800 300'
    else
      echo 'ns1.fastdognetworks.com. hostmaster.fastdognetworks.com. 21 3600 600 604800 300'
    fi ;;
esac
`, { mode: 0o755 });
    const run = (mismatch) => spawnSync('bash', ['scripts/ns-cut-checklist.sh'], {
      cwd: path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'),
      env: { ...process.env, PATH: `${dir}:${process.env.PATH}`, MISMATCH: mismatch ? 'yes' : 'no' },
      encoding: 'utf8',
    });
    const good = run(false);
    assert.equal(good.status, 0, good.stdout + good.stderr);
    assert.match(good.stdout, /SAFE_TO_FLIP=yes/);
    assert.match(good.stdout, /HOLD/);
    const bad = run(true);
    assert.equal(bad.status, 1, bad.stdout + bad.stderr);
    assert.match(bad.stdout, /FAIL SOA serial/);
    assert.match(bad.stdout, /SAFE_TO_FLIP=no/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});
