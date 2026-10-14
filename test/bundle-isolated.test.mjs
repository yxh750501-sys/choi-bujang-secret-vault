import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 30000, ...options });
  assert.equal(result.status, 0, `${command} ${args.join(' ')}: ${result.error?.message ?? result.stderr}`);
  return result.stdout.trim();
}

test('깨끗한 격리 복제본에서 bundle은 네트워크 없이 미실행 증거를 기록한다', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'byteback-bundle-'));
  const repository = join(temporary, 'repo');
  try {
    run('git', ['clone', '--quiet', '--no-hardlinks', root, repository]);
    copyFileSync(join(root, 'scripts/bundle.mjs'), join(repository, 'scripts/bundle.mjs'));
    const config = JSON.parse(readFileSync(join(repository, 'aleph.config.json'), 'utf8'));
    run('git', ['-C', repository, 'remote', 'set-url', 'origin', `${config.repoUrl}.git`]);
    run('git', ['-C', repository, 'add', 'scripts/bundle.mjs']);
    if (run('git', ['-C', repository, 'status', '--porcelain'])) {
      run('git', ['-C', repository, '-c', 'user.name=Bundle Test',
        '-c', 'user.email=bundle-test@example.test', '-c', 'commit.gpgsign=false',
        'commit', '--quiet', '-m', 'Test isolated bundle']);
    }
    writeFileSync(join(repository, 'bundle-notes.json'), JSON.stringify({
      explanation: '격리된 번들 생성 회귀 시험이며 외부 요청을 실행하지 않았습니다.',
    }));
    const guard = join(temporary, 'deny-network.cjs');
    writeFileSync(guard, `
      const deny = () => { process.exitCode = 88; throw new Error('NETWORK_FORBIDDEN'); };
      globalThis.fetch = deny;
      require('node:http').request = deny;
      require('node:https').request = deny;
    `);
    run('npm', ['run', 'bundle'], {
      cwd: repository,
      env: { ...process.env, NODE_OPTIONS: `--require=${guard}`, npm_config_offline: 'true' },
    });
    const bundle = JSON.parse(readFileSync(join(repository, 'artifacts/submission.json'), 'utf8'));
    assert.equal(bundle.schema, 'aleph.defense.submission.v2');
    assert.equal(bundle.step, 12);
    assert.equal(bundle.commit, run('git', ['-C', repository, 'rev-parse', 'HEAD']));
    assert.equal(bundle.repoUrl, config.repoUrl);
    assert.ok(bundle.changedFiles.includes('scripts/bundle.mjs'));
    assert.deepEqual(bundle.policyRules, ['device_registered', 'resource_boundary', 'step_up_required']);
    assert.ok(bundle.attackAttempts.length > 0);
    assert.ok(bundle.attackAttempts.every(item => item.observed === 'not_run'));
    assert.equal(run('git', ['-C', repository, 'status', '--porcelain', '--untracked-files=all']), '');
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
