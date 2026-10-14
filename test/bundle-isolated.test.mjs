import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';

const root = fileURLToPath(new URL('..', import.meta.url));
const failedCommit = '937f0d560d6aa21af13946718287abaa52b7b406';

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', timeout: 30000, ...options });
  assert.equal(result.status, 0, `${command} ${args.join(' ')}: ${result.error?.message ?? result.stderr}`);
  return result.stdout.trim();
}

function prepareRepository(path, repoUrl) {
  run('git', ['clone', '--quiet', '--no-hardlinks', root, path]);
  run('git', ['-C', path, 'remote', 'set-url', 'origin', `${repoUrl}.git`]);
  writeFileSync(join(path, 'bundle-notes.json'), JSON.stringify({
    explanation: '격리 실행 감사용 가상 설명이며 네트워크 요청을 실행하지 않았습니다.',
  }));
}

function runAuditedBundle(repository, temporary, label, allowedGit) {
  const audit = join(temporary, `${label}-children.jsonl`);
  const network = join(temporary, `${label}-network.log`);
  const guard = join(temporary, 'bundle-guard.cjs');
  const result = spawnSync('npm', ['run', 'bundle'], {
    cwd: repository, encoding: 'utf8', timeout: 30000,
    env: { ...process.env, NODE_OPTIONS: `--require=${guard}`, npm_config_offline: 'true',
      BUNDLE_AUDIT: audit, BUNDLE_NETWORK: network, BUNDLE_ALLOWED_GIT: JSON.stringify(allowedGit) },
  });
  const children = existsSync(audit)
    ? readFileSync(audit, 'utf8').trim().split(/\r?\n/u).filter(Boolean).map(JSON.parse) : [];
  return { result, children, networkAttempts: existsSync(network)
    ? readFileSync(network, 'utf8').trim().split(/\r?\n/u).filter(Boolean) : [] };
}

test('번들 import 그래프에는 심판 허용 모듈과 학생 판정 파일만 있다', () => {
  const graph = new Set(['scripts/bundle.mjs', 'src/decider.mjs', 'src/attack-check.mjs']);
  const allowedModules = new Set(['node:fs', 'node:path', 'node:url', 'node:child_process', 'node:crypto']);
  for (const file of graph) {
    const source = readFileSync(join(root, file), 'utf8');
    const dynamic = [...source.matchAll(/\bimport\(([^)]*)\)/gu)].map(match => match[1]);
    assert.deepEqual(dynamic, file === 'scripts/bundle.mjs'
      ? ['deciderUrl.href', 'checkerUrl.href'] : []);
    assert.doesNotMatch(source, /\brequire\s*\(/u);
    for (const match of source.matchAll(/\bfrom\s+['"]([^'"]+)['"]/gu)) {
      const specifier = match[1];
      if (specifier.startsWith('node:')) assert.ok(allowedModules.has(specifier), specifier);
      else assert.ok(graph.has(relative(root, resolve(dirname(join(root, file)), specifier))), specifier);
    }
  }
});

test('시작 틀 Git 호출 기준에서 실패 커밋은 막히고 현재 번들은 무네트워크로 통과한다', () => {
  const temporary = mkdtempSync(join(tmpdir(), 'byteback-bundle-audit-'));
  try {
    const baseline = run('git', ['-C', root, 'show', '8b7cadb:scripts/bundle.mjs']);
    const allowedGit = [...new Set([...baseline.matchAll(/\bgit\('([a-z-]+)'/gu)]
      .map(match => match[1]))];
    assert.ok(allowedGit.includes('diff-tree'));
    assert.ok(!allowedGit.includes('rev-list') && !allowedGit.includes('diff'));

    const guard = join(temporary, 'bundle-guard.cjs');
    writeFileSync(guard, `
      const fs = require('node:fs');
      const child = require('node:child_process');
      const { syncBuiltinESMExports } = require('node:module');
      if (process.argv[1]?.endsWith('scripts/bundle.mjs')) {
        const allowed = new Set(JSON.parse(process.env.BUNDLE_ALLOWED_GIT));
        for (const method of ['execFileSync', 'execSync', 'spawnSync', 'spawn', 'execFile', 'exec', 'fork']) {
          const original = child[method];
          child[method] = function (...call) {
            const [program, args] = call;
            const argv = Array.isArray(args) ? args : [];
            fs.appendFileSync(process.env.BUNDLE_AUDIT,
              JSON.stringify({ method, program: String(program), args: argv }) + '\\n');
            const subcommand = argv[0] === '-C' ? argv[2] : argv[0];
            if (program !== 'git' || !allowed.has(subcommand)) {
              process.exitCode = 88;
              throw new Error('UNSUPPORTED_CHILD_COMMAND');
            }
            return original.apply(this, call);
          };
        }
        const deny = name => {
          fs.appendFileSync(process.env.BUNDLE_NETWORK, name + '\\n');
          process.exitCode = 89;
          throw new Error('NETWORK_FORBIDDEN');
        };
        globalThis.fetch = () => deny('fetch');
        for (const name of ['node:http', 'node:https']) {
          const module = require(name);
          module.request = () => deny(name + '.request');
          module.get = () => deny(name + '.get');
        }
        require('node:net').connect = () => deny('net.connect');
        syncBuiltinESMExports();
      }
    `);

    const repoUrl = JSON.parse(readFileSync(join(root, 'aleph.config.json'), 'utf8')).repoUrl;
    const failed = join(temporary, 'failed');
    prepareRepository(failed, repoUrl);
    run('git', ['-C', failed, 'switch', '--detach', failedCommit]);
    const oldRun = runAuditedBundle(failed, temporary, 'failed', allowedGit);
    assert.notEqual(oldRun.result.status, 0);
    assert.ok(oldRun.children.some(item => item.args.includes('rev-list')),
      JSON.stringify({ children: oldRun.children, stdout: oldRun.result.stdout,
        stderr: oldRun.result.stderr, error: oldRun.result.error?.message }));
    assert.deepEqual(oldRun.networkAttempts, []);

    const current = join(temporary, 'current');
    prepareRepository(current, repoUrl);
    copyFileSync(join(root, 'scripts/bundle.mjs'), join(current, 'scripts/bundle.mjs'));
    run('git', ['-C', current, 'add', 'scripts/bundle.mjs']);
    if (run('git', ['-C', current, 'status', '--porcelain'])) {
      run('git', ['-C', current, '-c', 'user.name=Bundle Test',
        '-c', 'user.email=bundle-test@example.test', '-c', 'commit.gpgsign=false',
        'commit', '--quiet', '-m', 'Test isolated bundle']);
    }
    const checked = runAuditedBundle(current, temporary, 'current', allowedGit);
    assert.equal(checked.result.status, 0, checked.result.stderr);
    assert.deepEqual(checked.networkAttempts, []);
    assert.ok(checked.children.length > 0);
    assert.ok(checked.children.every(item => item.program === 'git'
      && item.method === 'execFileSync' && item.args[0] === '-C'
      && resolve(item.args[1]) === current && allowedGit.includes(item.args[2])),
    JSON.stringify(checked.children));
    const diffTree = checked.children.find(item => item.args[2] === 'diff-tree');
    assert.deepEqual(diffTree.args.slice(3, 9),
      ['--root', '--no-commit-id', '--name-only', '--no-renames', '-r',
        run('git', ['-C', current, 'rev-parse', 'HEAD'])]);

    const bundle = JSON.parse(readFileSync(join(current, 'artifacts/submission.json'), 'utf8'));
    const changed = run('git', ['-C', current, 'diff-tree', '--root', '--no-commit-id',
      '--name-only', '--no-renames', '-r', bundle.commit]).split(/\r?\n/u).filter(Boolean).sort();
    assert.equal(bundle.schema, 'aleph.defense.submission.v2');
    assert.equal(bundle.step, 12);
    assert.equal(bundle.repoUrl, repoUrl);
    assert.deepEqual(bundle.changedFiles, changed);
    assert.deepEqual(bundle.policyRules,
      ['device_registered', 'resource_boundary', 'step_up_required']);
    assert.ok(bundle.attackAttempts.length > 0);
    assert.ok(bundle.attackAttempts.every(item => item.observed === 'not_run'));
    assert.equal(run('git', ['-C', current, 'status', '--porcelain', '--untracked-files=all']), '');
  } finally {
    rmSync(temporary, { recursive: true, force: true });
  }
});
