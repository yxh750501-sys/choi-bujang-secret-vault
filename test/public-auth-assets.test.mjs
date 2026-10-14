import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { join, resolve } from 'node:path';
import { test } from 'node:test';

const root = resolve(import.meta.dirname, '..');
const publicDirectory = resolve(root, 'public');
const sentinel = 'sb_publishable_test_sentinel_never_use_as_a_credential';

async function publicFiles(directory = publicDirectory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const nested = await Promise.all(entries.map(entry => {
    const path = join(directory, entry.name);
    return entry.isDirectory() ? publicFiles(path) : [path];
  }));
  return nested.flat();
}

test('local build removes legacy Supabase assets and never publishes a configured sentinel key', async () => {
  const result = spawnSync(process.execPath, ['scripts/build-public.mjs', '--local'], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      SUPABASE_URL: 'https://supabase-project.example.test',
      SUPABASE_PUBLISHABLE_KEY: sentinel,
    },
  });
  assert.equal(result.error, undefined, 'build process must start');
  assert.equal(result.status, 0, `build must succeed; exit status ${result.status}`);
  assert.equal(`${result.stdout}\n${result.stderr}`.includes(sentinel), false,
    'build output must not contain the configured sentinel');

  const files = await publicFiles();
  const relativeFiles = files.map(path => path.slice(publicDirectory.length + 1).replaceAll('\\', '/'));
  assert.equal(relativeFiles.includes('supabase-config.js'), false);
  assert.equal(relativeFiles.includes('vendor/supabase.js'), false);

  const assetContents = await Promise.all(files.map(path => readFile(path, 'utf8')));
  for (const content of assetContents) {
    assert.equal(content.includes(sentinel), false, 'configured sentinel must not appear in public assets');
  }
});

test('public browser and build sources do not publish a Supabase key while server Auth retains its setting', async () => {
  const [html, browser, controller, build, serverSession, packageFile, vercelFile, configFile] =
    await Promise.all([
      readFile(resolve(root, 'public/index.html'), 'utf8'),
      readFile(resolve(root, 'src/auth-browser.mjs'), 'utf8'),
      readFile(resolve(root, 'src/auth-controller.mjs'), 'utf8'),
      readFile(resolve(root, 'scripts/build-public.mjs'), 'utf8'),
      readFile(resolve(root, 'src/server-session.mjs'), 'utf8'),
      readFile(resolve(root, 'package.json'), 'utf8'),
      readFile(resolve(root, 'vercel.json'), 'utf8').then(JSON.parse),
      readFile(resolve(root, 'aleph.config.json'), 'utf8').then(JSON.parse),
    ]);

  assert.doesNotMatch(html, /vendor\/supabase\.js|supabase-config\.js/u);
  assert.doesNotMatch(`${html}\n${browser}\n${controller}\n${build}`,
    /SUPABASE_PUBLISHABLE_KEY|BYTE_BACK_SUPABASE_CONFIG|sb_publishable_|anon key|window\.supabase/u);
  assert.match(serverSession, /import\s*\{\s*createClient\s*\}\s*from\s*'@supabase\/supabase-js'/u);
  assert.match(serverSession, /clientFactory\s*=\s*createClient/u);
  assert.match(serverSession, /SUPABASE_PUBLISHABLE_KEY/u);
  assert.match(serverSession,
    /return clientFactory\(configuration\.url,\s*configuration\.publishableKey,\s*\{\s*auth:/u);
  assert.match(packageFile, /"@supabase\/supabase-js"/u);
  assert.ok(configFile.step >= 5, '5단계 이상의 인증 구성이 유지되어야 합니다');
  assert.ok(configFile.step >= 6, '현재 자료실 설정은 6단계 이상이어야 합니다');
  assert.equal(configFile.step, 10, '현재 자료실 설정은 10단계여야 합니다');
  assert.equal(configFile.originalApiUrl, 'https://yweroshtkwjziprmgxcx.supabase.co/rest/v1/notes');
  assert.deepEqual(vercelFile.headers[0].headers.find(header =>
    header.key === 'X-Content-Type-Options'), {
    key: 'X-Content-Type-Options',
    value: 'nosniff',
  });
  assert.equal(vercelFile.rewrites, undefined);
  assert.equal(vercelFile.redirects, undefined);
  assert.equal(configFile.restoreRoute, 'POST /api/restore');
  assert.equal(vercelFile.functions['api/restore.js'].includeFiles, 'test/fixtures/**');
});
