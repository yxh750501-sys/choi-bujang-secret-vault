import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';

const root = new URL('../', import.meta.url);

test('stage 11 PWA manifest and declared icons are present and valid PNGs', async () => {
  const [html, manifestText] = await Promise.all([
    readFile(new URL('public/index.html', root), 'utf8'),
    readFile(new URL('public/manifest.webmanifest', root), 'utf8'),
  ]);
  const manifest = JSON.parse(manifestText);
  assert.match(html, /<link rel="manifest" href="\/manifest\.webmanifest">/u);
  assert.equal(manifest.name, '최부장의 비밀창고');
  assert.equal(manifest.short_name, '비밀창고');
  assert.equal(manifest.start_url, '/');
  assert.equal(manifest.scope, '/');
  assert.equal(manifest.display, 'standalone');
  for (const size of [192, 512]) {
    const icon = manifest.icons.find(item => item.sizes === `${size}x${size}`);
    assert.ok(icon, `missing ${size}px manifest icon`);
    assert.equal(icon.type, 'image/png');
    const png = await readFile(new URL(`public${icon.src}`, root));
    assert.deepEqual(png.subarray(0, 8), Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]));
    assert.equal(png.toString('ascii', 12, 16), 'IHDR');
    assert.equal(png.readUInt32BE(16), size);
    assert.equal(png.readUInt32BE(20), size);
  }
});

test('PWA only caches the public app shell and leaves every API request to the network', async () => {
  const sw = await readFile(new URL('public/sw.js', root), 'utf8');
  assert.match(sw, /CACHEABLE_URLS\.has\(url\.href\)/u);
  assert.match(sw, /url\.pathname === '\/api' \|\| url\.pathname\.startsWith\('\/api\/'\)/u);
  assert.match(sw, /key\.startsWith\(CACHE_PREFIX\)/u);
  assert.doesNotMatch(sw, /cache\.put\([^)]*api/u);
});

test('browser does not request protected notes until the server reports an approved device', async () => {
  const [html, browser] = await Promise.all([
    readFile(new URL('public/index.html', root), 'utf8'),
    readFile(new URL('src/auth-browser.mjs', root), 'utf8'),
  ]);
  assert.match(html, /id="device-request-button"/u);
  assert.match(html, /id="device-revoke-button"/u);
  assert.match(browser, /result\.approved === \(result\.status === 'approved'\)/u);
  assert.match(browser, /if \(!controller\?\.state\.authenticated \|\| !deviceState\.approved\)/u);
  assert.match(browser, /body: JSON\.stringify\(\{ action: 'request' \}\)/u);
  assert.match(browser, /body: JSON\.stringify\(\{ action: 'revoke' \}\)/u);
  assert.doesNotMatch(browser, /deviceRegistered\s*:/u);
});
