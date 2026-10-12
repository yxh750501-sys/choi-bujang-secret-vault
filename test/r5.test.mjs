import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import notesHandler from '../api/notes.js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 2,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

function mockResponse() {
  const headers = new Map();
  let statusCode;
  let body;
  const response = {
    setHeader: (key, value) => headers.set(key.toLowerCase(), value),
    status: value => {
      statusCode = value;
      return { json: value => { body = value; return response; } };
    },
  };
  return { response, headers, get statusCode() { return statusCode; }, get body() { return body; } };
}

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 2,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('second-stage attack check confirms anonymous data is empty or missing', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  let options;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      options = init;
      return new Response(null, { status: 404 });
    };
    const [result] = await runAttackChecks(config);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/data.json');
    assert.equal(options.redirect, 'error');
    assert.match(result.expected, /메모 0건 또는 404/u);
    assert.match(result.observed, /공개 메모가 없음/u);
    globalThis.fetch = async () => new Response(JSON.stringify({ notes: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    const [empty] = await runAttackChecks(config);
    assert.match(empty.observed, /공개 메모가 없음/u);
    globalThis.fetch = async () => new Response(JSON.stringify({ notes: [{ title: '가상' }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /메모가 노출됨/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('notes API reads four rows server-side without exposing its key', async () => {
  const originalFetch = globalThis.fetch;
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const rows = Array.from({ length: 4 }, (_, index) => ({
    title: `Example ${index + 1}`,
    content: 'Fictional test content',
  }));
  let requestedUrl;
  let requestKey;
  let requestAuthorization;
  try {
    process.env.SUPABASE_URL = 'https://database.example.test';
    process.env.SUPABASE_SECRET_KEY = 'sb_secret_test';
    globalThis.fetch = async (url, options) => {
      requestedUrl = new URL(url);
      const headers = new Headers(options.headers);
      requestKey = headers.get('apikey');
      requestAuthorization = headers.get('authorization');
      return new Response(JSON.stringify(rows), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const success = mockResponse();
    await notesHandler({ method: 'GET' }, success.response);
    assert.equal(success.statusCode, 200);
    assert.equal(success.headers.get('cache-control'), 'no-store');
    assert.equal(requestedUrl.pathname, '/rest/v1/notes');
    assert.equal(requestedUrl.searchParams.get('limit'), '4');
    assert.equal(requestKey, 'sb_secret_test');
    assert.equal(requestAuthorization, null);
    assert.deepEqual(success.body, { notes: rows });
    assert.doesNotMatch(JSON.stringify(success.body), /sb_secret_test/u);

    delete process.env.SUPABASE_URL;
    const missingConfiguration = mockResponse();
    await notesHandler({ method: 'GET' }, missingConfiguration.response);
    assert.equal(missingConfiguration.statusCode, 503);
    assert.deepEqual(missingConfiguration.body, { error: 'NOTES_UNAVAILABLE' });
    process.env.SUPABASE_URL = 'https://database.example.test';

    globalThis.fetch = async () => new Response('database details', { status: 500 });
    const failed = mockResponse();
    await notesHandler({ method: 'GET' }, failed.response);
    assert.equal(failed.statusCode, 503);
    assert.deepEqual(failed.body, { error: 'NOTES_UNAVAILABLE' });

    const rejected = mockResponse();
    await notesHandler({ method: 'POST' }, rejected.response);
    assert.equal(rejected.statusCode, 405);
    assert.equal(rejected.headers.get('allow'), 'GET');
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});

test('public page calls the notes API without bundling Supabase secrets', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.match(html, /fetch\('\/api\/notes'/u);
  assert.doesNotMatch(html, /SUPABASE_SECRET_KEY|sb_secret_/u);
});
