import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { createAuthController, createAuthorizationHeader } from '../src/auth-controller.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const config = {
  step: 3,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  publicAppUrl: 'https://student-defense.vercel.app',
  identityProvider: {
    issuer: 'https://yweroshtkwjziprmgxcx.supabase.co/auth/v1',
    jwksUrl: 'https://yweroshtkwjziprmgxcx.supabase.co/auth/v1/.well-known/jwks.json',
    audience: 'authenticated',
  },
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};
const testUserId = '123e4567-e89b-42d3-a456-426614174000';
const testToken = `eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.${Buffer
  .from(JSON.stringify({ iss: config.identityProvider.issuer }))
  .toString('base64url')}.mock-signature`;

function createTestNotesHandler() {
  return createNotesHandler({
    verifierFactory: options => createLoginVerifier({
      ...options,
      judgeKeySet: () => {},
      supabaseClient: {
        auth: {
          getClaims: async token => token === testToken
            ? {
              data: {
                claims: {
                  iss: config.identityProvider.issuer,
                  aud: config.identityProvider.audience,
                  role: 'authenticated',
                  sub: testUserId,
                  exp: Math.floor(Date.now() / 1000) + 300,
                },
              },
              error: null,
            }
            : { data: { claims: null }, error: { code: 'INVALID_TOKEN' } },
        },
      },
    }),
  });
}

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

function mockSupabaseAuth({ initialSession = null, signInError = null } = {}) {
  let session = initialSession;
  let authStateListener = () => {};
  let signInCalls = 0;
  let signOutCalls = 0;
  const auth = {
    getSession: async () => ({ data: { session }, error: null }),
    onAuthStateChange: listener => {
      authStateListener = listener;
      return { data: { subscription: { unsubscribe() {} } } };
    },
    signInWithPassword: async ({ email }) => {
      signInCalls += 1;
      if (signInError) return { data: { session: null }, error: signInError };
      session = { user: { email }, access_token: 'test-access-token' };
      authStateListener('SIGNED_IN', session);
      return { data: { session }, error: null };
    },
    signOut: async () => {
      signOutCalls += 1;
      session = null;
      authStateListener('SIGNED_OUT', null);
      return { error: null };
    },
  };
  return {
    client: { auth },
    get session() { return session; },
    get signInCalls() { return signInCalls; },
    get signOutCalls() { return signOutCalls; },
  };
}

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 3,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('third-stage attack check confirms anonymous data is private and API denial is JSON', async () => {
  const originalFetch = globalThis.fetch;
  let requestUrl;
  const requestedUrls = [];
  let apiOptions;
  let dataResponse = () => new Response(null, { status: 404 });
  let jsonApiDenial = true;
  let apiRequestCount = 0;
  try {
    globalThis.fetch = async (url, init) => {
      requestUrl = String(url);
      requestedUrls.push(requestUrl);
      if (new URL(url).pathname === '/api/notes') {
        apiOptions = init;
        apiRequestCount += 1;
        if (!jsonApiDenial) {
          return new Response('<html>denied</html>', {
            status: 401,
            headers: { 'content-type': 'text/html' },
          });
        }
        return new Response(JSON.stringify({ error: 'AUTHENTICATION_REQUIRED' }), {
          status: 401,
          headers: { 'content-type': 'application/json; charset=utf-8' },
        });
      }
      return dataResponse();
    };
    const [result, apiResult] = await runAttackChecks(config);
    assert.deepEqual(requestedUrls.slice(0, 2), [
      'https://student-defense.vercel.app/data.json',
      'https://student-defense.vercel.app/api/notes',
    ]);
    assert.equal(requestUrl, 'https://student-defense.vercel.app/api/notes');
    assert.equal(apiOptions.redirect, 'error');
    assert.match(result.expected, /메모 0건 또는 404/u);
    assert.match(result.observed, /공개 메모가 없음/u);
    assert.equal(apiResult.attackId, 'anonymous_notes_api');
    assert.match(apiResult.observed, /JSON 오류로 거부됨/u);

    dataResponse = () => new Response(JSON.stringify({ notes: [] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    const [empty] = await runAttackChecks(config);
    assert.match(empty.observed, /공개 메모가 없음/u);
    dataResponse = () => new Response(JSON.stringify({ notes: [{ title: '가상' }] }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
    const [failed] = await runAttackChecks(config);
    assert.match(failed.observed, /메모가 노출됨/u);
    assert.equal(apiRequestCount, 3);

    jsonApiDenial = false;
    const [, htmlDenied] = await runAttackChecks(config);
    assert.match(htmlDenied.observed, /안전한 JSON 거부를 확인하지 못함/u);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('notes API requires verified bearer auth before reading rows', async () => {
  const originalFetch = globalThis.fetch;
  const originalConsoleError = console.error;
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const diagnostics = [];
  const rows = Array.from({ length: 4 }, (_, index) => ({
    id: `123e4567-e89b-42d3-a456-${String(index + 1).padStart(12, '0')}`,
    title: `Example ${index + 1}`,
    content: 'Fictional test content',
  }));
  const notesHandler = createTestNotesHandler();
  let requestedUrl;
  let requestKey;
  let databaseRequests = 0;
  try {
    process.env.SUPABASE_URL = 'https://database.example.test';
    process.env.SUPABASE_SECRET_KEY = 'sb_secret_test';
    console.error = (...args) => diagnostics.push(args);
    globalThis.fetch = async (url, options) => {
      databaseRequests += 1;
      requestedUrl = new URL(url);
      requestKey = new Headers(options.headers).get('apikey');
      return new Response(JSON.stringify(rows), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    };
    const missingAuthorization = mockResponse();
    await notesHandler({ method: 'GET', headers: {} }, missingAuthorization.response);
    assert.equal(missingAuthorization.statusCode, 401);
    assert.equal(missingAuthorization.headers.get('content-type'), 'application/json; charset=utf-8');
    assert.deepEqual(missingAuthorization.body, { error: 'AUTHENTICATION_REQUIRED' });
    assert.equal(databaseRequests, 0);

    const forgedIdentity = mockResponse();
    await notesHandler({
      method: 'GET',
      headers: { authorization: 'Bearer not-a-valid-token' },
      body: { userId: testUserId, role: 'admin', owner_id: testUserId },
    }, forgedIdentity.response);
    assert.equal(forgedIdentity.statusCode, 401);
    assert.deepEqual(forgedIdentity.body, { error: 'AUTHENTICATION_REQUIRED' });
    assert.equal(JSON.stringify(forgedIdentity.body).includes('notes'), false);
    assert.equal(databaseRequests, 0);

    const success = mockResponse();
    await notesHandler({
      method: 'GET',
      headers: { authorization: `Bearer ${testToken}` },
      body: { userId: 'ffffffff-ffff-4fff-8fff-ffffffffffff', role: 'admin' },
      query: { owner_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff' },
    }, success.response);
    assert.equal(success.statusCode, 200);
    assert.equal(success.headers.get('cache-control'), 'no-store');
    assert.equal(requestedUrl.pathname, '/rest/v1/notes');
    assert.equal(requestedUrl.searchParams.has('limit'), false);
    assert.equal(requestedUrl.searchParams.has('userId'), false);
    assert.equal(requestKey, 'sb_secret_test');
    assert.deepEqual(success.body, {
      notes: rows.map(({ id, title, content }) => ({ id, title, body: content })),
    });
    assert.doesNotMatch(JSON.stringify(success.body), /sb_secret_test/u);

    delete process.env.SUPABASE_URL;
    delete process.env.SUPABASE_SECRET_KEY;
    const missingConfiguration = mockResponse();
    await notesHandler({
      method: 'GET',
      headers: { authorization: `Bearer ${testToken}` },
    }, missingConfiguration.response);
    assert.equal(missingConfiguration.statusCode, 503);
    assert.deepEqual(missingConfiguration.body, { error: 'NOTES_UNAVAILABLE' });
    assert.deepEqual(diagnostics[0], ['notes_api_supabase_diagnostic', {
      supabaseUrlPresent: false,
      secretKeyPresent: false,
      httpStatus: null,
      errorCode: 'ENV_MISSING',
    }]);

    process.env.SUPABASE_URL = 'https://database.example.test';
    process.env.SUPABASE_SECRET_KEY = 'sb_secret_test';

    globalThis.fetch = async () => new Response(JSON.stringify({
      code: '42501',
      message: 'sensitive database message',
      details: 'sensitive database details',
      hint: 'sensitive database hint',
    }), { status: 500, headers: { 'content-type': 'application/json' } });
    const failed = mockResponse();
    await notesHandler({
      method: 'GET',
      headers: { authorization: `Bearer ${testToken}` },
    }, failed.response);
    assert.equal(failed.statusCode, 503);
    assert.deepEqual(failed.body, { error: 'NOTES_UNAVAILABLE' });
    assert.deepEqual(diagnostics[1], ['notes_api_supabase_diagnostic', {
      supabaseUrlPresent: true,
      secretKeyPresent: true,
      httpStatus: 500,
      errorCode: '42501',
    }]);
    assert.doesNotMatch(JSON.stringify(diagnostics), /sb_secret_test|sensitive database/u);

    const rejected = mockResponse();
    await notesHandler({ method: 'DELETE', headers: {} }, rejected.response);
    assert.equal(rejected.statusCode, 405);
    assert.equal(rejected.headers.get('allow'), 'GET, POST');
  } finally {
    globalThis.fetch = originalFetch;
    console.error = originalConsoleError;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});

test('notes CRUD authenticates every route and maps body, id, and owner safely', async () => {
  const originalFetch = globalThis.fetch;
  const previousUrl = process.env.SUPABASE_URL;
  const previousKey = process.env.SUPABASE_SECRET_KEY;
  const notesHandler = createTestNotesHandler();
  const notesByIdHandler = createTestNotesHandler();
  const rows = new Map();
  const requests = [];
  const createdIdHolder = [];
  const secretKey = 'sb_secret_test';
  const apiToken = `Bearer ${testToken}`;

  globalThis.fetch = async (url, options) => {
    const parsed = new URL(url);
    const method = options.method ?? 'GET';
    const id = parsed.searchParams.get('id')?.slice('eq.'.length);
    const suppliedKey = new Headers(options.headers).get('apikey');
    assert.equal(suppliedKey, secretKey);
    requests.push({ method, id, url: parsed });

    if (method === 'GET') {
      const result = [...rows.values()].filter(row => !id || row.id === id);
      return new Response(JSON.stringify(result), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'POST') {
      const record = JSON.parse(options.body);
      rows.set(record.id, record);
      createdIdHolder.push(record.id);
      return new Response(JSON.stringify({ id: record.id }), {
        status: 201,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'PATCH') {
      const row = rows.get(id);
      if (!row) return new Response('[]', { status: 200 });
      const update = JSON.parse(options.body);
      Object.assign(row, update);
      return new Response(JSON.stringify(row), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    if (method === 'DELETE') {
      const existed = rows.has(id);
      rows.delete(id);
      return new Response(JSON.stringify(existed ? { id } : null), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }
    throw new Error(`Unexpected test method: ${method}`);
  };

  const invoke = async (handler, method, { id, authorization = apiToken, body } = {}) => {
    const result = mockResponse();
    await handler({
      method,
      query: id === undefined ? {} : { id },
      headers: authorization ? { authorization } : {},
      body,
      userId: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
      role: 'admin',
      owner_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
    }, result.response);
    return result;
  };
  try {
    process.env.SUPABASE_URL = 'https://database.example.test';
    process.env.SUPABASE_SECRET_KEY = secretKey;

    const protectedRequests = [
      [notesHandler, 'GET', {}],
      [notesHandler, 'POST', { body: { title: 'A', body: 'B' } }],
      [notesByIdHandler, 'GET', { id: testUserId }],
      [notesByIdHandler, 'PUT', { id: testUserId, body: { title: 'A', body: 'B' } }],
      [notesByIdHandler, 'DELETE', { id: testUserId }],
    ];
    for (const [handler, method, args] of protectedRequests) {
      const anonymous = await invoke(handler, method, { ...args, authorization: null });
      assert.equal(anonymous.statusCode, 401);
      assert.deepEqual(anonymous.body, { error: 'AUTHENTICATION_REQUIRED' });
      const forged = await invoke(handler, method, {
        ...args,
        authorization: 'Bearer malformed',
      });
      assert.equal(forged.statusCode, 401);
      assert.deepEqual(forged.body, { error: 'AUTHENTICATION_REQUIRED' });
    }
    assert.equal(requests.length, 0, 'unauthenticated and forged requests must not touch notes');

    const invalidId = await invoke(notesByIdHandler, 'GET', { id: 'not-a-uuid' });
    assert.equal(invalidId.statusCode, 400);
    assert.deepEqual(invalidId.body, { error: 'INVALID_NOTE_ID' });
    const invalidBody = await invoke(notesHandler, 'POST', { body: { title: '', body: 'x' } });
    assert.equal(invalidBody.statusCode, 400);
    assert.deepEqual(invalidBody.body, { error: 'INVALID_NOTE' });
    const invalidPostId = await invoke(notesHandler, 'POST', {
      body: { id: 'not-a-uuid', title: 'A', body: 'B' },
    });
    assert.equal(invalidPostId.statusCode, 400);
    assert.deepEqual(invalidPostId.body, { error: 'INVALID_NOTE' });
    assert.equal(requests.length, 0, 'invalid input must not touch notes');

    const created = await invoke(notesHandler, 'POST', {
      body: {
        title: 'Virtual note',
        body: 'Fictional test body',
        owner_id: 'ffffffff-ffff-4fff-8fff-ffffffffffff',
        role: 'admin',
      },
    });
    assert.equal(created.statusCode, 201);
    assert.match(created.body.id, /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu);
    const stored = rows.get(created.body.id);
    assert.equal(stored.owner_id, testUserId);
    assert.equal(stored.content, 'Fictional test body');
    assert.equal(Object.hasOwn(stored, 'body'), false);
    assert.deepEqual(createdIdHolder, [created.body.id]);

    const list = await invoke(notesHandler, 'GET');
    assert.equal(list.statusCode, 200);
    assert.deepEqual(list.body, {
      notes: [{ id: created.body.id, title: 'Virtual note', body: 'Fictional test body' }],
    });

    const detail = await invoke(notesByIdHandler, 'GET', { id: created.body.id });
    assert.equal(detail.statusCode, 200);
    assert.deepEqual(detail.body, {
      id: created.body.id,
      title: 'Virtual note',
      body: 'Fictional test body',
    });

    const updated = await invoke(notesByIdHandler, 'PUT', {
      id: created.body.id,
      body: { title: 'Updated virtual note', body: 'Updated fictional body' },
    });
    assert.equal(updated.statusCode, 200);
    assert.deepEqual(updated.body, {
      id: created.body.id,
      title: 'Updated virtual note',
      body: 'Updated fictional body',
    });
    assert.deepEqual((await invoke(notesByIdHandler, 'GET', { id: created.body.id })).body, updated.body);

    const deleted = await invoke(notesByIdHandler, 'DELETE', { id: created.body.id });
    assert.equal(deleted.statusCode, 200);
    assert.deepEqual(deleted.body, { id: created.body.id });
    const afterDelete = await invoke(notesByIdHandler, 'GET', { id: created.body.id });
    assert.equal(afterDelete.statusCode, 404);
    assert.deepEqual(afterDelete.body, { error: 'NOTE_NOT_FOUND' });

    const providedId = '123e4567-e89b-42d3-a456-426614174001';
    const createdWithId = await invoke(notesHandler, 'POST', {
      body: { id: providedId, title: 'Client-selected UUID', body: 'Fictional content' },
    });
    assert.equal(createdWithId.statusCode, 201);
    assert.deepEqual(createdWithId.body, { id: providedId });
    assert.equal(rows.get(providedId).owner_id, testUserId);
  } finally {
    globalThis.fetch = originalFetch;
    if (previousUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = previousUrl;
    if (previousKey === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = previousKey;
  }
});

test('public page loads a login form and local Supabase modules only', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const browserModule = await readFile(new URL('../src/auth-browser.mjs', import.meta.url), 'utf8');
  assert.match(html, /id="login-form"/u);
  assert.match(html, /id="login-email"/u);
  assert.match(html, /id="login-password"/u);
  assert.match(html, /id="logout-button"/u);
  assert.match(html, /id="note-form"/u);
  assert.match(html, /id="new-note"/u);
  assert.match(html, /id="delete-note"/u);
  assert.match(html, /src="\/vendor\/supabase\.js"/u);
  assert.match(html, /src="\/supabase-config\.js"/u);
  assert.match(html, /src="\/auth-browser\.mjs"/u);
  assert.match(browserModule, /apiRequest\('\/api\/notes'/u);
  assert.match(browserModule, /Authorization: createAuthorizationHeader\(accessToken\)/u);
  assert.equal(createAuthorizationHeader('test-access-token'), 'Bearer test-access-token');
  assert.throws(() => createAuthorizationHeader(''));
  assert.doesNotMatch(`${html}\n${browserModule}`, /SUPABASE_SECRET_KEY|sb_secret_/u);
});

test('auth controller signs in, restores a session, and signs out', async () => {
  const auth = mockSupabaseAuth();
  const states = [];
  const controller = createAuthController(auth.client, state => states.push(state));
  await controller.initialize();
  assert.equal(controller.state.loading, false);
  assert.equal(controller.state.authenticated, false);

  const mockPassword = String(Date.now());
  assert.equal(await controller.signIn('student@example.test', mockPassword), true);
  assert.equal(auth.signInCalls, 1);
  assert.equal(controller.state.authenticated, true);
  assert.equal(controller.state.email, 'student@example.test');
  assert.equal(await controller.getAccessToken(), 'test-access-token');
  assert.equal(controller.state.sessionRevision, 1);

  const restoredStates = [];
  const restored = createAuthController(mockSupabaseAuth({ initialSession: auth.session }).client,
    state => restoredStates.push(state));
  await restored.initialize();
  assert.equal(restored.state.authenticated, true);
  assert.equal(restored.state.email, 'student@example.test');
  assert.equal(await restored.getAccessToken(), 'test-access-token');
  assert.equal(await restored.signOut(), true);
  assert.equal(restored.state.authenticated, false);
  assert.equal(restored.state.email, null);
  assert.ok(states.some(state => state.authenticated));
  assert.ok(restoredStates.some(state => state.authenticated));
  assert.equal(await restored.getAccessToken(), null);
});

test('CRUD UI, server-only database privileges, and stage-three routes are configured', async () => {
  const html = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  const browserModule = await readFile(new URL('../src/auth-browser.mjs', import.meta.url), 'utf8');
  const browserController = await readFile(new URL('../src/auth-controller.mjs', import.meta.url), 'utf8');
  const itemRoute = await readFile(new URL('../api/notes/[id].js', import.meta.url), 'utf8');
  const configFile = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  const schema = await readFile(new URL('../supabase/schema.sql', import.meta.url), 'utf8');
  const buildScript = await readFile(new URL('../scripts/build-public.mjs', import.meta.url), 'utf8');
  const vercelConfig = JSON.parse(await readFile(new URL('../vercel.json', import.meta.url), 'utf8'));
  assert.equal(configFile.step, 3);
  assert.deepEqual(configFile.allowedRoutes, [
    'GET /api/notes',
    'POST /api/notes',
    'GET /api/notes/:id',
    'PUT /api/notes/:id',
    'DELETE /api/notes/:id',
  ]);
  assert.equal(configFile.identityProvider.audience, 'authenticated');
  assert.match(html, /id="note-form"/u);
  assert.match(html, /id="new-note"/u);
  assert.match(html, /id="delete-note"/u);
  assert.match(browserModule, /Authorization:/u);
  assert.match(browserModule, /method: editingId \? 'PUT' : 'POST'/u);
  assert.match(browserModule, /method: 'DELETE'/u);
  assert.match(browserModule, /window\.confirm/u);
  assert.match(schema, /grant select, insert, update, delete on table public\.notes to service_role;/u);
  assert.match(itemRoute, /import notesHandler from '\.\.\/notes\.js'/u);
  assert.match(buildScript, /resolve\(root, 'public', 'aleph\.json'\)/u);
  assert.deepEqual(vercelConfig.headers[0].headers.find(header =>
    header.key === 'X-Content-Type-Options'), { key: 'X-Content-Type-Options', value: 'nosniff' });
  assert.doesNotMatch(`${html}\n${browserModule}\n${browserController}`, /SUPABASE_SECRET_KEY|sb_secret_/u);
});

test('auth controller rejects tokenless sessions and clears expired sessions locally', async () => {
  const tokenless = createAuthController(mockSupabaseAuth({
    initialSession: { user: { email: 'student@example.test' } },
  }).client);
  await tokenless.initialize();
  assert.equal(tokenless.state.authenticated, false);
  assert.equal(await tokenless.getAccessToken(), null);

  const auth = mockSupabaseAuth();
  const controller = createAuthController(auth.client);
  await controller.initialize();
  assert.equal(await controller.signIn('student@example.test', 'test-password'), true);
  assert.equal(await controller.expireSession(), true);
  assert.equal(controller.state.authenticated, false);
  assert.equal(controller.state.email, null);
  assert.match(controller.state.message, /서버 인증이 만료/u);
  assert.equal(await controller.getAccessToken(), null);
});

test('auth controller returns safe login errors and blocks duplicate submits', async () => {
  const auth = mockSupabaseAuth({
    signInError: {
      code: 'invalid_credentials',
      status: 400,
      message: 'private auth error detail',
    },
  });
  const controller = createAuthController(auth.client);
  await controller.initialize();
  assert.equal(await controller.signIn('student@example.test', String(Date.now())), false);
  assert.equal(controller.state.message, '이메일 또는 비밀번호를 확인해 주세요.');
  assert.doesNotMatch(controller.state.message, /private auth error detail/u);
  assert.equal(auth.signInCalls, 1);

  const pendingAuth = mockSupabaseAuth();
  let releaseSignIn;
  pendingAuth.client.auth.signInWithPassword = () => new Promise(resolve => {
    releaseSignIn = () => resolve({
      data: { session: null },
      error: { code: 'invalid_credentials', status: 400 },
    });
  });
  const pendingController = createAuthController(pendingAuth.client);
  await pendingController.initialize();
  const pendingResult = pendingController.signIn('student@example.test', String(Date.now()));
  assert.equal(pendingController.state.busy, true);
  assert.equal(await pendingController.signIn('student@example.test', String(Date.now())), false);
  releaseSignIn();
  assert.equal(await pendingResult, false);
});
