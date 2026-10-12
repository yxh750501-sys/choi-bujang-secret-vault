import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createNotesHandler } from '../api/notes.js';
import { createAuthHandlers } from '../src/server-session.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const userA = '123e4567-e89b-42d3-a456-426614174000';
const userB = '123e4567-e89b-42d3-a456-426614174001';
const studentIssuer = 'https://yweroshtkwjziprmgxcx.supabase.co/auth/v1';
const accessToken = (userId, expiration) => {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256' })).toString('base64url');
  const payload = Buffer.from(JSON.stringify({
    iss: studentIssuer,
    aud: 'authenticated',
    sub: userId,
    exp: expiration,
  })).toString('base64url');
  return `${header}.${payload}.mock-signature`;
};
const accessA = accessToken(userA, Math.floor(Date.now() / 1000) + 300);
const accessB = accessToken(userB, Math.floor(Date.now() / 1000) + 300);
const expiredAccess = accessToken(userA, Math.floor(Date.now() / 1000) - 300);
const forgedAccess = 'forged-access-token';
const noteA = '223e4567-e89b-42d3-a456-000000000001';
const noteB = '223e4567-e89b-42d3-a456-000000000002';

function responseMock() {
  const headers = new Map();
  let statusCode;
  let body;
  const response = {
    setHeader: (name, value) => headers.set(name.toLowerCase(), value),
    status: code => {
      statusCode = code;
      return { json: value => { body = value; return response; } };
    },
  };
  return { response, headers, get statusCode() { return statusCode; }, get body() { return body; } };
}

function createFixture() {
  const previousEnv = new Map([
    ['SUPABASE_URL', process.env.SUPABASE_URL],
    ['SUPABASE_SECRET_KEY', process.env.SUPABASE_SECRET_KEY],
    ['APP_ORIGIN', process.env.APP_ORIGIN],
    ['CSRF_SECRET', process.env.CSRF_SECRET],
    ['VERCEL', process.env.VERCEL],
  ]);
  process.env.SUPABASE_URL = 'https://database.example.test';
  process.env.SUPABASE_SECRET_KEY = 'sb_secret_notes_cookie_test';
  process.env.APP_ORIGIN = 'https://vault.example.test';
  process.env.CSRF_SECRET = 'fake-csrf-secret-for-cookie-test-only-32-bytes';
  process.env.VERCEL = '1';

  const rows = new Map([
    [noteA, { id: noteA, owner_id: userA, title: 'A note', content: 'A body' }],
    [noteB, { id: noteB, owner_id: userB, title: 'B note', content: 'B body' }],
  ]);
  const databaseCalls = [];
  const authorizations = [];
  const claimsByToken = new Map([
    [accessA, { iss: studentIssuer, aud: 'authenticated', role: 'authenticated', sub: userA,
      exp: Math.floor(Date.now() / 1000) + 300 }],
    [accessB, { iss: studentIssuer, aud: 'authenticated', role: 'authenticated', sub: userB,
      exp: Math.floor(Date.now() / 1000) + 300 }],
    [expiredAccess, { iss: studentIssuer, aud: 'authenticated', role: 'authenticated', sub: userA,
      exp: Math.floor(Date.now() / 1000) - 300 }],
  ]);
  const verifierFactory = options => createLoginVerifier({
    ...options,
    config: {
      judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
      publicAppUrl: 'https://student-defense.vercel.app',
      identityProvider: {
        issuer: studentIssuer,
        jwksUrl: `${studentIssuer}/.well-known/jwks.json`,
        audience: 'authenticated',
      },
    },
    judgeKeySet: () => {},
    supabaseClient: {
      auth: {
        getClaims: async token => {
          authorizations.push(token);
          const claims = claimsByToken.get(token);
          return claims ? { data: { claims }, error: null }
            : { data: { claims: null }, error: { code: 'INVALID_TOKEN' } };
        },
      },
    },
  });
  const handler = createNotesHandler({ verifierFactory });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (input, init = {}) => {
    const url = new URL(input);
    const method = init.method ?? 'GET';
    const headers = new Headers(init.headers);
    databaseCalls.push({ method, url, headers });
    assert.equal(headers.get('apikey'), 'sb_secret_notes_cookie_test');
    const id = url.searchParams.get('id')?.slice(3);
    const ownerId = url.searchParams.get('owner_id')?.slice(3);
    const objectMode = headers.get('accept')?.includes('vnd.pgrst.object+json');
    const respond = (items, status = 200) => {
      if (!objectMode) return new Response(JSON.stringify(items), {
        status,
        headers: { 'content-type': 'application/json' },
      });
      const item = Array.isArray(items) ? items[0] : items;
      return item
        ? new Response(JSON.stringify(item), { status, headers: { 'content-type': 'application/json' } })
        : new Response(JSON.stringify({
          code: 'PGRST116',
          details: 'The result contains 0 rows',
          message: 'JSON object requested, multiple (or no) rows returned',
        }), { status: 406, headers: { 'content-type': 'application/json' } });
    };

    if (method === 'GET') {
      const found = [...rows.values()].filter(row =>
        (!id || row.id === id) && (!ownerId || row.owner_id === ownerId));
      return respond(found);
    }
    if (method === 'POST') {
      const record = JSON.parse(init.body);
      rows.set(record.id, record);
      return respond([{ id: record.id }], 201);
    }
    if (method === 'PATCH') {
      const row = rows.get(id);
      if (!row || row.owner_id !== ownerId) return respond([]);
      Object.assign(row, JSON.parse(init.body));
      return respond([{ id: row.id, title: row.title, content: row.content }]);
    }
    if (method === 'DELETE') {
      const row = rows.get(id);
      if (!row || row.owner_id !== ownerId) return respond([]);
      rows.delete(id);
      return respond([{ id: row.id }]);
    }
    throw new Error(`Unexpected test method: ${method}`);
  };

  const auth = createAuthHandlers({
    env: process.env,
    nonceFactory: length => Buffer.alloc(length, 9),
  });
  return {
    handler,
    auth,
    rows,
    databaseCalls,
    authorizations,
    async csrfToken() {
      const result = responseMock();
      await auth.csrf({ method: 'GET', headers: {} }, result.response);
      assert.equal(result.statusCode, 200);
      return result.body.csrfToken;
    },
    request(method, token, { id, access = accessA, body, headers = {}, rawCookie } = {}) {
      const cookie = rawCookie ?? [
        `__Host-bb_access=${encodeURIComponent(access)}`,
        ...(token ? [`__Host-bb_csrf=${encodeURIComponent(token)}`] : []),
      ].join('; ');
      return {
        method,
        query: id === undefined ? {} : { id },
        body,
        headers: {
          cookie,
          origin: process.env.APP_ORIGIN,
          'sec-fetch-site': 'same-origin',
          ...(method === 'POST' || method === 'PUT' ? { 'content-type': 'application/json' } : {}),
          ...(token ? { 'x-csrf-token': token } : {}),
          ...headers,
        },
      };
    },
    async invoke(request) {
      const result = responseMock();
      await handler(request, result.response);
      return result;
    },
    restore() {
      globalThis.fetch = originalFetch;
      for (const [key, value] of previousEnv) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    },
  };
}

test('cookie authentication preserves A/B ownership and CRUD while Bearer remains supported', async () => {
  const fixture = createFixture();
  try {
    assert.notEqual(accessA, accessB, 'test users must have distinct access tokens');
    const csrf = await fixture.csrfToken();
    const listA = await fixture.invoke(fixture.request('GET', null));
    assert.equal(listA.statusCode, 200);
    assert.deepEqual(listA.body.notes.map(note => note.id), [noteA]);

    const createdA = await fixture.invoke(fixture.request('POST', csrf, {
      body: {
        title: 'New A note',
        body: 'Fictional A content',
        owner_id: userB,
      },
    }));
    assert.equal(createdA.statusCode, 201);
    assert.equal(fixture.rows.get(createdA.body.id).owner_id, userA);

    const detailA = await fixture.invoke(fixture.request('GET', null, { id: createdA.body.id }));
    assert.equal(detailA.statusCode, 200);
    assert.deepEqual(detailA.body, {
      id: createdA.body.id,
      title: 'New A note',
      body: 'Fictional A content',
    });

    const updatedA = await fixture.invoke(fixture.request('PUT', csrf, {
      id: createdA.body.id,
      body: { title: 'Updated A', body: 'Updated fictional content', owner_id: userB },
    }));
    assert.equal(updatedA.statusCode, 200);
    assert.equal(fixture.rows.get(createdA.body.id).owner_id, userA);

    const bCannotRead = await fixture.invoke(fixture.request('GET', null, {
      id: createdA.body.id,
      access: accessB,
    }));
    const bCannotUpdate = await fixture.invoke(fixture.request('PUT', csrf, {
      id: createdA.body.id,
      access: accessB,
      body: { title: 'Unauthorized', body: 'Must not change' },
    }));
    const bCannotDelete = await fixture.invoke(fixture.request('DELETE', csrf, {
      id: createdA.body.id,
      access: accessB,
    }));
    for (const denied of [bCannotRead, bCannotUpdate, bCannotDelete]) {
      assert.equal(denied.statusCode, 404);
      assert.deepEqual(denied.body, { error: 'NOTE_NOT_FOUND' });
    }
    assert.equal(fixture.rows.get(createdA.body.id).title, 'Updated A');

    const bList = await fixture.invoke(fixture.request('GET', null, { access: accessB }));
    assert.equal(bList.statusCode, 200);
    assert.deepEqual(bList.body.notes.map(note => note.id), [noteB]);

    const deletedA = await fixture.invoke(fixture.request('DELETE', csrf, { id: createdA.body.id }));
    assert.equal(deletedA.statusCode, 200);
    assert.equal(fixture.rows.has(createdA.body.id), false);

    const bearer = await fixture.invoke({
      method: 'GET',
      headers: { authorization: `Bearer ${accessA}` },
    });
    assert.equal(bearer.statusCode, 200);
    assert.deepEqual(bearer.body.notes.map(note => note.id), [noteA]);
    assert.ok(fixture.authorizations.includes(accessA));
    assert.doesNotMatch(JSON.stringify([createdA.body, updatedA.body]), /fake-access|sb_secret/u);
  } finally {
    fixture.restore();
  }
});

test('cookie mutations fail closed for CSRF, Origin, malformed cookies, and mixed credentials', async () => {
  const fixture = createFixture();
  try {
    const csrf = await fixture.csrfToken();
    const initialDatabaseCalls = fixture.databaseCalls.length;
    const noCsrf = await fixture.invoke(fixture.request('POST', null, {
      body: { title: 'Blocked', body: 'Blocked content' },
    }));
    const mismatchedCsrf = await fixture.invoke(fixture.request('POST', csrf, {
      body: { title: 'Blocked', body: 'Blocked content' },
      headers: { 'x-csrf-token': 'mismatched-test-csrf-token' },
    }));
    const wrongOrigin = await fixture.invoke(fixture.request('POST', csrf, {
      body: { title: 'Blocked', body: 'Blocked content' },
      headers: { origin: 'https://attacker.example.test' },
    }));
    const badContentType = await fixture.invoke(fixture.request('PUT', csrf, {
      id: noteA,
      body: { title: 'Blocked', body: 'Blocked content' },
      headers: { 'content-type': 'text/plain' },
    }));
    for (const denied of [noCsrf, mismatchedCsrf, wrongOrigin]) {
      assert.equal(denied.statusCode, 403);
      assert.deepEqual(denied.body, { error: 'CSRF_VALIDATION_FAILED' });
    }
    assert.equal(badContentType.statusCode, 415);
    assert.deepEqual(badContentType.body, { error: 'UNSUPPORTED_MEDIA_TYPE' });

    for (const access of [forgedAccess, expiredAccess]) {
      const denied = await fixture.invoke(fixture.request('GET', null, { access }));
      assert.equal(denied.statusCode, 401);
      assert.deepEqual(denied.body, { error: 'AUTHENTICATION_REQUIRED' });
    }
    const duplicateCookie = await fixture.invoke(fixture.request('GET', null, {
      rawCookie: `__Host-bb_access=${accessA}; __Host-bb_access=${accessB}`,
    }));
    assert.equal(duplicateCookie.statusCode, 401);
    const mixed = await fixture.invoke({
      method: 'GET',
      headers: {
        authorization: 'Bearer judge-token-a',
        cookie: `__Host-bb_access=${accessA}`,
      },
    });
    assert.equal(mixed.statusCode, 401);
    assert.deepEqual(mixed.body, { error: 'AMBIGUOUS_AUTHENTICATION' });
    const refreshMixed = await fixture.invoke({
      method: 'GET',
      headers: {
        authorization: 'Bearer judge-token-a',
        cookie: '__Host-bb_refresh=opaque-refresh-cookie',
      },
    });
    assert.equal(refreshMixed.statusCode, 401);
    assert.deepEqual(refreshMixed.body, { error: 'AMBIGUOUS_AUTHENTICATION' });

    assert.equal(fixture.databaseCalls.length, initialDatabaseCalls);
    assert.equal(fixture.rows.get(noteA).title, 'A note');
    assert.doesNotMatch(JSON.stringify([noCsrf.body, mixed.body]), /fake-access|sb_secret/u);
  } finally {
    fixture.restore();
  }
});

test('missing authentication returns JSON 401 without querying notes', async () => {
  const fixture = createFixture();
  try {
    const denied = await fixture.invoke({ method: 'GET', headers: {} });
    assert.equal(denied.statusCode, 401);
    assert.equal(denied.headers.get('content-type'), 'application/json; charset=utf-8');
    assert.deepEqual(denied.body, { error: 'AUTHENTICATION_REQUIRED' });
    assert.equal(fixture.databaseCalls.length, 0);
  } finally {
    fixture.restore();
  }
});
