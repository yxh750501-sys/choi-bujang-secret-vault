import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createAuthHandlers } from '../src/server-session.mjs';

const accessTokenOne = 'fake-access-token-one';
const refreshTokenOne = 'fake-refresh-token-one';
const accessTokenTwo = 'fake-access-token-two';
const refreshTokenTwo = 'fake-refresh-token-two';
const accessTokenB = 'fake-access-token-b';
const password = 'fake-password-for-test-only';

function fixture({ loginError = null, refreshError = null, userError = false } = {}) {
  let currentTime = 1_800_000_000_000;
  const env = {
    APP_ORIGIN: 'https://vault.example.test',
    CSRF_SECRET: 'fake-csrf-secret-for-unit-tests-only-32-bytes',
    SUPABASE_URL: 'https://project.example.test',
    SUPABASE_PUBLISHABLE_KEY: 'fake-publishable-key-for-unit-tests',
    VERCEL: '1',
  };
  const calls = { clientOptions: [], login: [], refresh: [], user: [], setSession: [], signOut: [] };
  const clientFactory = (url, key, options) => {
    calls.clientOptions.push({ url, key, options });
    return {
      auth: {
        signInWithPassword: async credentials => {
          calls.login.push(credentials);
          return loginError
            ? { data: { session: null }, error: loginError }
            : {
              data: {
                session: {
                  access_token: accessTokenOne,
                  refresh_token: refreshTokenOne,
                  expires_in: 1800,
                  user: { id: 'user-a', email: 'a@example.test' },
                },
              },
              error: null,
            };
        },
        getUser: async token => {
          calls.user.push(token);
          if (userError) return { data: { user: null }, error: userError };
          if (![accessTokenOne, accessTokenTwo, accessTokenB].includes(token)) {
            return { data: { user: null }, error: { status: 401 } };
          }
          return {
            data: {
              user: {
                id: token === accessTokenB ? 'user-b' : 'user-a',
                email: token === accessTokenB ? 'b@example.test' : 'a@example.test',
              },
            },
            error: null,
          };
        },
        refreshSession: async ({ refresh_token }) => {
          calls.refresh.push(refresh_token);
          return refreshError || refresh_token !== refreshTokenOne
            ? { data: { session: null }, error: { status: 401 } }
            : {
              data: {
                session: {
                  access_token: accessTokenTwo,
                  refresh_token: refreshTokenTwo,
                  expires_in: 1800,
                  user: { id: 'user-a', email: 'a@example.test' },
                },
              },
              error: null,
            };
        },
        setSession: async tokens => {
          calls.setSession.push(tokens);
          return { data: { session: null }, error: null };
        },
        signOut: async options => {
          calls.signOut.push(options);
          return { error: null };
        },
      },
    };
  };
  return {
    env,
    calls,
    handlers: createAuthHandlers({
      env,
      clientFactory,
      now: () => currentTime,
      nonceFactory: length => Buffer.alloc(length, 7),
    }),
    setNow(value) { currentTime = value; },
  };
}

function responseMock() {
  const headers = new Map();
  let statusCode;
  let body;
  const response = {
    setHeader: (name, value) => headers.set(name.toLowerCase(), value),
    getHeader: name => headers.get(name.toLowerCase()),
    status: code => {
      statusCode = code;
      return { json: value => { body = value; return response; } };
    },
  };
  return {
    response,
    headers,
    get statusCode() { return statusCode; },
    get body() { return body; },
  };
}

function csrfRequest(fixtureState, token, overrides = {}) {
  return {
    method: 'POST',
    headers: {
      origin: fixtureState.env.APP_ORIGIN,
      'sec-fetch-site': 'same-origin',
      'content-type': 'application/json',
      cookie: `__Host-bb_csrf=${encodeURIComponent(token)}`,
      'x-csrf-token': token,
      ...overrides,
    },
    body: {},
  };
}

async function issueCsrf(fixtureState) {
  const result = responseMock();
  await fixtureState.handlers.csrf({ method: 'GET', headers: {} }, result.response);
  assert.equal(result.statusCode, 200);
  return { token: result.body.csrfToken, cookies: result.headers.get('set-cookie') };
}

function cookieValue(setCookie, name) {
  const cookie = setCookie.find(value => value.startsWith(`${name}=`));
  assert.ok(cookie, `missing ${name} cookie`);
  return decodeURIComponent(cookie.slice(name.length + 1, cookie.indexOf(';')));
}

test('login validates JSON and credentials and issues secure HttpOnly cookies without tokens in JSON', async () => {
  const state = fixture();
  const csrf = await issueCsrf(state);
  const result = responseMock();
  result.response.setHeader('Set-Cookie', ['unrelated=preserve; Path=/']);
  await state.handlers.login({
    ...csrfRequest(state, csrf.token),
    body: { email: ' a@example.test ', password },
  }, result.response);

  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { authenticated: true, user: { id: 'user-a', email: 'a@example.test' } });
  assert.doesNotMatch(JSON.stringify(result.body), /fake-access|fake-refresh|fake-password|fake-publishable/u);
  const setCookies = result.headers.get('set-cookie');
  assert.equal(setCookies.length, 3);
  assert.equal(setCookies[0], 'unrelated=preserve; Path=/');
  for (const cookie of setCookies.slice(1)) {
    assert.match(cookie, /^__Host-bb_(?:access|refresh)=/u);
    assert.match(cookie, /; HttpOnly;/u);
    assert.match(cookie, /; Secure;/u);
    assert.match(cookie, /; SameSite=Strict;/u);
    assert.match(cookie, /; Path=\//u);
    assert.doesNotMatch(cookie, /; Domain=/iu);
  }
  assert.deepEqual(state.calls.login, [{ email: 'a@example.test', password }]);
  assert.equal(state.calls.clientOptions[0].key, state.env.SUPABASE_PUBLISHABLE_KEY);
  assert.equal(state.calls.clientOptions[0].url, state.env.SUPABASE_URL);
  assert.equal(state.calls.clientOptions[0].options.auth.persistSession, false);
});

test('login rejects invalid content, invalid fields, and oversized requests before Auth', async () => {
  const state = fixture();
  const csrf = await issueCsrf(state);
  for (const [request, status, error] of [
    [{ ...csrfRequest(state, csrf.token), headers: { ...csrfRequest(state, csrf.token).headers, 'content-type': 'text/plain' } }, 400, 'INVALID_CONTENT_TYPE'],
    [{ ...csrfRequest(state, csrf.token), headers: { ...csrfRequest(state, csrf.token).headers, 'content-length': '9000' } }, 413, 'REQUEST_TOO_LARGE'],
    [{ ...csrfRequest(state, csrf.token), body: { email: 'not-an-email', password } }, 400, 'INVALID_CREDENTIALS_FORMAT'],
    [{ ...csrfRequest(state, csrf.token), body: { email: 'a@example.test', password: '' } }, 400, 'INVALID_CREDENTIALS_FORMAT'],
  ]) {
    const result = responseMock();
    await state.handlers.login(request, result.response);
    assert.equal(result.statusCode, status);
    assert.deepEqual(result.body, { error });
  }
  assert.equal(state.calls.login.length, 0);
});

test('login failures expose only a generic JSON error', async () => {
  const state = fixture({ loginError: { message: 'provider details with sensitive values' } });
  const csrf = await issueCsrf(state);
  const result = responseMock();
  await state.handlers.login({
    ...csrfRequest(state, csrf.token),
    body: { email: 'a@example.test', password },
  }, result.response);
  assert.equal(result.statusCode, 401);
  assert.deepEqual(result.body, { error: 'AUTHENTICATION_FAILED' });
  assert.doesNotMatch(JSON.stringify(result.body), /provider details|fake-password/u);
});

test('session lookup validates access cookie through Supabase and rejects forged or expired tokens', async () => {
  const state = fixture();
  for (const [token, expectedStatus] of [
    [accessTokenOne, 200],
    [accessTokenB, 200],
    ['forged-token', 401],
    ['expired-token', 401],
    ['', 401],
  ]) {
    const result = responseMock();
    await state.handlers.session({
      method: 'GET',
      headers: { cookie: token ? `__Host-bb_access=${token}` : '' },
    }, result.response);
    assert.equal(result.statusCode, expectedStatus);
    if (expectedStatus === 200) {
      const expectedUser = token === accessTokenB
        ? { id: 'user-b', email: 'b@example.test' }
        : { id: 'user-a', email: 'a@example.test' };
      assert.deepEqual(result.body, { authenticated: true, user: expectedUser });
      assert.doesNotMatch(JSON.stringify(result.body), /fake-access|fake-refresh/u);
    } else {
      assert.deepEqual(result.body, { error: 'AUTHENTICATION_REQUIRED' });
    }
  }
  assert.deepEqual(state.calls.user, [accessTokenOne, accessTokenB, 'forged-token', 'expired-token']);
});

test('session lookup preserves cookies during temporary Auth outages', async () => {
  const state = fixture({ userError: { status: 503 } });
  const result = responseMock();
  await state.handlers.session({
    method: 'GET',
    headers: { cookie: `__Host-bb_access=${accessTokenOne}` },
  }, result.response);
  assert.equal(result.statusCode, 503);
  assert.deepEqual(result.body, { error: 'AUTH_UNAVAILABLE' });
  assert.equal(result.headers.get('set-cookie'), undefined);
});

test('session refresh rotates both HttpOnly cookies and clears them on failure', async () => {
  const state = fixture();
  const csrf = await issueCsrf(state);
  const result = responseMock();
  await state.handlers.refresh({
    ...csrfRequest(state, csrf.token),
    headers: {
      ...csrfRequest(state, csrf.token).headers,
      cookie: `__Host-bb_csrf=${encodeURIComponent(csrf.token)}; __Host-bb_refresh=${refreshTokenOne}`,
    },
  }, result.response);
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { authenticated: true, user: { id: 'user-a', email: 'a@example.test' } });
  const cookies = result.headers.get('set-cookie');
  assert.equal(cookieValue(cookies, '__Host-bb_access'), accessTokenTwo);
  assert.equal(cookieValue(cookies, '__Host-bb_refresh'), refreshTokenTwo);
  assert.deepEqual(state.calls.refresh, [refreshTokenOne]);
  assert.doesNotMatch(JSON.stringify(result.body), /fake-access|fake-refresh/u);

  const failed = responseMock();
  await state.handlers.refresh({
    ...csrfRequest(state, csrf.token),
    headers: {
      ...csrfRequest(state, csrf.token).headers,
      cookie: `__Host-bb_csrf=${encodeURIComponent(csrf.token)}; __Host-bb_refresh=expired-refresh`,
    },
  }, failed.response);
  assert.equal(failed.statusCode, 401);
  assert.deepEqual(failed.body, { error: 'SESSION_REFRESH_FAILED' });
  assert.equal(failed.headers.get('set-cookie').length, 3);
  assert.ok(failed.headers.get('set-cookie').every(cookie => /Max-Age=0/u.test(cookie)));
});

test('logout removes all session cookies and requests server-side revocation', async () => {
  const state = fixture();
  const csrf = await issueCsrf(state);
  const result = responseMock();
  await state.handlers.logout({
    ...csrfRequest(state, csrf.token),
    headers: {
      ...csrfRequest(state, csrf.token).headers,
      cookie: `__Host-bb_csrf=${encodeURIComponent(csrf.token)}; __Host-bb_access=${accessTokenOne}; __Host-bb_refresh=${refreshTokenOne}`,
    },
  }, result.response);
  assert.equal(result.statusCode, 200);
  assert.deepEqual(result.body, { authenticated: false, serverSessionRevoked: true });
  assert.equal(result.headers.get('set-cookie').length, 3);
  assert.ok(result.headers.get('set-cookie').every(cookie => /Max-Age=0/u.test(cookie)));
  assert.deepEqual(state.calls.setSession, [{ access_token: accessTokenOne, refresh_token: refreshTokenOne }]);
  assert.deepEqual(state.calls.signOut, [{ scope: 'global' }]);
});

test('CSRF token is signed, double-submitted, and all mutating routes reject invalid origin or token', async () => {
  const state = fixture();
  const csrf = await issueCsrf(state);
  const invalidRequests = [
    csrfRequest(state, csrf.token, { 'x-csrf-token': undefined }),
    csrfRequest(state, csrf.token, { 'x-csrf-token': 'forged-token' }),
    csrfRequest(state, '1800007200.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'),
    csrfRequest(state, csrf.token, { origin: 'https://attacker.example.test' }),
    csrfRequest(state, csrf.token, { 'sec-fetch-site': 'cross-site' }),
  ];
  for (const request of invalidRequests) {
    const result = responseMock();
    await state.handlers.logout(request, result.response);
    assert.equal(result.statusCode, 403);
    assert.match(result.body.error, /ORIGIN_NOT_ALLOWED|CSRF_VALIDATION_FAILED/u);
  }
  assert.equal(state.calls.signOut.length, 0);

  const expiredState = fixture();
  const expiredCsrf = await issueCsrf(expiredState);
  expiredState.setNow(1_800_000_000_000 + 3 * 60 * 60 * 1000);
  const expired = responseMock();
  await expiredState.handlers.logout(csrfRequest(expiredState, expiredCsrf.token), expired.response);
  assert.equal(expired.statusCode, 403);
  assert.deepEqual(expired.body, { error: 'CSRF_VALIDATION_FAILED' });
});

test('non-production cookies use development names and can be cleared with the same attributes', async () => {
  const state = fixture();
  state.env.VERCEL = undefined;
  state.env.NODE_ENV = 'development';
  const csrf = await issueCsrf(state);
  const result = responseMock();
  await state.handlers.login({
    ...csrfRequest(state, csrf.token),
    headers: {
      ...csrfRequest(state, csrf.token).headers,
      cookie: `bb_csrf=${encodeURIComponent(csrf.token)}`,
    },
    body: { email: 'a@example.test', password },
  }, result.response);
  assert.equal(result.statusCode, 200);
  assert.ok(result.headers.get('set-cookie').every(cookie => /^bb_(?:access|refresh)=/u.test(cookie)));
  assert.ok(result.headers.get('set-cookie').every(cookie => !/; Secure;/u.test(cookie)));

  const logoutResult = responseMock();
  await state.handlers.logout({
    method: 'POST',
    headers: {
      origin: state.env.APP_ORIGIN,
      'sec-fetch-site': 'same-origin',
      'x-csrf-token': csrf.token,
      cookie: `bb_csrf=${encodeURIComponent(csrf.token)}; bb_access=${accessTokenOne}; bb_refresh=${refreshTokenOne}`,
    },
  }, logoutResult.response);
  assert.equal(logoutResult.statusCode, 200);
  assert.deepEqual(logoutResult.headers.get('set-cookie').map(cookie => cookie.split('=')[0]), [
    'bb_access',
    'bb_refresh',
    'bb_csrf',
  ]);
  assert.ok(logoutResult.headers.get('set-cookie').every(cookie =>
    /; Path=\/; HttpOnly; SameSite=Strict; Max-Age=0;/u.test(cookie)));
});

test('Vercel routes and the server-backed browser Auth contract are wired', async () => {
  const [csrfRoute, loginRoute, sessionRoute, refreshRoute, logoutRoute, notesApi, browserAuth, authController] =
    await Promise.all([
      readFile(new URL('../api/auth/csrf.js', import.meta.url), 'utf8'),
      readFile(new URL('../api/auth/login.js', import.meta.url), 'utf8'),
      readFile(new URL('../api/auth/session.js', import.meta.url), 'utf8'),
      readFile(new URL('../api/auth/refresh.js', import.meta.url), 'utf8'),
      readFile(new URL('../api/auth/logout.js', import.meta.url), 'utf8'),
      readFile(new URL('../api/notes.js', import.meta.url), 'utf8'),
      readFile(new URL('../src/auth-browser.mjs', import.meta.url), 'utf8'),
      readFile(new URL('../src/auth-controller.mjs', import.meta.url), 'utf8'),
    ]);
  for (const route of [csrfRoute, loginRoute, sessionRoute, refreshRoute, logoutRoute]) {
    assert.match(route, /createAuthHandlers\(\)/u);
    assert.match(route, /export default/u);
  }
  assert.match(notesApi, /request\.headers\?\.authorization/u);
  assert.match(browserAuth, /controller = createAuthController\(render\)/u);
  assert.match(authController, /\/api\/auth\/login/u);
  assert.match(authController, /\/api\/auth\/session/u);
  assert.match(authController, /\/api\/auth\/refresh/u);
  assert.match(authController, /\/api\/auth\/logout/u);
  assert.doesNotMatch(`${browserAuth}\n${authController}`, /window\.supabase|signInWithPassword|auth\.signOut|auth\.getSession|Authorization/u);
});
