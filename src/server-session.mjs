import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

const BODY_LIMIT = 8192;
const CSRF_TTL_SECONDS = 2 * 60 * 60;
const REFRESH_TTL_SECONDS = 30 * 24 * 60 * 60;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/u;

function json(response, status, body) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(body);
}

function appendSetCookie(response, cookies) {
  const existing = response.getHeader?.('Set-Cookie');
  const values = existing === undefined ? [] : Array.isArray(existing) ? existing : [existing];
  response.setHeader('Set-Cookie', [...values, ...cookies]);
}

function secureCookies(env) {
  return env.VERCEL === '1' || env.NODE_ENV === 'production';
}

function cookieNames(env) {
  const prefix = secureCookies(env) ? '__Host-' : '';
  return {
    access: `${prefix}bb_access`,
    refresh: `${prefix}bb_refresh`,
    csrf: `${prefix}bb_csrf`,
  };
}

function cookieOptions(env, maxAge) {
  return [
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    ...(secureCookies(env) ? ['Secure'] : []),
    `Max-Age=${maxAge}`,
  ].join('; ');
}

function serializeCookie(name, value, env, maxAge) {
  return `${name}=${encodeURIComponent(value)}; ${cookieOptions(env, maxAge)}`;
}

function clearCookies(env) {
  const names = cookieNames(env);
  const clear = name => `${name}=; ${cookieOptions(env, 0)}; Expires=Thu, 01 Jan 1970 00:00:00 GMT`;
  return [clear(names.access), clear(names.refresh), clear(names.csrf)];
}

function parseCookies(request) {
  const header = request.headers?.cookie ?? request.headers?.Cookie;
  const result = new Map();
  if (typeof header !== 'string') return result;
  for (const part of header.split(';')) {
    const separator = part.indexOf('=');
    if (separator < 1) continue;
    const name = part.slice(0, separator).trim();
    if (result.has(name)) {
      result.set(name, null);
      continue;
    }
    try {
      result.set(name, decodeURIComponent(part.slice(separator + 1).trim()));
    } catch {
      result.set(name, null);
    }
  }
  return result;
}

function requestOrigin(request) {
  return request.headers?.origin ?? request.headers?.Origin;
}

function configuredOrigin(env) {
  const value = env.APP_ORIGIN;
  if (typeof value !== 'string' || !value) throw new Error('missing_app_origin');
  const url = new URL(value);
  if (url.origin !== value || url.username || url.password
      || (secureCookies(env) && url.protocol !== 'https:')
      || (!secureCookies(env) && !['https:', 'http:'].includes(url.protocol))) {
    throw new Error('invalid_app_origin');
  }
  return url.origin;
}

function originAllowed(request, env) {
  let origin;
  try {
    origin = requestOrigin(request);
    if (typeof origin !== 'string' || origin !== configuredOrigin(env)) return false;
  } catch {
    return false;
  }
  const fetchSite = request.headers?.['sec-fetch-site'] ?? request.headers?.['Sec-Fetch-Site'];
  return fetchSite === undefined || fetchSite === 'same-origin';
}

function requestBody(request) {
  const contentType = request.headers?.['content-type'] ?? request.headers?.['Content-Type'];
  if (typeof contentType !== 'string' || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) {
    return { error: 'INVALID_CONTENT_TYPE' };
  }
  const contentLength = request.headers?.['content-length'] ?? request.headers?.['Content-Length'];
  if (contentLength !== undefined && (!/^\d+$/u.test(String(contentLength))
      || Number(contentLength) > BODY_LIMIT)) return { error: 'REQUEST_TOO_LARGE' };

  let body = request.body;
  if (typeof body === 'string') {
    if (Buffer.byteLength(body, 'utf8') > BODY_LIMIT) return { error: 'REQUEST_TOO_LARGE' };
    try {
      body = JSON.parse(body);
    } catch {
      return { error: 'INVALID_JSON' };
    }
  } else if (body !== undefined) {
    try {
      if (Buffer.byteLength(JSON.stringify(body), 'utf8') > BODY_LIMIT) return { error: 'REQUEST_TOO_LARGE' };
    } catch {
      return { error: 'INVALID_JSON' };
    }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'INVALID_JSON' };
  return { body };
}

function authConfiguration(env) {
  const urlValue = env.SUPABASE_URL;
  const publishableKey = env.SUPABASE_PUBLISHABLE_KEY;
  if (typeof urlValue !== 'string' || typeof publishableKey !== 'string'
      || !publishableKey.trim() || publishableKey !== publishableKey.trim()) return null;
  try {
    const url = new URL(urlValue);
    if (url.protocol !== 'https:' || url.username || url.password || url.port
        || url.pathname !== '/' || url.search || url.hash) return null;
    return { url: url.origin, publishableKey };
  } catch {
    return null;
  }
}

function makeClient(env, clientFactory) {
  const configuration = authConfiguration(env);
  if (!configuration) return null;
  try {
    return clientFactory(configuration.url, configuration.publishableKey, {
      auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    });
  } catch {
    return null;
  }
}

function safeUser(user) {
  if (typeof user?.id !== 'string' || !user.id) return null;
  return {
    id: user.id,
    email: typeof user.email === 'string' ? user.email : null,
  };
}

function csrfSignature(payload, secret) {
  return createHmac('sha256', secret).update(payload).digest('base64url');
}

function equalText(left, right) {
  const leftBuffer = Buffer.from(left);
  const rightBuffer = Buffer.from(right);
  return leftBuffer.length === rightBuffer.length && timingSafeEqual(leftBuffer, rightBuffer);
}

function csrfSecret(env) {
  const value = env.CSRF_SECRET;
  return typeof value === 'string' && Buffer.byteLength(value, 'utf8') >= 32 ? value : null;
}

function createCsrfToken(secret, now, nonceFactory) {
  const payload = `${Math.floor(now() / 1000) + CSRF_TTL_SECONDS}.${nonceFactory(32).toString('base64url')}`;
  return `${payload}.${csrfSignature(payload, secret)}`;
}

function validCsrfToken(token, secret, now) {
  if (typeof token !== 'string' || token.length > 256) return false;
  const parts = token.split('.');
  if (parts.length !== 3 || !/^\d{10,12}$/u.test(parts[0])
      || !/^[A-Za-z0-9_-]{32,64}$/u.test(parts[1])
      || !/^[A-Za-z0-9_-]{43}$/u.test(parts[2])) return false;
  const expiresAt = Number(parts[0]);
  if (!Number.isSafeInteger(expiresAt)
      || expiresAt <= Math.floor(now() / 1000)
      || expiresAt > Math.floor(now() / 1000) + CSRF_TTL_SECONDS) return false;
  const payload = `${parts[0]}.${parts[1]}`;
  return equalText(parts[2], csrfSignature(payload, secret));
}

function csrfAllowed(request, env, now) {
  if (!originAllowed(request, env)) return false;
  const secret = csrfSecret(env);
  if (!secret) return false;
  const names = cookieNames(env);
  const cookieToken = parseCookies(request).get(names.csrf);
  const headerToken = request.headers?.['x-csrf-token'] ?? request.headers?.['X-CSRF-Token'];
  return typeof cookieToken === 'string' && typeof headerToken === 'string'
    && equalText(cookieToken, headerToken)
    && validCsrfToken(cookieToken, secret, now);
}

export function readAccessTokenCookie(request, env = process.env) {
  const names = cookieNames(env);
  const cookies = parseCookies(request);
  return {
    present: cookies.has(names.access),
    sessionPresent: cookies.has(names.access) || cookies.has(names.refresh),
    token: cookies.get(names.access) ?? null,
  };
}

export function verifyCsrfRequest(request, { env = process.env, now = Date.now } = {}) {
  return csrfAllowed(request, env, now);
}

function sessionCookies(session, env, now) {
  if (typeof session?.access_token !== 'string' || !session.access_token
      || typeof session.refresh_token !== 'string' || !session.refresh_token) return null;
  const expiresAt = Number.isSafeInteger(session.expires_at)
    ? session.expires_at
    : Math.floor(now() / 1000) + (Number.isSafeInteger(session.expires_in) ? session.expires_in : 3600);
  const accessMaxAge = Math.max(1, Math.min(3600, expiresAt - Math.floor(now() / 1000)));
  const names = cookieNames(env);
  return [
    serializeCookie(names.access, session.access_token, env, accessMaxAge),
    serializeCookie(names.refresh, session.refresh_token, env, REFRESH_TTL_SECONDS),
  ];
}

function methodNotAllowed(response, allowed) {
  response.setHeader('Allow', allowed.join(', '));
  return json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
}

function requireCsrf(request, response, env, now) {
  if (!originAllowed(request, env)) {
    json(response, 403, { error: 'ORIGIN_NOT_ALLOWED' });
    return false;
  }
  if (!csrfSecret(env)) {
    json(response, 503, { error: 'AUTH_UNAVAILABLE' });
    return false;
  }
  if (!csrfAllowed(request, env, now)) {
    json(response, 403, { error: 'CSRF_VALIDATION_FAILED' });
    return false;
  }
  return true;
}

function operationFailed(response, status, error) {
  return json(response, status, { error });
}

export function createAuthHandlers({
  env = process.env,
  clientFactory = createClient,
  now = Date.now,
  nonceFactory = randomBytes,
} = {}) {
  const csrf = async (request, response) => {
    if (request.method !== 'GET') return methodNotAllowed(response, ['GET']);
    let names;
    try {
      names = cookieNames(env);
      configuredOrigin(env);
    } catch {
      return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
    }
    const secret = csrfSecret(env);
    if (!secret) return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
    const token = createCsrfToken(secret, now, nonceFactory);
    appendSetCookie(response, [serializeCookie(names.csrf, token, env, CSRF_TTL_SECONDS)]);
    return json(response, 200, { csrfToken: token });
  };

  const login = async (request, response) => {
    if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
    if (!requireCsrf(request, response, env, now)) return;
    const parsed = requestBody(request);
    if (parsed.error) return operationFailed(response, parsed.error === 'REQUEST_TOO_LARGE' ? 413 : 400, parsed.error);
    const email = typeof parsed.body.email === 'string' ? parsed.body.email.trim() : '';
    const password = parsed.body.password;
    if (!EMAIL_PATTERN.test(email) || email.length > 320
        || typeof password !== 'string' || !password || password.length > 1024
        || /[\u0000-\u001f\u007f]/u.test(email)) {
      return operationFailed(response, 400, 'INVALID_CREDENTIALS_FORMAT');
    }
    const client = makeClient(env, clientFactory);
    if (!client) return operationFailed(response, 503, 'AUTH_UNAVAILABLE');

    try {
      const { data, error } = await client.auth.signInWithPassword({ email, password });
      if (error || !data?.session) return operationFailed(response, 401, 'AUTHENTICATION_FAILED');
      const user = safeUser(data.session.user);
      const cookies = sessionCookies(data.session, env, now);
      if (!user || !cookies) return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
      appendSetCookie(response, cookies);
      return json(response, 200, { authenticated: true, user });
    } catch {
      return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
    }
  };

  const session = async (request, response) => {
    if (request.method !== 'GET') return methodNotAllowed(response, ['GET']);
    const names = cookieNames(env);
    const accessToken = parseCookies(request).get(names.access);
    if (!accessToken) return operationFailed(response, 401, 'AUTHENTICATION_REQUIRED');
    const client = makeClient(env, clientFactory);
    if (!client) return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
    try {
      const { data, error } = await client.auth.getUser(accessToken);
      if (Number.isInteger(error?.status) && error.status >= 500) {
        return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
      }
      const user = error ? null : safeUser(data?.user);
      if (!user) {
        appendSetCookie(response, clearCookies(env));
        return operationFailed(response, 401, 'AUTHENTICATION_REQUIRED');
      }
      return json(response, 200, { authenticated: true, user });
    } catch {
      return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
    }
  };

  const refresh = async (request, response) => {
    if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
    if (!requireCsrf(request, response, env, now)) return;
    const names = cookieNames(env);
    const refreshToken = parseCookies(request).get(names.refresh);
    const client = makeClient(env, clientFactory);
    if (!client) return operationFailed(response, 503, 'AUTH_UNAVAILABLE');
    if (!refreshToken) {
      appendSetCookie(response, clearCookies(env));
      return operationFailed(response, 401, 'AUTHENTICATION_REQUIRED');
    }
    try {
      const { data, error } = await client.auth.refreshSession({ refresh_token: refreshToken });
      const nextSession = data?.session;
      const user = error ? null : safeUser(nextSession?.user);
      const cookies = user ? sessionCookies(nextSession, env, now) : null;
      if (!user || !cookies) {
        appendSetCookie(response, clearCookies(env));
        return operationFailed(response, 401, 'SESSION_REFRESH_FAILED');
      }
      appendSetCookie(response, cookies);
      return json(response, 200, { authenticated: true, user });
    } catch {
      appendSetCookie(response, clearCookies(env));
      return operationFailed(response, 401, 'SESSION_REFRESH_FAILED');
    }
  };

  const logout = async (request, response) => {
    if (request.method !== 'POST') return methodNotAllowed(response, ['POST']);
    if (!requireCsrf(request, response, env, now)) return;
    const names = cookieNames(env);
    const cookies = parseCookies(request);
    const accessToken = cookies.get(names.access);
    const refreshToken = cookies.get(names.refresh);
    const client = makeClient(env, clientFactory);
    appendSetCookie(response, clearCookies(env));
    let serverSessionRevoked = false;
    if (client && accessToken && refreshToken) {
      try {
        const { error: sessionError } = await client.auth.setSession({
          access_token: accessToken,
          refresh_token: refreshToken,
        });
        if (!sessionError) {
          const { error } = await client.auth.signOut({ scope: 'global' });
          serverSessionRevoked = !error;
        }
      } catch {
        serverSessionRevoked = false;
      }
    }
    return json(response, 200, { authenticated: false, serverSessionRevoked });
  };

  return { csrf, login, session, refresh, logout };
}
