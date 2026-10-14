import { createHash, randomBytes } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';

const DEVICE_COOKIE_MAX_AGE = 365 * 24 * 60 * 60;
const DEVICE_APPROVAL_TTL_MS = 30 * 24 * 60 * 60 * 1000;

function secureCookies(env) {
  return env.VERCEL === '1' || env.NODE_ENV === 'production';
}

function deviceCookieName(env) {
  return `${secureCookies(env) ? '__Host-' : ''}bb_device_ref`;
}

function cookieValues(request, name) {
  const header = request.headers?.cookie ?? request.headers?.Cookie;
  if (typeof header !== 'string') return [];
  return header.split(';').flatMap(part => {
    const separator = part.indexOf('=');
    if (separator < 1 || part.slice(0, separator).trim() !== name) return [];
    try {
      return [decodeURIComponent(part.slice(separator + 1).trim())];
    } catch {
      return [null];
    }
  });
}

export function readDeviceReference(request, env = process.env) {
  const values = cookieValues(request, deviceCookieName(env));
  if (values.length !== 1 || typeof values[0] !== 'string'
      || !/^[A-Za-z0-9_-]{43}$/u.test(values[0])) return null;
  return values[0];
}

export function hashDeviceReference(reference) {
  if (typeof reference !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(reference)) {
    throw new TypeError('invalid_device_reference');
  }
  return createHash('sha256').update(reference).digest('hex');
}

export function issueDeviceReference(request, response, {
  env = process.env,
  nonceFactory = randomBytes,
} = {}) {
  const existing = readDeviceReference(request, env);
  if (existing) return existing;
  if (cookieValues(request, deviceCookieName(env)).length > 0) return null;

  const reference = nonceFactory(32).toString('base64url');
  if (!/^[A-Za-z0-9_-]{43}$/u.test(reference)) throw new Error('invalid_device_reference_generator');
  const cookie = [
    `${deviceCookieName(env)}=${encodeURIComponent(reference)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Strict',
    ...(secureCookies(env) ? ['Secure'] : []),
    `Max-Age=${DEVICE_COOKIE_MAX_AGE}`,
  ].join('; ');
  const current = response.getHeader?.('Set-Cookie');
  const cookies = current === undefined ? [] : Array.isArray(current) ? current : [current];
  response.setHeader('Set-Cookie', [...cookies, cookie]);
  return reference;
}

function validIdentity(value) {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value);
}

export function createSupabaseDeviceApprovalStore({
  env = process.env,
  clientFactory = createClient,
  now = Date.now,
} = {}) {
  const url = env.SUPABASE_URL;
  const secretKey = env.SUPABASE_SECRET_KEY;
  if (typeof url !== 'string' || typeof secretKey !== 'string' || !secretKey.trim()) {
    throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
  }
  const client = clientFactory(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  if (typeof client?.from !== 'function') throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');

  return {
    async isAdmin(userId) {
      if (!validIdentity(userId)) throw new TypeError('invalid_device_approval_admin');
      const { data, error } = await client.from('device_approval_admins')
        .select('enabled')
        .eq('user_id', userId)
        .maybeSingle();
      if (error) throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
      return data?.enabled === true;
    },

    async listPending() {
      const { data, error } = await client.from('device_approvals')
        .select('user_id,device_ref,status,requested_at')
        .eq('status', 'pending')
        .order('requested_at', { ascending: true })
        .limit(100);
      if (error || !Array.isArray(data)) throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
      return data;
    },

    async get(userId, deviceRef) {
      if (!validIdentity(userId) || !/^[0-9a-f]{64}$/u.test(deviceRef)) {
        throw new TypeError('invalid_device_approval_lookup');
      }
      const { data, error } = await client.from('device_approvals')
        .select('user_id,device_ref,status,requested_at,approved_by,approved_at,approved_expires_at,rejected_at,revoked_at')
        .eq('user_id', userId)
        .eq('device_ref', deviceRef)
        .maybeSingle();
      if (error) throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
      if (data?.status === 'approved') {
        const expiration = typeof data.approved_expires_at === 'string'
          ? Date.parse(data.approved_expires_at)
          : Number.NaN;
        if (!Number.isFinite(expiration) || expiration <= now()) {
          if (Number.isFinite(expiration)) {
            const { data: expired, error: expirationError } = await client.from('device_approvals')
              .update({ status: 'expired', updated_by: 'system:expiry' })
              .eq('user_id', userId)
              .eq('device_ref', deviceRef)
              .eq('status', 'approved')
              .eq('approved_expires_at', data.approved_expires_at)
              .select('user_id,device_ref,status,requested_at,approved_by,approved_at,approved_expires_at,rejected_at,revoked_at')
              .maybeSingle();
            if (expirationError) throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
            return expired ?? { ...data, status: 'expired' };
          }
          return { ...data, status: 'expired' };
        }
      }
      return data;
    },

    async request(userId, deviceRef) {
      if (!validIdentity(userId) || !/^[0-9a-f]{64}$/u.test(deviceRef)) {
        throw new TypeError('invalid_device_approval_request');
      }
      const { data, error } = await client.rpc('request_device_approval', {
        p_user_id: userId,
        p_device_ref: deviceRef,
        p_actor: `user:${userId}`,
      });
      const record = Array.isArray(data) ? data[0] : data;
      if (error) throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
      if (record) return record;
      const current = await this.get(userId, deviceRef);
      if (current?.status === 'approved') return current;
      throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
    },

    async setStatus(userId, deviceRef, status, actor, expectedStatus) {
      if (!['approved', 'rejected', 'revoked'].includes(status)) {
        throw new TypeError('invalid_device_approval_status');
      }
      if (!['pending', 'approved'].includes(expectedStatus)) {
        throw new TypeError('invalid_device_approval_transition');
      }
      const now = new Date().toISOString();
      const approvedAt = Date.parse(now);
      const update = {
        status,
        approved_by: status === 'approved' ? actor : null,
        approved_at: status === 'approved' ? now : null,
        approved_expires_at: status === 'approved'
          ? new Date(approvedAt + DEVICE_APPROVAL_TTL_MS).toISOString()
          : null,
        rejected_at: status === 'rejected' ? now : null,
        revoked_at: status === 'revoked' ? now : null,
        updated_by: actor,
      };
      const { data, error } = await client.from('device_approvals')
        .update(update)
        .eq('user_id', userId)
        .eq('device_ref', deviceRef)
        .eq('status', expectedStatus)
        .select('user_id,device_ref,status,requested_at,approved_by,approved_at,approved_expires_at,rejected_at,revoked_at')
        .maybeSingle();
      if (error) throw new Error('DEVICE_APPROVAL_STORE_UNAVAILABLE');
      return data;
    },
  };
}
