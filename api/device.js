import config from '../aleph.config.json' with { type: 'json' };
import { operationReport } from '../src/operation-room.mjs';
import {
  createSupabaseDeviceApprovalStore,
  hashDeviceReference,
  issueDeviceReference,
  readDeviceReference,
} from '../src/device-approval.mjs';
import { readAccessTokenCookie, verifyCsrfRequest } from '../src/server-session.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const BODY_LIMIT = 8192;
const ALLOWED_ACTIONS = new Set(['request', 'revoke']);

function jsonError(response, status, error) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json({ error });
}

function parseBody(request) {
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
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'INVALID_JSON' };
  try {
    if (Buffer.byteLength(JSON.stringify(body), 'utf8') > BODY_LIMIT) return { error: 'REQUEST_TOO_LARGE' };
  } catch {
    return { error: 'INVALID_JSON' };
  }
  return { body };
}

function statusResponse(record) {
  return {
    status: record?.status ?? 'unregistered',
    approved: record?.status === 'approved',
    pending: record?.status === 'pending',
  };
}

export function createDeviceHandler({
  env = process.env,
  verifierFactory = createLoginVerifier,
  storeFactory = createSupabaseDeviceApprovalStore,
  nonceFactory,
} = {}) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    if (!['GET', 'POST'].includes(request.method)) {
      response.setHeader('Allow', 'GET, POST');
      return jsonError(response, 405, 'METHOD_NOT_ALLOWED');
    }
    if (request.method === 'POST' && !verifyCsrfRequest(request, { env })) {
      return jsonError(response, 403, 'CSRF_VALIDATION_FAILED');
    }

    const accessCookie = readAccessTokenCookie(request, env);
    if (!accessCookie.present || typeof accessCookie.token !== 'string' || !accessCookie.token) {
      return jsonError(response, 401, 'AUTHENTICATION_REQUIRED');
    }
    let identity;
    try {
      identity = await verifierFactory({
        config,
        supabaseSecretKey: env.SUPABASE_SECRET_KEY,
      })(`Bearer ${accessCookie.token}`);
    } catch {
      return jsonError(response, 503, 'AUTHENTICATION_UNAVAILABLE');
    }
    if (!identity || identity.kind !== 'student' || typeof identity.userId !== 'string') {
      return jsonError(response, 401, 'AUTHENTICATION_REQUIRED');
    }

    let body;
    if (request.method === 'POST') {
      const parsed = parseBody(request);
      if (parsed.error) {
        return jsonError(response, parsed.error === 'REQUEST_TOO_LARGE' ? 413 : 400, parsed.error);
      }
      body = parsed.body;
      if (body.action === 'approve' || body.action === 'reject') {
        return jsonError(response, 403, 'DEVICE_APPROVAL_FORBIDDEN');
      }
      if (Object.keys(body).length !== 1 || !ALLOWED_ACTIONS.has(body.action)) {
        return jsonError(response, 400, 'INVALID_DEVICE_ACTION');
      }
    }

    let deviceRef;
    if (request.method === 'GET') {
      try {
        deviceRef = issueDeviceReference(request, response, { env, nonceFactory });
      } catch {
        return jsonError(response, 503, 'DEVICE_REFERENCE_UNAVAILABLE');
      }
    } else {
      deviceRef = readDeviceReference(request, env);
    }
    if (!deviceRef) return jsonError(response, 400, 'DEVICE_REFERENCE_REQUIRED');

    let record;
    try {
      const store = storeFactory({ env });
      const deviceRefHash = hashDeviceReference(deviceRef);
      if (request.method === 'GET') {
        record = await store.get(identity.userId, deviceRefHash);
        if (request.query?.view === 'operation') {
          return response.status(200).json(operationReport(record?.status ?? 'unregistered'));
        }
        return response.status(200).json(statusResponse(record));
      }
      if (body.action === 'request') {
        record = await store.request(identity.userId, deviceRefHash);
        return response.status(200).json(statusResponse(record));
      }
      if (body.action === 'revoke') {
        const current = await store.get(identity.userId, deviceRefHash);
        if (current?.status !== 'approved') return jsonError(response, 409, 'DEVICE_NOT_APPROVED');
        record = await store.setStatus(identity.userId, deviceRefHash, 'revoked', `user:${identity.userId}`, 'approved');
        if (!record) return jsonError(response, 409, 'DEVICE_STATUS_CHANGED');
        return response.status(200).json(statusResponse(record));
      }

      return jsonError(response, 400, 'INVALID_DEVICE_ACTION');
    } catch {
      return jsonError(response, 503, 'DEVICE_APPROVAL_STORE_UNAVAILABLE');
    }
  };
}

export function createDeviceApprovalAdminHandler({
  env = process.env,
  verifierFactory = createLoginVerifier,
  storeFactory = createSupabaseDeviceApprovalStore,
} = {}) {
  return async function handler(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    if (!['GET', 'POST'].includes(request.method)) {
      response.setHeader('Allow', 'GET, POST');
      return jsonError(response, 405, 'METHOD_NOT_ALLOWED');
    }
    if (request.method === 'POST' && !verifyCsrfRequest(request, { env })) {
      return jsonError(response, 403, 'CSRF_VALIDATION_FAILED');
    }

    const accessCookie = readAccessTokenCookie(request, env);
    if (!accessCookie.present || typeof accessCookie.token !== 'string' || !accessCookie.token) {
      return jsonError(response, 401, 'AUTHENTICATION_REQUIRED');
    }
    let identity;
    try {
      identity = await verifierFactory({
        config,
        supabaseSecretKey: env.SUPABASE_SECRET_KEY,
      })(`Bearer ${accessCookie.token}`);
    } catch {
      return jsonError(response, 503, 'AUTHENTICATION_UNAVAILABLE');
    }
    if (!identity || identity.kind !== 'student' || typeof identity.userId !== 'string') {
      return jsonError(response, 401, 'AUTHENTICATION_REQUIRED');
    }

    let body;
    if (request.method === 'POST') {
      const parsed = parseBody(request);
      if (parsed.error) {
        return jsonError(response, parsed.error === 'REQUEST_TOO_LARGE' ? 413 : 400, parsed.error);
      }
      body = parsed.body;
      if (Object.keys(body).length !== 3
          || !['approve', 'reject'].includes(body.action)
          || typeof body.userId !== 'string'
          || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(body.userId)
          || typeof body.deviceRef !== 'string'
          || !/^[0-9a-f]{64}$/u.test(body.deviceRef)) {
        return jsonError(response, 400, 'INVALID_DEVICE_APPROVAL_REQUEST');
      }
      if (body.userId === identity.userId) {
        return jsonError(response, 403, 'SELF_DEVICE_APPROVAL_FORBIDDEN');
      }
    }

    try {
      const store = storeFactory({ env });
      if (!await store.isAdmin(identity.userId)) {
        return jsonError(response, 403, 'DEVICE_APPROVAL_ADMIN_REQUIRED');
      }
      if (request.method === 'GET') {
        const requests = await store.listPending();
        return response.status(200).json({
          requests: requests.map(item => ({
            userId: item.user_id,
            deviceRef: item.device_ref,
            requestedAt: item.requested_at,
          })),
        });
      }

      const current = await store.get(body.userId, body.deviceRef);
      if (current?.status !== 'pending') return jsonError(response, 409, 'DEVICE_NOT_PENDING');
      const status = body.action === 'approve' ? 'approved' : 'rejected';
      const updated = await store.setStatus(
        body.userId,
        body.deviceRef,
        status,
        identity.userId,
        'pending',
      );
      if (!updated) return jsonError(response, 409, 'DEVICE_STATUS_CHANGED');
      return response.status(200).json({
        status: updated.status,
        userId: updated.user_id,
        deviceRef: updated.device_ref,
        approvedBy: updated.approved_by ?? null,
        approvedAt: updated.approved_at ?? null,
        approvedExpiresAt: updated.approved_expires_at ?? null,
      });
    } catch {
      return jsonError(response, 503, 'DEVICE_APPROVAL_STORE_UNAVAILABLE');
    }
  };
}

export default createDeviceHandler();
