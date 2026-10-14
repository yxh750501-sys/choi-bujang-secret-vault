import config from '../aleph.config.json' with { type: 'json' };
import { readAccessTokenCookie } from '../src/server-session.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import {
  createInitialTestRecoveryState,
  getVerifiedBackups,
  previewTestRecovery,
  readTestBackups,
  restoreVerifiedTestRecovery,
} from '../test/helpers/stage10-recovery.mjs';

const MAX_BODY_BYTES = 8192;
const MAX_RUNS = 32;
const RUN_TTL_MS = 15 * 60 * 1000;

function json(response, status, body) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(body);
}

function requestBody(request) {
  const contentType = request.headers?.['content-type'] ?? request.headers?.['Content-Type'];
  if (typeof contentType !== 'string'
      || !/^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(contentType)) return null;
  let body = request.body;
  if (typeof body === 'string') {
    if (Buffer.byteLength(body, 'utf8') > MAX_BODY_BYTES) return null;
    try {
      body = JSON.parse(body);
    } catch {
      return null;
    }
  } else if (body !== undefined) {
    try {
      if (Buffer.byteLength(JSON.stringify(body), 'utf8') > MAX_BODY_BYTES) return null;
    } catch {
      return null;
    }
  }
  if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).sort().join(',') !== 'action,noteId'
      || !['preview', 'restore'].includes(body.action)
      || typeof body.noteId !== 'string') return null;
  return body;
}

function errorCode(error) {
  return typeof error?.message === 'string'
    && /^[A-Z][A-Z0-9_]{0,63}$/u.test(error.message)
    ? error.message
    : 'RESTORE_FAILED';
}

function pruneRuns(runs, now) {
  for (const [runId, entry] of runs) {
    if (now - entry.lastUsedAt > RUN_TTL_MS) runs.delete(runId);
  }
}

export function createRestoreHandler({
  verifyAuthorization,
  readBackups = readTestBackups,
  runs = new Map(),
  now = Date.now,
} = {}) {
  if (typeof verifyAuthorization !== 'function') {
    throw new TypeError('restore_authorization_verifier_required');
  }

  return async function restoreHandler(request, response) {
    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      return json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
    }

    const authorization = request.headers?.authorization ?? request.headers?.Authorization;
    const cookie = readAccessTokenCookie(request);
    if (typeof authorization !== 'string' || !/^Bearer\s+\S+$/iu.test(authorization)
        || cookie.sessionPresent) {
      return json(response, 401, { error: 'AUTHENTICATION_REQUIRED' });
    }

    let identity;
    try {
      identity = await verifyAuthorization(authorization);
    } catch {
      return json(response, 503, { error: 'AUTHENTICATION_UNAVAILABLE' });
    }
    if (!identity || identity.kind !== 'judge' || identity.identity !== 'b'
        || typeof identity.userId !== 'string' || typeof identity.runId !== 'string') {
      return json(response, identity ? 403 : 401, {
        error: identity ? 'JUDGE_B_REQUIRED' : 'AUTHENTICATION_REQUIRED',
      });
    }

    const body = requestBody(request);
    if (!body) return json(response, 400, { error: 'INVALID_RESTORE_REQUEST' });

    try {
      const backups = await readBackups();
      const verified = getVerifiedBackups(backups);
      pruneRuns(runs, now());
      const entry = runs.get(identity.runId);
      const currentState = entry?.state ?? createInitialTestRecoveryState();
      const preview = previewTestRecovery(currentState, backups, body.noteId);

      if (body.action === 'preview') {
        return json(response, 200, {
          action: 'preview',
          policyVersion: preview.policyVersion,
          policyChanges: preview.policyChanges,
          memo: preview.memo,
          persistence: 'serverless-memory-only',
        });
      }

      if (!entry && runs.size >= MAX_RUNS) {
        return json(response, 503, { error: 'RESTORE_CAPACITY_REACHED' });
      }

      const restored = restoreVerifiedTestRecovery(currentState, backups, body.noteId);
      const rereadBackups = await readBackups();
      const rereadVerified = getVerifiedBackups(rereadBackups);
      if (verified.policy.sha256 !== rereadVerified.policy.sha256
          || verified.memo.fixtureSha256 !== rereadVerified.memo.fixtureSha256) {
        return json(response, 503, { error: 'BACKUP_CHANGED_DURING_RESTORE' });
      }

      const updatedAt = now();
      runs.set(identity.runId, { state: restored.state, lastUsedAt: updatedAt });
      return json(response, 200, {
        action: 'restore',
        restored: true,
        policyVersion: restored.preview.policyVersion,
        policyChanges: restored.preview.policyChanges,
        memo: restored.preview.memo,
        auditEntriesAdded: 2,
        persistence: 'serverless-memory-only',
      });
    } catch (error) {
      const code = errorCode(error);
      console.error('stage10_restore_rejected', { code });
      if (code === 'NOTE_ID_NOT_IN_BACKUP') {
        return json(response, 404, { error: code });
      }
      if (code === 'EXISTING_TARGET_OWNER_CONFLICTS') {
        return json(response, 409, { error: code });
      }
      if (code === 'POLICY_SERVICE_NOT_IN_BACKUP') {
        return json(response, 400, { error: code });
      }
      return json(response, 503, {
        error: code.startsWith('POLICY_BACKUP') || code.startsWith('NOTE_BACKUP')
          || code === 'BACKUP_MISSING'
          ? 'BACKUP_VERIFICATION_FAILED'
          : code,
      });
    }
  };
}

const noStudentClaims = {
  auth: {
    getClaims: async () => ({ data: { claims: null }, error: { code: 'NOT_STUDENT_TOKEN' } }),
  },
};
const verifyAuthorization = createLoginVerifier({
  config,
  supabaseClient: noStudentClaims,
});

export default createRestoreHandler({ verifyAuthorization });
