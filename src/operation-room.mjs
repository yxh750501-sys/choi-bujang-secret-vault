import { randomUUID } from 'node:crypto';
import { RULE_IDS } from './decider.mjs';
import fixture from '../test/fixtures/stage10-policy.json' with { type: 'json' };

// Only the three fixed, anonymous GET requests below are executed. The other
// entries describe tests that need a real identity, engine event, or write.
export const CHECKS = Object.freeze([
  ['s01_public_shell', 1, 'normal', 'GET /', 'HTTP 200'],
  ['s01_deployment', 1, 'normal', 'GET /aleph.json', 'HTTP 200, step 12 and current commit'],
  ['s02_anonymous_note', 2, 'forbidden', 'GET /api/notes/:id without login', 'HTTP 401 or 403'],
  ['s02_static_copy', 2, 'forbidden', 'GET /data.json', 'private notes absent'],
  ['s03_login', 3, 'normal', 'POST /api/auth login', 'verified session'],
  ['s03_anonymous_notes', 3, 'forbidden', 'GET /api/notes without login', 'HTTP 401 or 403'],
  ['s03_logout', 3, 'normal', 'POST /api/auth logout', 'session cleared'],
  ['s04_session', 4, 'normal', 'GET /api/auth with session', 'authenticated session'],
  ['s04_csrf', 4, 'forbidden', 'POST /api/notes without CSRF', 'HTTP 403'],
  ['s04_expired', 4, 'forbidden', 'GET /api/notes with expired session', 'HTTP 401'],
  ['s04_origin', 4, 'forbidden', 'POST /api/notes with wrong Origin', 'HTTP 403'],
  ['s05_own_list', 5, 'normal', 'GET /api/notes as owner', 'owner notes only'],
  ['s05_own_read', 5, 'normal', 'GET /api/notes/:id as owner', 'owner note only'],
  ['s05_cross_read', 5, 'forbidden', 'GET /api/notes/:id as other user', 'HTTP 404'],
  ['s05_cross_write', 5, 'forbidden', 'PUT /api/notes/:id as other user', 'HTTP 404'],
  ['s05_cross_delete', 5, 'forbidden', 'DELETE /api/notes/:id as other user', 'HTTP 404'],
  ['s06_approved_device', 6, 'normal', 'GET /api/notes with approved device', 'owner access'],
  ['s06_pending_device', 6, 'forbidden', 'GET /api/notes with pending device', 'access denied'],
  ['s06_revoked_device', 6, 'forbidden', 'GET /api/notes with revoked device', 'access denied'],
  ['s06_forged_device', 6, 'forbidden', 'GET /api/notes with forged device claim', 'access denied'],
  ['s07_normal_decision', 7, 'normal', 'decide normal request', 'allow'],
  ['s07_risk_step_up', 7, 'forbidden', 'decide composite risk', 'step_up'],
  ['s07_unverified_step_up', 7, 'forbidden', 'decide unverified step-up', 'step_up'],
  ['s08_note_route', 8, 'normal', 'GET /notes/:id', 'allow'],
  ['s08_query', 8, 'forbidden', 'GET /notes/:id?query', 'deny'],
  ['s08_write', 8, 'forbidden', 'PUT /notes/:id', 'deny'],
  ['s08_prefix', 8, 'forbidden', 'GET /notes/..', 'deny'],
  ['s08_unknown', 8, 'forbidden', 'GET /unknown', 'deny'],
  ['s09_below_threshold', 9, 'normal', 'detect normal reads', 'observe'],
  ['s09_over_threshold', 9, 'forbidden', 'detect excess reads', 'propose_revocation'],
  ['s09_mixed_subjects', 9, 'normal', 'detect separate subjects', 'separate counts'],
  ['s09_no_events', 9, 'normal', 'detect empty events', 'no revocation'],
  ['s10_restore_preview', 10, 'normal', 'POST /api/restore preview', 'verified preview'],
  ['s10_restore_apply', 10, 'normal', 'POST /api/restore restore', 'verified fixture only'],
  ['s10_wrong_owner', 10, 'forbidden', 'POST /api/restore as other user', 'access denied'],
  ['s10_missing_backup', 10, 'forbidden', 'POST /api/restore without backup', 'restore denied'],
  ['s11_pwa_shell', 11, 'normal', 'GET /manifest.webmanifest', 'public manifest'],
  ['s11_anonymous_device', 11, 'forbidden', 'GET /api/operations without login', 'HTTP 401'],
  ['s11_admin_forbidden', 11, 'forbidden', 'POST /api/device-approval as student', 'approval denied'],
  ['s11_offline_api', 11, 'forbidden', 'GET /api/notes offline', 'no protected cache'],
  ['s11_approved_open', 11, 'normal', 'GET /api/operations on approved device', 'HTTP 200'],
]);

const probes = Object.freeze([
  { id: 's01_deployment', path: '/aleph.json' },
  { id: 's02_anonymous_note', path: '/api/notes/00000000-0000-4000-8000-000000000001' },
  { id: 's03_anonymous_notes', path: '/api/notes' },
]);

function publicBase(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
      || url.pathname !== '/' || url.hostname.endsWith('.example')) {
    throw new Error('INVALID_PUBLIC_APP_URL');
  }
  return url;
}

export async function operationReport({ config, deviceStatus, fetchImpl = fetch,
  now = () => new Date(), requestIdFactory = randomUUID,
  deployedCommit = null } = {}) {
  const checks = CHECKS.map(([id, stage, kind, request, expected]) => ({
    id, stage, kind, request, expected, actual: null, requestId: null,
    requestIdSource: null, checkedAt: null, status: 'NOT_RUN',
  }));
  const base = publicBase(config.publicAppUrl);
  for (const probe of probes) {
    const id = requestIdFactory();
    let response;
    try {
      response = await fetchImpl(new URL(probe.path, base), {
        method: 'GET', redirect: 'error', credentials: 'omit',
        headers: { 'X-Request-Id': id }, signal: AbortSignal.timeout(5000),
      });
    } catch {
      continue; // No response evidence means NOT_RUN, including timeouts.
    }
    if (!Number.isInteger(response?.status) || response.status < 100 || response.status > 599) continue;
    let matched = response.status === 401 || response.status === 403;
    const actual = { httpStatus: response.status, body: 'response body redacted' };
    if (probe.id === 's01_deployment') {
      matched = false;
      try {
        const data = await response.json();
        const commit = deployedCommit ?? null;
        matched = response.status === 200 && data?.step === 12
          && (!commit || data.commit === commit);
        actual.step = Number.isInteger(data?.step) ? data.step : null;
        actual.commitMatched = commit ? data?.commit === commit : null;
      } catch {
        actual.step = null;
        actual.commitMatched = null;
      }
    }
    const check = checks.find(item => item.id === probe.id);
    check.actual = actual;
    check.requestId = id;
    check.requestIdSource = 'operations-correlation-id';
    check.checkedAt = now().toISOString();
    check.status = matched ? 'PASS' : 'FAIL';
  }
  const counts = {
    pass: checks.filter(item => item.status === 'PASS').length,
    fail: checks.filter(item => item.status === 'FAIL').length,
    notRun: checks.filter(item => item.status === 'NOT_RUN').length,
  };
  return {
    schema: 'aleph.operations.v1', checkedCommit: deployedCommit,
    generatedAt: now().toISOString(),
    sources: { student: ['src/decider.mjs', 'src/detect.mjs', 'api/notes.js',
      'public/manifest.webmanifest', 'src/operation-room.mjs'], engine: 'ALEPH SDP 엔진' },
    policy: { ruleIds: [...RULE_IDS], count: RULE_IDS.length, status: 'NOT_RUN' },
    detection: { status: 'NOT_RUN', eventCount: null },
    revocation: { status: 'NOT_RUN', completed: null },
    recovery: { version: fixture.version, status: 'NOT_RUN', source: 'student-fixture' },
    deviceApproval: { status: deviceStatus },
    verification: { counts, cases: checks },
  };
}
