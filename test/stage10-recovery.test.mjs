import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { resolve } from 'node:path';
import {
  createInitialTestRecoveryState,
  getVerifiedBackups,
  previewTestPolicyRestore,
  readTestBackups,
  runPostRestoreRetests,
  restoreTestMemo,
  restoreTestPolicy,
  restoreVerifiedTestRecovery,
  sha256,
  verifyNoteBackup,
  verifyPolicyBackup,
} from './helpers/stage10-recovery.mjs';
import { createRestoreHandler, default as restoreRoute } from '../api/restore.js';
import { decide } from '../src/decider.mjs';

const root = resolve(import.meta.dirname, '..');
const policyBackup = JSON.parse(await readFile(
  new URL('./fixtures/stage10-policy.json', import.meta.url), 'utf8'));
const noteBackup = JSON.parse(await readFile(
  new URL('./fixtures/stage10-note.json', import.meta.url), 'utf8'));
const targetNoteId = '623e4567-e89b-42d3-a456-000000000001';
const targetOwnerId = '723e4567-e89b-42d3-a456-000000000001';

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

function policyState() {
  return {
    policies: {
      notes: {
        ownerIsolation: false,
        registeredDeviceRequired: false,
        riskStepUpRequired: false,
        resourceBoundary: 'all-notes',
        localOnlyGuard: 'preserve-me',
      },
      announcements: { access: 'read-only', audit: true },
      billing: { access: 'deny', audit: true },
    },
    audit: [{ action: 'prior_event', sequence: 1 }],
  };
}

function memoState() {
  return {
    notes: [
      {
        id: '823e4567-e89b-42d3-a456-000000000001',
        ownerId: '923e4567-e89b-42d3-a456-000000000001',
        title: 'other fixture note',
        body: 'independent synthetic note',
        contentSha256: sha256('independent synthetic note'),
      },
    ],
    audit: [{ action: 'prior_event', sequence: 1 }],
  };
}

test('generated policy and memo fixtures verify exact version, scope, owner and content hash', () => {
  const policy = verifyPolicyBackup(policyBackup);
  const note = verifyNoteBackup(noteBackup);
  assert.equal(policy.version, 'stage10-safe-policy-fixture-v1');
  assert.equal(policy.service, 'notes');
  assert.equal(policy.historicalBackup, false);
  assert.equal(note.id, targetNoteId);
  assert.equal(note.ownerId, targetOwnerId);
  assert.equal(note.contentSha256, sha256(noteBackup.note.body));
  assert.equal(note.historicalBackup, false);
});

test('missing, wrong-version and altered backup fixtures fail closed', () => {
  assert.throws(() => verifyPolicyBackup(null), /POLICY_BACKUP_MISSING/u);
  assert.throws(() => verifyPolicyBackup({ ...policyBackup, version: 'unknown' }),
    /POLICY_BACKUP_VERSION_OR_SCOPE_INVALID/u);
  assert.throws(() => verifyPolicyBackup({
    ...policyBackup,
    policies: {
      ...policyBackup.policies,
      notes: { ...policyBackup.policies.notes, ownerIsolation: false },
    },
  }), /POLICY_BACKUP_INTEGRITY_FAILED/u);
  assert.throws(() => verifyNoteBackup(null), /NOTE_BACKUP_MISSING/u);
  assert.throws(() => verifyNoteBackup({ ...noteBackup, version: 'unknown' }),
    /NOTE_BACKUP_VERSION_SCOPE_OR_CONTENT_INVALID/u);
  assert.throws(() => verifyNoteBackup({
    ...noteBackup,
    note: { ...noteBackup.note, body: 'altered fixture content' },
  }), /NOTE_BACKUP_VERSION_SCOPE_OR_CONTENT_INVALID/u);
});

test('policy dry-run previews only selected service changes without exposing note content', () => {
  const state = policyState();
  const preview = previewTestPolicyRestore(state.policies, policyBackup);
  assert.equal(preview.version, policyBackup.version);
  assert.equal(preview.service, 'notes');
  assert.deepEqual(preview.changes.map(change => change.field), [
    'ownerIsolation',
    'registeredDeviceRequired',
    'resourceBoundary',
    'riskStepUpRequired',
  ]);
  assert.deepEqual(preview.unchangedServices, ['announcements', 'billing']);
  assert.equal(JSON.stringify(preview).includes(noteBackup.note.body), false);
  assert.equal(state.policies.notes.ownerIsolation, false, 'dry-run must not mutate state');
  assert.throws(() => previewTestPolicyRestore(state.policies, policyBackup, 'billing'),
    /POLICY_SERVICE_NOT_IN_BACKUP/u);
});

test('policy restore changes only notes, re-verifies state and preserves prior audit history', () => {
  const state = policyState();
  const next = restoreTestPolicy(state, policyBackup);
  assert.deepEqual(Object.fromEntries(Object.keys(policyBackup.policies.notes)
    .map(field => [field, next.policies.notes[field]])), policyBackup.policies.notes);
  assert.deepEqual(next.policies.announcements, state.policies.announcements);
  assert.deepEqual(next.policies.billing, state.policies.billing);
  assert.equal(next.policies.notes.localOnlyGuard, 'preserve-me');
  assert.deepEqual(next.audit[0], state.audit[0]);
  assert.equal(next.audit[1].version, policyBackup.version);
  assert.equal(next.audit[1].outcome, 'restored');
  assert.deepEqual(state.policies.notes, {
    ownerIsolation: false,
    registeredDeviceRequired: false,
    riskStepUpRequired: false,
    resourceBoundary: 'all-notes',
    localOnlyGuard: 'preserve-me',
  });
});

test('single memo restore verifies ID, owner and content hash and leaves every other note unchanged', () => {
  const state = memoState();
  const next = restoreTestMemo(state, noteBackup, targetNoteId);
  const restored = next.notes.find(note => note.id === targetNoteId);
  assert.equal(restored.id, targetNoteId);
  assert.equal(restored.ownerId, targetOwnerId);
  assert.equal(sha256(restored.body), noteBackup.note.contentSha256);
  assert.deepEqual(next.notes.filter(note => note.id !== targetNoteId), state.notes);
  assert.deepEqual(next.audit[0], state.audit[0]);
  assert.equal(next.audit[1].id, targetNoteId);
  assert.equal(next.audit[1].ownerId, targetOwnerId);
  assert.equal(next.audit[1].contentSha256, noteBackup.note.contentSha256);
  assert.equal(Object.hasOwn(next.audit[1], 'body'), false);
  assert.equal(JSON.stringify(next.audit).includes(noteBackup.note.body), false);
});

test('unknown IDs, untrusted owners, altered hashes and conflicting rows are rejected without mutation', () => {
  const state = memoState();
  const original = structuredClone(state);
  assert.throws(() => restoreTestMemo(state, noteBackup, 'not-in-backup'),
    /NOTE_ID_NOT_IN_BACKUP/u);
  assert.deepEqual(state, original);
  assert.throws(() => verifyNoteBackup({
    ...noteBackup,
    note: { ...noteBackup.note, ownerId: 'a23e4567-e89b-42d3-a456-000000000001' },
  }), /NOTE_BACKUP_VERSION_SCOPE_OR_CONTENT_INVALID/u);
  assert.throws(() => restoreTestMemo({
    ...state,
    notes: [...state.notes, {
      id: targetNoteId,
      ownerId: 'a23e4567-e89b-42d3-a456-000000000001',
      body: 'conflicting row',
      contentSha256: sha256('conflicting row'),
    }],
  }, noteBackup, targetNoteId), /EXISTING_TARGET_OWNER_CONFLICTS/u);
  assert.deepEqual(state, original);
});

test('same-owner tampering is repaired while other memo and audit entries stay unchanged', () => {
  const state = memoState();
  state.notes.push({
    id: targetNoteId,
    ownerId: targetOwnerId,
    title: 'modified synthetic title',
    body: 'modified synthetic body',
    contentSha256: sha256('modified synthetic body'),
  });
  const previousAudit = structuredClone(state.audit);
  const next = restoreTestMemo(state, noteBackup, targetNoteId);
  const restored = next.notes.find(note => note.id === targetNoteId);
  assert.equal(restored.title, noteBackup.note.title);
  assert.equal(restored.ownerId, targetOwnerId);
  assert.equal(sha256(restored.body), noteBackup.note.contentSha256);
  assert.deepEqual(next.notes.filter(note => note.id !== targetNoteId), state.notes
    .filter(note => note.id !== targetNoteId));
  assert.deepEqual(next.audit.slice(0, previousAudit.length), previousAudit);
});

test('repeated memo and policy restores are data-idempotent and append-only in audit', () => {
  const memoOnce = restoreTestMemo(memoState(), noteBackup, targetNoteId);
  const memoTwice = restoreTestMemo(memoOnce, noteBackup, targetNoteId);
  assert.equal(memoTwice.notes.length, memoOnce.notes.length);
  assert.deepEqual(memoTwice.notes, memoOnce.notes);
  assert.equal(memoTwice.audit.length, memoOnce.audit.length + 1);
  assert.equal(memoTwice.audit.at(-1).outcome, 'already_safe');

  const policyOnce = restoreTestPolicy(policyState(), policyBackup);
  const policyTwice = restoreTestPolicy(policyOnce, policyBackup);
  assert.deepEqual(policyTwice.policies, policyOnce.policies);
  assert.equal(policyTwice.audit.length, policyOnce.audit.length + 1);
  assert.equal(policyTwice.audit.at(-1).outcome, 'already_safe');
});

test('configured POST route maps to a real handler and fixture reads are fresh', async () => {
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
  const vercel = JSON.parse(await readFile(resolve(root, 'vercel.json'), 'utf8'));
  const [method, route] = config.restoreRoute.split(' ');
  assert.equal(method, 'POST');
  assert.equal(route, '/api/restore');
  assert.equal(typeof restoreRoute, 'function');
  assert.equal(vercel.functions['api/restore.js'].includeFiles, 'test/fixtures/**');
  assert.deepEqual(config.allowedRoutes, ['GET /api/notes/:id']);

  let reads = 0;
  const backups = await readTestBackups(async (path) => {
    reads += 1;
    return readFile(path, 'utf8');
  });
  assert.equal(reads, 2);
  assert.equal(getVerifiedBackups(backups).memo.id, targetNoteId);

  const unauthorized = mockResponse();
  await restoreRoute({
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: { action: 'restore', noteId: targetNoteId },
  }, unauthorized.response);
  assert.equal(unauthorized.statusCode, 401);
  const wrongMethod = mockResponse();
  await restoreRoute({ method: 'GET', headers: {} }, wrongMethod.response);
  assert.equal(wrongMethod.statusCode, 405);
});

test('restore POST requires a server-verified judge B identity and rejects forged role claims', async () => {
  const calls = [];
  const handler = createRestoreHandler({
    verifyAuthorization: async authorization => {
      calls.push(authorization);
      if (authorization === 'Bearer local-student') {
        return { kind: 'student', userId: targetOwnerId };
      }
      if (authorization === 'Bearer local-judge-a') {
        return { kind: 'judge', identity: 'a', userId: targetOwnerId, runId: 'run-a' };
      }
      if (authorization === 'Bearer local-judge-b') {
        return { kind: 'judge', identity: 'b', userId: targetOwnerId, runId: 'run-b' };
      }
      return null;
    },
  });
  const invoke = async ({ method = 'POST', authorization, body, headers = {} } = {}) => {
    const result = mockResponse();
    await handler({
      method,
      headers: {
        ...(authorization ? { authorization } : {}),
        'content-type': 'application/json',
        ...headers,
      },
      body,
    }, result.response);
    return result;
  };
  const missing = await invoke({ body: { action: 'restore', noteId: targetNoteId, role: 'admin' } });
  assert.equal(missing.statusCode, 401);
  const student = await invoke({
    authorization: 'Bearer local-student',
    body: { action: 'restore', noteId: targetNoteId },
  });
  assert.equal(student.statusCode, 403);
  const judgeA = await invoke({
    authorization: 'Bearer local-judge-a',
    body: { action: 'restore', noteId: targetNoteId },
  });
  assert.equal(judgeA.statusCode, 403);
  const forgedRole = await invoke({
    authorization: 'Bearer local-judge-b',
    body: { action: 'restore', noteId: targetNoteId, role: 'admin' },
  });
  assert.equal(forgedRole.statusCode, 400);
  const cookieAuth = await invoke({
    authorization: 'Bearer local-judge-b',
    headers: { cookie: 'bb_access=some-session' },
    body: { action: 'restore', noteId: targetNoteId },
  });
  assert.equal(cookieAuth.statusCode, 401);
  const allowedMethod = await invoke({ method: 'GET' });
  assert.equal(allowedMethod.statusCode, 405);
  assert.equal(calls.length, 3);
});

test('restore endpoint previews version and fields then restores one B test note in memory', async () => {
  const runs = new Map();
  let backupReads = 0;
  const handler = createRestoreHandler({
    verifyAuthorization: async () => ({
      kind: 'judge', identity: 'b', userId: targetOwnerId, runId: 'run-restore',
    }),
    readBackups: async () => {
      backupReads += 1;
      return { policy: structuredClone(policyBackup), memo: structuredClone(noteBackup) };
    },
    runs,
  });
  const invoke = async action => {
    const result = mockResponse();
    await handler({
      method: 'POST',
      headers: { authorization: 'Bearer local-judge-b', 'content-type': 'application/json' },
      body: { action, noteId: targetNoteId },
    }, result.response);
    return result;
  };

  const preview = await invoke('preview');
  assert.equal(preview.statusCode, 200);
  assert.equal(preview.body.policyVersion, policyBackup.version);
  assert.deepEqual(preview.body.policyChanges.map(change => change.field), [
    'ownerIsolation',
    'registeredDeviceRequired',
    'resourceBoundary',
    'riskStepUpRequired',
  ]);
  assert.equal(Object.hasOwn(preview.body.memo, 'body'), false);
  assert.equal(preview.body.persistence, 'serverless-memory-only');
  assert.deepEqual(preview.body.postRestoreRetests, {
    executed: 0,
    passed: 0,
    failed: 0,
    skipped: 0,
    status: 'not_run',
    cases: [],
  });
  assert.equal(backupReads, 1);

  const restored = await invoke('restore');
  assert.equal(restored.statusCode, 200);
  assert.equal(restored.body.restored, true);
  assert.equal(restored.body.persistence, 'serverless-memory-only');
  assert.equal(backupReads, 3, 'restore rereads both backup files before applying');
  const retests = restored.body.postRestoreRetests;
  assert.equal(retests.status, 'pass');
  assert.equal(retests.executed, 18);
  assert.equal(retests.passed, 18);
  assert.equal(retests.failed, 0);
  assert.equal(retests.skipped, 0);
  assert.equal(retests.cases.length, 18);
  assert.equal(retests.cases.find(item => item.id === 'registered_note_get').actual.decision, 'allow');
  assert.equal(retests.cases.find(item => item.id === 'notes_list').actual.decision, 'deny');
  assert.equal(retests.cases.find(item =>
    item.id === 'suspicious_request_requires_step_up').actual.decision, 'step_up');
  assert.deepEqual(retests.cases.filter(item => item.environment === 'server-mock')
    .map(item => [item.id, item.status]), [
    ['api_owner_a_own_note', 'pass'],
    ['api_owner_a_other_note', 'pass'],
    ['api_owner_b_own_note', 'pass'],
    ['api_owner_b_other_note', 'pass'],
  ]);
  const state = runs.get('run-restore').state;
  const restoredMemo = state.notes.find(note => note.id === targetNoteId);
  assert.equal(restoredMemo.ownerId, targetOwnerId);
  assert.equal(sha256(restoredMemo.body), noteBackup.note.contentSha256);
  assert.equal(state.notes.length, 2);
  assert.equal(state.notes.some(note => note.ownerId === '923e4567-e89b-42d3-a456-000000000001'), true);
  assert.equal(state.audit[0].action, 'test_fixture_initialized');
  assert.equal(state.audit.length, 4);
  assert.deepEqual(state.audit.at(-1).cases, retests.cases);
});

test('retests invoke the real decider against the restored candidate and failures do not commit it', async () => {
  const runs = new Map();
  let calls = 0;
  let candidateWasRestoredBeforeRetest = true;
  const handler = createRestoreHandler({
    verifyAuthorization: async () => ({
      kind: 'judge', identity: 'b', userId: targetOwnerId, runId: 'run-retest-failure',
    }),
    readBackups: async () => ({
      policy: structuredClone(policyBackup),
      memo: structuredClone(noteBackup),
    }),
    runRetests: state => runPostRestoreRetests(state, {
      decideRequest: async request => {
        calls += 1;
        candidateWasRestoredBeforeRetest &&= state.noteId === targetNoteId
          && state.notes.some(note => note.id === targetNoteId
            && note.ownerId === targetOwnerId
            && sha256(note.body) === noteBackup.note.contentSha256)
          && state.policies.notes.ownerIsolation === true;
        const actual = await decide(request);
        return request.service === 'teacher'
          ? { ...actual, decision: 'allow', reasonCode: 'approved' }
          : actual;
      },
    }),
    runs,
  });
  const result = mockResponse();
  await handler({
    method: 'POST',
    headers: { authorization: 'Bearer local-judge-b', 'content-type': 'application/json' },
    body: { action: 'restore', noteId: targetNoteId },
  }, result.response);
  assert.equal(result.statusCode, 409);
  assert.equal(result.body.restored, false);
  assert.equal(result.body.status, 'fail');
  assert.equal(result.body.postRestoreRetests.failed, 1);
  assert.equal(result.body.postRestoreRetests.passed, 17);
  assert.equal(calls, 12);
  assert.equal(candidateWasRestoredBeforeRetest, true);
  const state = runs.get('run-retest-failure').state;
  assert.equal(state.notes.some(note => note.id === targetNoteId), false);
  assert.equal(state.policies.notes.ownerIsolation, false);
  assert.equal(state.audit.at(-1).status, 'fail');
  assert.deepEqual(state.audit.at(-1).cases, result.body.postRestoreRetests.cases);
});

test('retest exceptions and runner-level skips are recorded and never reported as pass', async () => {
  const state = {
    ...restoreVerifiedTestRecovery(
      createInitialTestRecoveryState(), { policy: policyBackup, memo: noteBackup }, targetNoteId,
    ).state,
    noteId: targetNoteId,
    ownerId: targetOwnerId,
    contentSha256: noteBackup.note.contentSha256,
  };
  const perCaseFailure = await runPostRestoreRetests(state, {
    decideRequest: async request => {
      if (request.method === 'PUT') throw new Error('CASE_EXECUTION_ERROR');
      return decide(request);
    },
  });
  assert.equal(perCaseFailure.status, 'fail');
  assert.equal(perCaseFailure.cases.find(item => item.id === 'notes_put_denied').status, 'fail');
  assert.equal(perCaseFailure.cases.find(item => item.id === 'notes_put_denied').errorCode,
    'CASE_EXECUTION_ERROR');
  assert.notEqual(perCaseFailure.cases.find(item => item.id === 'notes_put_denied').status, 'pass');

  const runs = new Map();
  const handler = createRestoreHandler({
    verifyAuthorization: async () => ({
      kind: 'judge', identity: 'b', userId: targetOwnerId, runId: 'run-retest-exception',
    }),
    readBackups: async () => ({
      policy: structuredClone(policyBackup),
      memo: structuredClone(noteBackup),
    }),
    runRetests: async () => { throw new Error('RETEST_RUNNER_FAILED'); },
    runs,
  });
  const result = mockResponse();
  await handler({
    method: 'POST',
    headers: { authorization: 'Bearer local-judge-b', 'content-type': 'application/json' },
    body: { action: 'restore', noteId: targetNoteId },
  }, result.response);
  assert.equal(result.statusCode, 409);
  assert.equal(result.body.restored, false);
  assert.equal(result.body.postRestoreRetests.status, 'partial');
  assert.equal(result.body.postRestoreRetests.executed, 0);
  assert.equal(result.body.postRestoreRetests.failed, 0);
  assert.equal(result.body.postRestoreRetests.skipped, 1);
  assert.equal(result.body.postRestoreRetests.cases[0].status, 'not_run');
  assert.equal(runs.get('run-retest-exception').state.notes
    .some(note => note.id === targetNoteId), false);
  assert.equal(runs.get('run-retest-exception').state.audit.at(-1).status, 'partial');
});

test('missing, tampered, wrong-version or changing backup stops restore without changing state', async () => {
  const cases = [
    { code: 'BACKUP_VERIFICATION_FAILED', read: async () => { throw new Error('BACKUP_MISSING'); } },
    {
      code: 'BACKUP_VERIFICATION_FAILED',
      read: async () => ({
        policy: { ...policyBackup, policies: { ...policyBackup.policies, billing: { access: 'allow' } } },
        memo: structuredClone(noteBackup),
      }),
    },
    {
      code: 'BACKUP_VERIFICATION_FAILED',
      read: async () => ({
        policy: { ...policyBackup, version: 'wrong-version' },
        memo: structuredClone(noteBackup),
      }),
    },
  ];

  for (const scenario of cases) {
    const runs = new Map();
    const handler = createRestoreHandler({
      verifyAuthorization: async () => ({
        kind: 'judge', identity: 'b', userId: targetOwnerId, runId: scenario.code,
      }),
      readBackups: scenario.read,
      runs,
    });
    const result = mockResponse();
    await handler({
      method: 'POST',
      headers: { authorization: 'Bearer local-judge-b', 'content-type': 'application/json' },
      body: { action: 'restore', noteId: targetNoteId },
    }, result.response);
    assert.equal(result.statusCode, 503);
    assert.equal(result.body.error, scenario.code);
    assert.equal(runs.size, 0);
  }

  const runs = new Map();
  let count = 0;
  const changedDuringRestore = createRestoreHandler({
    verifyAuthorization: async () => ({
      kind: 'judge', identity: 'b', userId: targetOwnerId, runId: 'run-changed',
    }),
    readBackups: async () => {
      count += 1;
      return {
        policy: structuredClone(policyBackup),
        memo: count === 1 ? structuredClone(noteBackup) : {
          ...noteBackup,
          note: { ...noteBackup.note, title: 'changed after verification' },
        },
      };
    },
    runs,
  });
  const changed = mockResponse();
  await changedDuringRestore({
    method: 'POST',
    headers: { authorization: 'Bearer local-judge-b', 'content-type': 'application/json' },
    body: { action: 'restore', noteId: targetNoteId },
  }, changed.response);
  assert.equal(changed.statusCode, 503);
  assert.equal(changed.body.error, 'BACKUP_VERIFICATION_FAILED');
  assert.equal(count, 2, 'backup files must be read again before state is committed');
  assert.equal(runs.size, 0);
});

test('repeat restore is idempotent and unknown memo IDs are rejected', async () => {
  const runs = new Map();
  const handler = createRestoreHandler({
    verifyAuthorization: async () => ({
      kind: 'judge', identity: 'b', userId: targetOwnerId, runId: 'run-repeat',
    }),
    readBackups: async () => ({
      policy: structuredClone(policyBackup),
      memo: structuredClone(noteBackup),
    }),
    runs,
  });
  const invoke = async noteId => {
    const result = mockResponse();
    await handler({
      method: 'POST',
      headers: { authorization: 'Bearer local-judge-b', 'content-type': 'application/json' },
      body: { action: 'restore', noteId },
    }, result.response);
    return result;
  };
  const unknown = await invoke('923e4567-e89b-42d3-a456-000000000001');
  assert.equal(unknown.statusCode, 404);
  assert.equal(unknown.body.error, 'NOTE_ID_NOT_IN_BACKUP');
  assert.equal(runs.size, 0);
  assert.equal((await invoke(targetNoteId)).body.restored, true);
  const first = runs.get('run-repeat').state;
  assert.equal((await invoke(targetNoteId)).body.restored, true);
  const second = runs.get('run-repeat').state;
  assert.equal(second.notes.length, first.notes.length);
  assert.equal(second.audit.length, first.audit.length + 3);
  assert.equal(second.audit.findLast(item => item.action === 'memo_restore').outcome, 'already_safe');
  assert.deepEqual(second.audit.at(-1).cases, first.audit.at(-1).cases);
});
