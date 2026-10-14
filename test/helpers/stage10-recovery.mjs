import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';
import { createNotesHandler } from '../../api/notes.js';
import { decide } from '../../src/decider.mjs';

const POLICY_SHA256 = '6b10ef3fee2879431384e551d1c2f4566845ea6931c5b9ee17327be228ec9008';
const NOTE_SHA256 = '1d3d0e89982e4ef8498e78f769def23071174c48706b6b16ce74b3d5e168aced';
const EXPECTED_POLICY_VERSION = 'stage10-safe-policy-fixture-v1';
const EXPECTED_POLICY_COMMIT = '9dd2379666b36ea1dc3cc5ac021d56b46dae6a16';
const EXPECTED_NOTE_ID = '623e4567-e89b-42d3-a456-000000000001';
const EXPECTED_OWNER_ID = '723e4567-e89b-42d3-a456-000000000001';

export function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function fixtureDigest(fixture) {
  return sha256(JSON.stringify(fixture));
}

function parseBackup(contents, code) {
  try {
    return JSON.parse(contents);
  } catch {
    throw new Error(code);
  }
}

function requireFixture(condition, code) {
  if (!condition) throw new Error(code);
}

export async function readTestBackups(read = readFile) {
  const policyPath = new URL('../fixtures/stage10-policy.json', import.meta.url);
  const notePath = new URL('../fixtures/stage10-note.json', import.meta.url);
  let policyContents;
  let noteContents;
  try {
    [policyContents, noteContents] = await Promise.all([
      read(policyPath, 'utf8'),
      read(notePath, 'utf8'),
    ]);
  } catch {
    throw new Error('BACKUP_MISSING');
  }
  return {
    policy: parseBackup(policyContents, 'POLICY_BACKUP_INVALID'),
    memo: parseBackup(noteContents, 'NOTE_BACKUP_INVALID'),
  };
}

export function verifyPolicyBackup(backup) {
  requireFixture(backup && typeof backup === 'object' && !Array.isArray(backup),
    'POLICY_BACKUP_MISSING');
  requireFixture(backup.schema === 'byteback.test-policy-backup.v1'
    && backup.version === EXPECTED_POLICY_VERSION
    && backup.provenance?.kind === 'locally-generated-test-fixture'
    && backup.provenance?.basedOnCommit === EXPECTED_POLICY_COMMIT
    && backup.provenance?.historicalBackup === false
    && backup.scope?.environment === 'test-only'
    && backup.scope?.service === 'notes'
    && backup.policies && typeof backup.policies === 'object'
    && Object.keys(backup.policies).sort().join(',') === 'announcements,billing,notes'
    && Object.keys(backup.policies.notes).sort().join(',')
      === 'ownerIsolation,registeredDeviceRequired,resourceBoundary,riskStepUpRequired',
  'POLICY_BACKUP_VERSION_OR_SCOPE_INVALID');
  requireFixture(fixtureDigest(backup) === POLICY_SHA256, 'POLICY_BACKUP_INTEGRITY_FAILED');
  return Object.freeze({
    version: backup.version,
    service: backup.scope.service,
    sha256: POLICY_SHA256,
    historicalBackup: false,
  });
}

export function previewTestPolicyRestore(currentPolicies, backup, service = 'notes') {
  const verified = verifyPolicyBackup(backup);
  requireFixture(service === verified.service, 'POLICY_SERVICE_NOT_IN_BACKUP');
  requireFixture(currentPolicies && typeof currentPolicies === 'object'
    && !Array.isArray(currentPolicies), 'CURRENT_POLICY_INVALID');
  const targetPolicy = backup.policies[service];
  const currentPolicy = currentPolicies[service];
  const fields = Object.keys(targetPolicy).sort();
  const changes = fields.filter(key => !isDeepStrictEqual(currentPolicy?.[key], targetPolicy[key]))
    .map(key => ({
      field: key,
      from: currentPolicy?.[key] ?? null,
      to: targetPolicy[key] ?? null,
    }));
  return {
    version: verified.version,
    service,
    changes,
    unchangedServices: Object.keys(currentPolicies).filter(name => name !== service).sort(),
  };
}

export function restoreTestPolicy(state, backup, service = 'notes') {
  requireFixture(state && state.policies && Array.isArray(state.audit), 'RECOVERY_STATE_INVALID');
  const preview = previewTestPolicyRestore(state?.policies, backup, service);
  const policies = structuredClone(state.policies);
  if (preview.changes.length) {
    policies[service] ??= {};
    for (const field of Object.keys(backup.policies[service])) {
      policies[service][field] = structuredClone(backup.policies[service][field]);
    }
  }
  requireFixture(Object.keys(backup.policies[service]).every(field =>
    isDeepStrictEqual(policies[service][field], backup.policies[service][field])),
    'POLICY_POST_RESTORE_VERIFICATION_FAILED');
  return {
    policies,
    audit: [
      ...state.audit,
      {
        action: 'policy_restore',
        service,
        version: preview.version,
        outcome: preview.changes.length ? 'restored' : 'already_safe',
      },
    ],
  };
}

export function verifyNoteBackup(backup) {
  requireFixture(backup && typeof backup === 'object' && !Array.isArray(backup),
    'NOTE_BACKUP_MISSING');
  requireFixture(backup.schema === 'byteback.test-note-backup.v1'
    && backup.version === 'stage10-virtual-note-fixture-v1'
    && backup.provenance?.kind === 'locally-generated-test-fixture'
    && backup.provenance?.historicalBackup === false
    && backup.scope?.environment === 'test-only'
    && backup.scope?.recordCount === 1
    && backup.note?.id === EXPECTED_NOTE_ID
    && backup.note?.ownerId === EXPECTED_OWNER_ID
    && typeof backup.note?.title === 'string'
    && typeof backup.note?.body === 'string'
    && backup.note?.contentSha256 === sha256(backup.note.body),
  'NOTE_BACKUP_VERSION_SCOPE_OR_CONTENT_INVALID');
  requireFixture(fixtureDigest(backup) === NOTE_SHA256, 'NOTE_BACKUP_INTEGRITY_FAILED');
  return Object.freeze({
    version: backup.version,
    id: backup.note.id,
    ownerId: backup.note.ownerId,
    contentSha256: backup.note.contentSha256,
    fixtureSha256: fixtureDigest(backup),
    historicalBackup: false,
  });
}

export function restoreTestMemo(state, backup, requestedId) {
  const verified = verifyNoteBackup(backup);
  requireFixture(requestedId === verified.id, 'NOTE_ID_NOT_IN_BACKUP');
  requireFixture(state && Array.isArray(state.notes) && Array.isArray(state.audit),
    'RECOVERY_STATE_INVALID');
  const existing = state.notes.filter(note => note.id === verified.id);
  requireFixture(existing.length <= 1, 'DUPLICATE_TARGET_NOTE');
  if (existing.length) requireFixture(existing[0].ownerId === verified.ownerId,
    'EXISTING_TARGET_OWNER_CONFLICTS');

  const beforeOtherNotes = state.notes.filter(note => note.id !== verified.id);
  const restoredNote = {
    ...(existing[0] ?? {}),
    id: verified.id,
    ownerId: verified.ownerId,
    title: backup.note.title,
    body: backup.note.body,
    contentSha256: verified.contentSha256,
  };
  const notes = existing.length
    ? state.notes.map(note => note.id === verified.id ? restoredNote : structuredClone(note))
    : [...structuredClone(state.notes), restoredNote];
  const restored = notes.find(note => note.id === verified.id);
  requireFixture(restored?.id === verified.id && restored.ownerId === verified.ownerId
    && restored.title === backup.note.title
    && sha256(restored.body) === verified.contentSha256
    && isDeepStrictEqual(notes.filter(note => note.id !== verified.id), beforeOtherNotes),
  'NOTE_POST_RESTORE_VERIFICATION_FAILED');
  return {
    notes,
    audit: [
      ...state.audit,
      {
        action: 'memo_restore',
        id: verified.id,
        ownerId: verified.ownerId,
        contentSha256: verified.contentSha256,
        outcome: existing.length
          && existing[0].title === backup.note.title
          && existing[0].contentSha256 === verified.contentSha256
          && sha256(existing[0].body) === verified.contentSha256
          ? 'already_safe'
          : 'restored',
      },
    ],
  };
}

export function createInitialTestRecoveryState() {
  return {
    policies: {
      notes: {
        ownerIsolation: false,
        registeredDeviceRequired: false,
        riskStepUpRequired: false,
        resourceBoundary: 'all-notes',
      },
      announcements: { access: 'read-only', audit: true },
      billing: { access: 'deny', audit: true },
    },
    notes: [{
      id: '823e4567-e89b-42d3-a456-000000000001',
      ownerId: '923e4567-e89b-42d3-a456-000000000001',
      title: '가상 A 메모',
      body: '인메모리 시험 자료',
      contentSha256: sha256('인메모리 시험 자료'),
    }],
    audit: [{ action: 'test_fixture_initialized', sequence: 1 }],
  };
}

export function getVerifiedBackups(backups) {
  return {
    policy: verifyPolicyBackup(backups?.policy),
    memo: verifyNoteBackup(backups?.memo),
  };
}

export function previewTestRecovery(state, backups, requestedId) {
  const verified = getVerifiedBackups(backups);
  requireFixture(requestedId === verified.memo.id, 'NOTE_ID_NOT_IN_BACKUP');
  return {
    policyVersion: verified.policy.version,
    policySha256: verified.policy.sha256,
    policyChanges: previewTestPolicyRestore(state.policies, backups.policy).changes,
    memo: {
      id: verified.memo.id,
      ownerId: verified.memo.ownerId,
      contentSha256: verified.memo.contentSha256,
    },
  };
}

export function restoreVerifiedTestRecovery(state, backups, requestedId) {
  const preview = previewTestRecovery(state, backups, requestedId);
  const policyResult = restoreTestPolicy(state, backups.policy);
  const memoResult = restoreTestMemo({
    ...state,
    notes: state.notes,
    audit: policyResult.audit,
  }, backups.memo, requestedId);
  return {
    state: {
      policies: policyResult.policies,
      notes: memoResult.notes,
      audit: memoResult.audit,
    },
    preview,
  };
}

const DECISION_CASES = [
  {
    id: 'registered_note_get',
    target: 'restored B note via decider',
    request: { service: 'notes', method: 'GET', path: '/notes/:noteId', route: 'GET /notes/:id' },
    expected: { decision: 'allow', reasonCode: 'approved' },
  },
  {
    id: 'announcements_get',
    target: 'announcements read policy',
    request: {
      service: 'announcements', method: 'GET', path: '/announcements',
      route: 'GET /announcements',
    },
    expected: { decision: 'allow', reasonCode: 'approved' },
  },
  {
    id: 'unregistered_device',
    target: 'registered-device policy',
    request: { service: 'notes', method: 'GET', deviceRegistered: false },
    expected: { decision: 'deny', reasonCode: 'device_not_registered' },
  },
  {
    id: 'notes_list',
    target: 'notes collection boundary',
    request: { service: 'notes', method: 'GET', path: '/notes', route: 'GET /notes' },
    expected: { decision: 'deny', reasonCode: 'resource_access_denied' },
  },
  ...['POST', 'PUT', 'DELETE'].map(method => ({
    id: `notes_${method.toLowerCase()}_denied`,
    target: `notes ${method} write policy`,
    request: {
      service: 'notes', method, path: '/notes/:noteId', route: `${method} /notes/:id`,
    },
    expected: { decision: 'deny', reasonCode: 'resource_access_denied' },
  })),
  {
    id: 'announcements_write_denied',
    target: 'announcements read-only policy',
    request: {
      service: 'announcements', method: 'POST', path: '/announcements',
      route: 'POST /announcements',
    },
    expected: { decision: 'deny', reasonCode: 'resource_access_denied' },
  },
  {
    id: 'teacher_resource_denied',
    target: 'unlisted teacher resource',
    request: {
      service: 'teacher', method: 'GET', path: '/teacher/materials',
      route: 'GET /teacher/materials',
    },
    expected: { decision: 'deny', reasonCode: 'resource_access_denied' },
  },
  {
    id: 'step_up_cannot_bypass_write',
    target: 'write denial despite verified step-up',
    request: {
      service: 'notes', method: 'DELETE', path: '/notes/:noteId',
      route: 'DELETE /notes/:id', stepUp: { verified: true, authAgeSeconds: 30 },
    },
    expected: { decision: 'deny', reasonCode: 'resource_access_denied' },
  },
  {
    id: 'suspicious_request_requires_step_up',
    target: 'composite suspicious request',
    request: {
      service: 'notes',
      method: 'GET',
      path: '/notes/:noteId',
      route: 'GET /notes/:id',
      stepUp: { verified: false, authAgeSeconds: null },
      recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 10 }],
      signals: { source: 'judge_fixture', region: 'unknown', network: 'unusual', hour: 2 },
    },
    expected: { decision: 'step_up', reasonCode: 'step_up_required' },
  },
  {
    id: 'verified_step_up_allows_note_get',
    target: 'registered note GET after reauthentication',
    request: {
      service: 'notes',
      method: 'GET',
      path: '/notes/:noteId',
      route: 'GET /notes/:id',
      stepUp: { verified: true, authAgeSeconds: 30 },
    },
    expected: { decision: 'allow', reasonCode: 'approved' },
  },
];

function decisionRequest(index, override, noteId) {
  const request = {
    schema: 'aleph.decision.v1',
    requestId: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    classId: 'stage10-test-class',
    projectId: 'stage10-test-project',
    subjectId: 'stage10-test-subject',
    deviceId: '0123456789abcdef',
    service: 'notes',
    method: 'GET',
    path: `/notes/${noteId}`,
    route: 'GET /notes/:id',
    queryLength: 0,
    querySha256: sha256(''),
    at: new Date().toISOString(),
    policyRevision: 10,
    deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null },
    recentEvents: [],
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 12 },
    ...override,
  };
  if (Object.keys(request).length !== 18) throw new Error('DECIDER_REQUEST_FIELDS_INVALID');
  return request;
}

function decisionResultValid(result) {
  return result && typeof result === 'object' && !Array.isArray(result)
    && Object.keys(result).sort().join(',') === 'decision,reasonCode,requestId,ruleIds,schema'
    && result.schema === 'aleph.decision.v1'
    && typeof result.requestId === 'string'
    && ['allow', 'deny', 'step_up'].includes(result.decision)
    && typeof result.reasonCode === 'string'
    && Array.isArray(result.ruleIds)
    && result.ruleIds.every(ruleId => ['device_registered', 'resource_boundary',
      'step_up_required'].includes(ruleId));
}

function caseRecord({ id, target, environment, expected, actual, errorCode }) {
  const pass = !errorCode && expected.status === actual?.status
    && (expected.decision === undefined || expected.decision === actual?.decision)
    && (expected.reasonCode === undefined || expected.reasonCode === actual?.reasonCode)
    && (expected.noteId === undefined || expected.noteId === actual?.noteId)
    && (expected.contentSha256 === undefined
      || expected.contentSha256 === actual?.contentSha256);
  return {
    id,
    target,
    environment,
    executed: true,
    expected,
    actual: actual ?? null,
    status: pass ? 'pass' : 'fail',
    ...(errorCode ? { errorCode } : {}),
  };
}

export async function runPostRestoreRetests(state, { decideRequest = decide } = {}) {
  const cases = [];
  let requestIndex = 1;

  for (const scenario of DECISION_CASES) {
    try {
      const request = decisionRequest(requestIndex++, scenario.request, state.noteId);
      if (typeof request.path === 'string') {
        request.path = request.path.replace(':noteId', state.noteId);
      }
      const result = await decideRequest(request);
      if (!decisionResultValid(result) || result.requestId !== request.requestId) {
        cases.push(caseRecord({
          ...scenario,
          environment: 'virtual-decider',
          expected: { ...scenario.expected, status: 'valid-contract-response' },
          actual: null,
          errorCode: 'DECIDER_RESPONSE_INVALID',
        }));
        continue;
      }
      cases.push(caseRecord({
        ...scenario,
        environment: 'virtual-decider',
        expected: {
          ...scenario.expected,
          status: 'valid-contract-response',
        },
        actual: {
          decision: result.decision,
          reasonCode: result.reasonCode,
          ruleIds: result.ruleIds,
          status: 'valid-contract-response',
        },
      }));
    } catch (error) {
      cases.push(caseRecord({
        ...scenario,
        environment: 'virtual-decider',
        expected: { ...scenario.expected, status: 'valid-contract-response' },
        actual: null,
        errorCode: typeof error?.message === 'string'
          && /^[A-Z][A-Z0-9_]{0,63}$/u.test(error.message)
          ? error.message
          : 'DECIDER_EXECUTION_FAILED',
      }));
    }
  }

  try {
    const policy = state.policies?.notes;
    const note = state.notes?.find(item => item.id === state.noteId);
    const actual = {
      status: note && policy?.ownerIsolation === true
        && policy?.registeredDeviceRequired === true
        && policy?.riskStepUpRequired === true
        && policy?.resourceBoundary === 'single-note'
        && note.id === state.noteId
        && note.ownerId === state.ownerId
        && sha256(note.body) === state.contentSha256
        && note.contentSha256 === state.contentSha256
        ? 'verified'
        : 'mismatch',
      ownerId: note?.ownerId ?? null,
      contentSha256: note ? sha256(note.body) : null,
    };
    cases.push(caseRecord({
      id: 'restored_b_note_and_policy_integrity',
      target: 'same restored policy and B test note state',
      environment: 'serverless-memory-test-state',
      expected: {
        status: 'verified',
        ownerId: state.ownerId,
        contentSha256: state.contentSha256,
      },
      actual,
    }));
  } catch {
    cases.push(caseRecord({
      id: 'restored_b_note_and_policy_integrity',
      target: 'same restored policy and B test note state',
      environment: 'serverless-memory-test-state',
      expected: { status: 'verified', ownerId: state.ownerId,
        contentSha256: state.contentSha256 },
      actual: null,
      errorCode: 'RESTORED_STATE_CHECK_FAILED',
    }));
  }

  try {
    const otherPoliciesPreserved = state.policies?.announcements?.access === 'read-only'
      && state.policies.announcements.audit === true
      && state.policies?.billing?.access === 'deny'
      && state.policies.billing.audit === true;
    cases.push(caseRecord({
      id: 'other_service_policies_preserved',
      target: 'non-target service policies',
      environment: 'serverless-memory-test-state',
      expected: { status: 'verified' },
      actual: { status: otherPoliciesPreserved ? 'verified' : 'mismatch' },
    }));
  } catch {
    cases.push(caseRecord({
      id: 'other_service_policies_preserved',
      target: 'non-target service policies',
      environment: 'serverless-memory-test-state',
      expected: { status: 'verified' },
      actual: null,
      errorCode: 'OTHER_POLICY_CHECK_FAILED',
    }));
  }

  try {
    cases.push(...await runOwnerApiRetests(state));
  } catch {
    cases.push({
      id: 'api_owner_isolation',
      target: 'A/B ownership in existing notes API handler',
      environment: 'server-mock',
      executed: false,
      expected: { status: 'A/B owner isolation verified' },
      actual: null,
      status: 'not_run',
      errorCode: 'OWNER_API_RETEST_UNAVAILABLE',
    });
  }

  const passed = cases.filter(item => item.status === 'pass').length;
  const failed = cases.filter(item => item.status === 'fail').length;
  const skipped = cases.filter(item => item.status === 'not_run').length;
  return {
    executed: cases.filter(item => item.executed).length,
    passed,
    failed,
    skipped,
    status: failed ? 'fail' : skipped ? 'partial' : 'pass',
    cases,
  };
}

async function runOwnerApiRetests(state) {
  const a = state.notes.find(note => note.id !== state.noteId);
  const b = state.notes.find(note => note.id === state.noteId);
  if (!a || !b) throw new Error('OWNER_TEST_NOTES_MISSING');
  const identities = new Map([
    ['stage10-internal-a', { kind: 'student', userId: a.ownerId }],
    ['stage10-internal-b', { kind: 'student', userId: b.ownerId }],
  ]);
  const clientFactory = () => ({
    from(table) {
      if (table !== 'notes') throw new Error('OWNER_TEST_TABLE_INVALID');
      const filters = [];
      const query = {
        select() { return query; },
        eq(field, value) { filters.push([field, value]); return query; },
        async maybeSingle() {
          const row = state.notes.find(note => filters.every(([field, value]) => (
            field === 'id' ? note.id === value
              : field === 'owner_id' ? note.ownerId === value
                : false
          )));
          return {
            data: row ? { id: row.id, title: row.title, content: row.body } : null,
            error: null,
          };
        },
      };
      return query;
    },
  });
  const handler = createNotesHandler({
    verifierFactory: () => async authorization => identities.get(authorization) ?? null,
    clientFactory,
    env: { SUPABASE_URL: 'https://memory.test.invalid', SUPABASE_SECRET_KEY: 'memory-only' },
  });
  const checks = [
    { actor: 'A', note: a, status: 200 },
    { actor: 'A', note: b, status: 404 },
    { actor: 'B', note: b, status: 200 },
    { actor: 'B', note: a, status: 404 },
  ];
  const results = [];
  for (const [index, check] of checks.entries()) {
    const response = {
      statusCode: null,
      body: null,
      setHeader() {},
      status(value) {
        response.statusCode = value;
        return { json(body) { response.body = body; return response; } };
      },
    };
    await handler({
      method: 'GET',
      query: { id: check.note.id },
      headers: { authorization: `stage10-internal-${check.actor.toLowerCase()}` },
    }, response);
    const expected = {
      status: check.status,
      noteId: check.status === 200 ? check.note.id : null,
    };
    const actual = {
      status: response.statusCode,
      noteId: response.body?.id ?? null,
    };
    results.push(caseRecord({
      id: `api_owner_${check.actor.toLowerCase()}_${index % 2 ? 'other' : 'own'}_note`,
      target: `notes API verified identity ${check.actor} owner filter`,
      environment: 'server-mock',
      expected,
      actual,
    }));
  }
  return results;
}
