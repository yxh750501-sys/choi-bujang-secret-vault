import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { isDeepStrictEqual } from 'node:util';

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
