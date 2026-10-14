import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { test } from 'node:test';
import { resolve } from 'node:path';
import {
  previewTestPolicyRestore,
  restoreTestMemo,
  restoreTestPolicy,
  sha256,
  verifyNoteBackup,
  verifyPolicyBackup,
} from './helpers/stage10-recovery.mjs';

const root = resolve(import.meta.dirname, '..');
const policyBackup = JSON.parse(await readFile(
  new URL('./fixtures/stage10-policy.json', import.meta.url), 'utf8'));
const noteBackup = JSON.parse(await readFile(
  new URL('./fixtures/stage10-note.json', import.meta.url), 'utf8'));
const targetNoteId = '623e4567-e89b-42d3-a456-000000000001';
const targetOwnerId = '723e4567-e89b-42d3-a456-000000000001';

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
  }, noteBackup, targetNoteId), /EXISTING_TARGET_NOTE_CONFLICTS/u);
  assert.deepEqual(state, original);
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

test('no public restore POST route or student policy route was added', async () => {
  const config = JSON.parse(await readFile(resolve(root, 'aleph.config.json'), 'utf8'));
  const apiFiles = (await readdir(resolve(root, 'api'), { recursive: true }))
    .filter(file => /restore/iu.test(file));
  assert.equal(config.restoreRoute, null);
  assert.deepEqual(config.allowedRoutes, ['GET /api/notes/:id']);
  assert.deepEqual(apiFiles, []);
});
