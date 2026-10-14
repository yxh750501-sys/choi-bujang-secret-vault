import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createDeviceApprovalAdminHandler } from '../api/device-approval.js';
import { createDeviceHandler } from '../api/device.js';
import { createNotesHandler } from '../api/notes.js';
import { createAuthHandlers } from '../src/server-session.mjs';
import {
  createSupabaseDeviceApprovalStore,
  hashDeviceReference,
} from '../src/device-approval.mjs';
import { readFile } from 'node:fs/promises';

const userA = '123e4567-e89b-42d3-a456-426614174000';
const userB = '123e4567-e89b-42d3-a456-426614174001';
const userAdmin = '123e4567-e89b-42d3-a456-426614174002';
const userInactiveAdmin = '123e4567-e89b-42d3-a456-426614174003';
const accessA = 'verified-test-session-a';
const accessB = 'verified-test-session-b';
const accessAdmin = 'verified-test-session-admin';
const accessInactiveAdmin = 'verified-test-session-inactive-admin';
const noteA = '223e4567-e89b-42d3-a456-000000000001';
const noteB = '223e4567-e89b-42d3-a456-000000000002';
const deviceCookieName = '__Host-bb_device_ref';
const deviceReference = Buffer.alloc(32, 5).toString('base64url');
const env = {
  APP_ORIGIN: 'https://vault.example.test',
  CSRF_SECRET: 'test-csrf-secret-for-device-approval-only-32-bytes',
  SUPABASE_URL: 'https://database.example.test',
  SUPABASE_SECRET_KEY: 'test-server-key-not-a-credential',
  VERCEL: '1',
};

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
  return { response, headers, get statusCode() { return statusCode; }, get body() { return body; } };
}

function approvalStore({ adminLookupFailure = false } = {}) {
  const records = new Map();
  const calls = [];
  const admins = new Set([userAdmin]);
  const key = (userId, deviceRef) => `${userId}:${deviceRef}`;
  return {
    calls,
    records,
    admins,
    async get(userId, deviceRef) {
      calls.push({ operation: 'get', userId, deviceRef });
      const record = records.get(key(userId, deviceRef)) ?? null;
      if (record?.status === 'approved' && Date.parse(record.approved_expires_at) <= Date.now()) {
        record.status = 'expired';
      }
      return record;
    },
    async isAdmin(userId) {
      calls.push({ operation: 'isAdmin', userId });
      if (adminLookupFailure) throw new Error('allowlist unavailable');
      return admins.has(userId);
    },
    async listPending() {
      calls.push({ operation: 'listPending' });
      return [...records.values()]
        .filter(record => record.status === 'pending')
        .map(({ user_id, device_ref, requested_at }) => ({ user_id, device_ref, requested_at }));
    },
    async request(userId, deviceRef) {
      calls.push({ operation: 'request', userId, deviceRef });
      const existing = records.get(key(userId, deviceRef));
      if (existing?.status === 'approved') return existing;
      const record = {
        user_id: userId,
        device_ref: deviceRef,
        status: 'pending',
        requested_at: new Date().toISOString(),
      };
      records.set(key(userId, deviceRef), record);
      return record;
    },
    async setStatus(userId, deviceRef, status, actor, expectedStatus) {
      calls.push({ operation: 'setStatus', userId, deviceRef, status, actor, expectedStatus });
      const existing = records.get(key(userId, deviceRef));
      if (!existing || existing.status !== expectedStatus) return null;
      const now = new Date().toISOString();
      const record = {
        ...existing,
        status,
        updated_by: actor,
        approved_by: status === 'approved' ? actor : null,
        approved_at: status === 'approved' ? now : null,
        approved_expires_at: status === 'approved'
          ? new Date(Date.parse(now) + 30 * 24 * 60 * 60 * 1000).toISOString()
          : null,
        rejected_at: status === 'rejected' ? now : null,
        revoked_at: status === 'revoked' ? now : null,
      };
      records.set(key(userId, deviceRef), record);
      return record;
    },
  };
}

class NotesQuery {
  constructor(rows, calls) {
    this.rows = rows;
    this.calls = calls;
    this.filters = {};
    this.method = 'GET';
    this.body = null;
  }

  select() { return this; }
  order() { return this; }
  eq(key, value) { this.filters[key] = value; return this; }
  insert(value) { this.method = 'POST'; this.body = value; return this; }
  update(value) { this.method = 'PATCH'; this.body = value; return this; }
  delete() { this.method = 'DELETE'; return this; }

  execute(single = false) {
    this.calls.push({ method: this.method, filters: { ...this.filters } });
    if (this.method === 'POST') {
      this.rows.set(this.body.id, this.body);
      return { data: [{ id: this.body.id }], error: null, status: 201 };
    }
    const found = [...this.rows.values()].filter(row =>
      Object.entries(this.filters).every(([field, value]) => row[field] === value));
    if (this.method === 'PATCH' && found[0]) Object.assign(found[0], this.body);
    if (this.method === 'DELETE' && found[0]) this.rows.delete(found[0].id);
    const data = single ? found[0] ?? null : found;
    return { data, error: null, status: 200 };
  }

  then(resolve, reject) {
    return Promise.resolve(this.execute()).then(resolve, reject);
  }
  async maybeSingle() { return this.execute(true); }
  async single() { return this.execute(true); }
}

class ApprovalQuery {
  constructor(rows) {
    this.rows = rows;
    this.filters = {};
    this.updateValues = null;
  }

  select() { return this; }
  eq(key, value) { this.filters[key] = value; return this; }
  update(value) { this.updateValues = value; return this; }
  async maybeSingle() {
    const record = this.rows.get(`${this.filters.user_id}:${this.filters.device_ref}`);
    if (!record || (this.filters.status && record.status !== this.filters.status)) {
      return { data: null, error: null };
    }
    if (this.updateValues) Object.assign(record, this.updateValues);
    return { data: { ...record }, error: null };
  }
}

function createFixture({ store = approvalStore(), storeFailure = false } = {}) {
  const identities = new Map([
    [accessA, { kind: 'student', userId: userA }],
    [accessB, { kind: 'student', userId: userB }],
    [accessAdmin, { kind: 'student', userId: userAdmin }],
    [accessInactiveAdmin, { kind: 'student', userId: userInactiveAdmin }],
  ]);
  const verifierFactory = () => async authorization =>
    identities.get(authorization.slice('Bearer '.length)) ?? null;
  const noteRows = new Map([
    [noteA, { id: noteA, owner_id: userA, title: 'A private test note', content: 'A fixture body' }],
    [noteB, { id: noteB, owner_id: userB, title: 'B private test note', content: 'B fixture body' }],
  ]);
  const noteDbCalls = [];
  const clientFactory = () => ({
    from(table) {
      assert.equal(table, 'notes');
      return new NotesQuery(noteRows, noteDbCalls);
    },
  });
  const deviceHandler = createDeviceHandler({
    env,
    verifierFactory,
    storeFactory: () => {
      if (storeFailure) throw new Error('database unavailable');
      return store;
    },
    nonceFactory: length => Buffer.alloc(length, 5),
  });
  const deviceApprovalAdminHandler = createDeviceApprovalAdminHandler({
    env,
    verifierFactory,
    storeFactory: () => store,
  });
  const notesHandler = createNotesHandler({
    env,
    verifierFactory,
    clientFactory,
    deviceApprovalStoreFactory: () => {
      if (storeFailure) throw new Error('database unavailable');
      return store;
    },
  });
  const auth = createAuthHandlers({
    env,
    nonceFactory: length => Buffer.alloc(length, 7),
  });

  function request(method, {
    user = accessA,
    csrf,
    reference = null,
    body,
    id,
    headers = {},
    origin = env.APP_ORIGIN,
  } = {}) {
    const cookieParts = [`__Host-bb_access=${encodeURIComponent(user)}`];
    if (csrf) cookieParts.push(`__Host-bb_csrf=${encodeURIComponent(csrf)}`);
    if (reference) cookieParts.push(`${deviceCookieName}=${encodeURIComponent(reference)}`);
    return {
      method,
      query: id === undefined ? {} : { id },
      body,
      headers: {
        cookie: cookieParts.join('; '),
        origin,
        'sec-fetch-site': 'same-origin',
        ...(csrf ? { 'x-csrf-token': csrf } : {}),
        ...(method === 'POST' || method === 'PUT' ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
    };
  }

  return {
    store,
    noteRows,
    noteDbCalls,
    request,
    async csrfToken() {
      const result = responseMock();
      await auth.csrf({ method: 'GET', headers: {} }, result.response);
      assert.equal(result.statusCode, 200);
      return result.body.csrfToken;
    },
    async invoke(handler, requestValue) {
      const result = responseMock();
      await handler(requestValue, result.response);
      return result;
    },
    handlers: { deviceHandler, deviceApprovalAdminHandler, notesHandler },
  };
}

test('device and admin handlers enforce allowlist approval, ownership, and revocation', async () => {
  const fixture = createFixture();
  const csrf = await fixture.csrfToken();
  const rawDeviceRequest = fixture.request('GET');
  const rawNotes = await fixture.invoke(fixture.handlers.notesHandler, rawDeviceRequest);
  assert.equal(rawNotes.statusCode, 403);
  assert.equal(rawNotes.body.error, 'DEVICE_NOT_APPROVED');
  assert.equal(fixture.noteDbCalls.length, 0, 'unregistered devices must not query protected notes');

  const firstStatus = await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('GET'));
  assert.equal(firstStatus.statusCode, 200);
  assert.deepEqual(firstStatus.body, { status: 'unregistered', approved: false, pending: false });
  const setCookies = firstStatus.headers.get('set-cookie');
  const issuedCookie = setCookies.find(value => value.startsWith(`${deviceCookieName}=`));
  assert.ok(issuedCookie);
  assert.match(issuedCookie, /; HttpOnly;/u);
  assert.match(issuedCookie, /; Secure;/u);
  assert.equal(decodeURIComponent(issuedCookie.slice(deviceCookieName.length + 1, issuedCookie.indexOf(';'))),
    deviceReference);
  const referenceHash = hashDeviceReference(deviceReference);

  const pending = await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('POST', {
    csrf, reference: deviceReference, body: { action: 'request' },
    headers: { 'x-device-id': 'attacker-selected-device' },
  }));
  assert.equal(pending.statusCode, 200);
  assert.equal(pending.body.status, 'pending');
  assert.equal(fixture.store.calls.at(-1).deviceRef, referenceHash);

  const whilePending = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('GET', { reference: deviceReference }));
  assert.equal(whilePending.statusCode, 403);
  for (const [method, options] of [
    ['GET', { id: noteA }],
    ['POST', { body: { title: 'blocked fixture', body: 'blocked body' } }],
    ['PUT', { id: noteA, body: { title: 'blocked fixture', body: 'blocked body' } }],
    ['DELETE', { id: noteA }],
  ]) {
    const denied = await fixture.invoke(fixture.handlers.notesHandler,
      fixture.request(method, { ...options, csrf, reference: deviceReference }));
    assert.equal(denied.statusCode, 403, `${method} must remain blocked while pending`);
    assert.equal(denied.body.error, 'DEVICE_NOT_APPROVED');
  }
  const unsupportedPatch = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('PATCH', { id: noteA, reference: deviceReference }));
  assert.equal(unsupportedPatch.statusCode, 405);
  assert.equal(fixture.noteDbCalls.length, 0);

  const selfApprove = await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('POST', {
    csrf, reference: deviceReference, body: { action: 'approve' },
  }));
  assert.equal(selfApprove.statusCode, 403);
  assert.equal(selfApprove.body.error, 'DEVICE_APPROVAL_FORBIDDEN');
  const forgedApproval = await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('POST', {
    csrf, reference: deviceReference, body: { action: 'request', approved: true, role: 'admin' },
  }));
  assert.equal(forgedApproval.statusCode, 400);

  const nonAdminList = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('GET', { user: accessA }));
  assert.equal(nonAdminList.statusCode, 403);

  const inactiveAdminList = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('GET', { user: accessInactiveAdmin }));
  assert.equal(inactiveAdminList.statusCode, 403);

  const pendingList = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('GET', { user: accessAdmin }));
  assert.equal(pendingList.statusCode, 200);
  assert.deepEqual(pendingList.body.requests, [{
    userId: userA,
    deviceRef: referenceHash,
    requestedAt: fixture.store.records.get(`${userA}:${referenceHash}`).requested_at,
  }]);

  const selfApproval = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('POST', {
      user: accessAdmin,
      csrf,
      body: { action: 'approve', userId: userAdmin, deviceRef: referenceHash },
    }));
  assert.equal(selfApproval.statusCode, 403);
  assert.equal(selfApproval.body.error, 'SELF_DEVICE_APPROVAL_FORBIDDEN');

  const stolenDeviceReference = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('POST', {
      user: accessAdmin,
      csrf,
      body: { action: 'approve', userId: userA, deviceRef: 'a'.repeat(64) },
    }));
  assert.equal(stolenDeviceReference.statusCode, 409);
  assert.equal(fixture.store.records.get(`${userA}:${referenceHash}`).status, 'pending');

  const approvedByAdmin = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('POST', {
      user: accessAdmin,
      csrf,
      body: { action: 'approve', userId: userA, deviceRef: referenceHash },
    }));
  assert.equal(approvedByAdmin.statusCode, 200);
  assert.equal(approvedByAdmin.body.status, 'approved');
  assert.equal(approvedByAdmin.body.approvedBy, userAdmin);
  assert.ok(Date.parse(approvedByAdmin.body.approvedExpiresAt) > Date.now());
  assert.equal(fixture.store.calls.at(-1).actor, userAdmin);

  const approvedStatus = await fixture.invoke(fixture.handlers.deviceHandler,
    fixture.request('GET', { reference: deviceReference }));
  assert.deepEqual(approvedStatus.body, { status: 'approved', approved: true, pending: false });

  const copiedClientId = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('GET', {
      reference: Buffer.alloc(32, 9).toString('base64url'),
      headers: { 'x-device-id': deviceReference },
    }));
  assert.equal(copiedClientId.statusCode, 403);
  assert.equal(fixture.noteDbCalls.length, 0);

  const ownNotes = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('GET', { reference: deviceReference }));
  assert.equal(ownNotes.statusCode, 200);
  assert.deepEqual(ownNotes.body.notes.map(note => note.id), [noteA]);
  const otherOwnersNote = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('GET', { reference: deviceReference, id: noteB }));
  assert.equal(otherOwnersNote.statusCode, 404);
  assert.equal(fixture.noteDbCalls.length, 2);

  const revoked = await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('POST', {
    csrf, reference: deviceReference, body: { action: 'revoke' },
  }));
  assert.equal(revoked.statusCode, 200);
  assert.equal(revoked.body.status, 'revoked');
  const afterRevocation = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('GET', { reference: deviceReference }));
  assert.equal(afterRevocation.statusCode, 403);
  assert.equal(fixture.noteDbCalls.length, 2, 'revoked devices must not query protected notes');
});

test('device mutations require Origin and CSRF; client device IDs do not establish approval', async () => {
  const fixture = createFixture();
  const csrf = await fixture.csrfToken();
  const initial = await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('GET'));
  assert.equal(initial.statusCode, 200);

  const otherUserStatus = await fixture.invoke(fixture.handlers.deviceHandler,
    fixture.request('GET', { user: accessB, reference: deviceReference }));
  assert.equal(otherUserStatus.body.status, 'unregistered');

  for (const request of [
    fixture.request('POST', { reference: deviceReference, body: { action: 'request' } }),
    fixture.request('POST', { csrf, reference: deviceReference, body: { action: 'request' }, origin: 'https://attacker.example' }),
  ]) {
    const result = await fixture.invoke(fixture.handlers.deviceHandler, request);
    assert.equal(result.statusCode, 403);
  }

  const noReference = await fixture.invoke(fixture.handlers.deviceHandler,
    fixture.request('POST', { csrf, body: { action: 'request' }, headers: { 'x-device-id': 'approved-device' } }));
  assert.equal(noReference.statusCode, 400);
  assert.equal(noReference.body.error, 'DEVICE_REFERENCE_REQUIRED');

  for (const [body, headers, expectedStatus] of [
    ['{', { 'content-type': 'application/json' }, 400],
    ['x'.repeat(8193), { 'content-type': 'application/json' }, 413],
    [{ action: 'unknown' }, {}, 400],
  ]) {
    const result = await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('POST', {
      csrf,
      reference: deviceReference,
      body,
      headers,
    }));
    assert.equal(result.statusCode, expectedStatus);
  }
  const unsupported = await fixture.invoke(fixture.handlers.deviceHandler,
    fixture.request('PUT', { reference: deviceReference }));
  assert.equal(unsupported.statusCode, 405);
  assert.equal(fixture.store.calls.filter(call => call.operation !== 'get').length, 0);
});

test('admin approval API enforces CSRF, Origin, allowlist lookup, and transition validation', async () => {
  const fixture = createFixture();
  const csrf = await fixture.csrfToken();
  const hash = hashDeviceReference(deviceReference);
  await fixture.invoke(fixture.handlers.deviceHandler, fixture.request('POST', {
    csrf,
    reference: deviceReference,
    user: accessB,
    body: { action: 'request' },
  }));

  const invalidRequests = [
    [fixture.request('POST', {
      user: accessAdmin,
      reference: deviceReference,
      body: { action: 'approve', userId: userB, deviceRef: hash },
    }), 403],
    [fixture.request('POST', {
      user: accessAdmin,
      csrf,
      origin: 'https://attacker.example',
      body: { action: 'approve', userId: userB, deviceRef: hash },
    }), 403],
    [fixture.request('POST', {
      user: accessAdmin,
      csrf,
      body: { action: 'approve', userId: userB, deviceRef: hash, role: 'admin' },
    }), 400],
  ];
  for (const [request, expectedStatus] of invalidRequests) {
    const result = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler, request);
    assert.equal(result.statusCode, expectedStatus);
  }

  const expiredSession = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('GET', { user: 'expired-session' }));
  assert.equal(expiredSession.statusCode, 401);

  const failingAllowlist = createFixture({
    store: approvalStore({ adminLookupFailure: true }),
  });
  const failedLookup = await failingAllowlist.invoke(
    failingAllowlist.handlers.deviceApprovalAdminHandler,
    failingAllowlist.request('GET', { user: accessAdmin }),
  );
  assert.equal(failedLookup.statusCode, 503);
  assert.equal(failedLookup.body.error, 'DEVICE_APPROVAL_STORE_UNAVAILABLE');

  const unsupported = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('PATCH', { user: accessAdmin }));
  assert.equal(unsupported.statusCode, 405);

  const rejected = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('POST', {
      user: accessAdmin,
      csrf,
      body: { action: 'reject', userId: userB, deviceRef: hash },
    }));
  assert.equal(rejected.statusCode, 200);
  assert.equal(rejected.body.status, 'rejected');
  assert.equal(fixture.store.records.get(`${userB}:${hash}`).rejected_at !== undefined, true);
});

test('admin approval-store write failures never report approval success', async () => {
  const store = approvalStore();
  const referenceHash = hashDeviceReference(deviceReference);
  store.records.set(`${userA}:${referenceHash}`, {
    user_id: userA,
    device_ref: referenceHash,
    status: 'pending',
    requested_at: new Date().toISOString(),
  });
  store.setStatus = async () => {
    throw new Error('approval persistence unavailable');
  };
  const fixture = createFixture({ store });
  const csrf = await fixture.csrfToken();
  const result = await fixture.invoke(fixture.handlers.deviceApprovalAdminHandler,
    fixture.request('POST', {
      user: accessAdmin,
      csrf,
      body: { action: 'approve', userId: userA, deviceRef: referenceHash },
    }));
  assert.equal(result.statusCode, 503);
  assert.equal(result.body.error, 'DEVICE_APPROVAL_STORE_UNAVAILABLE');
  assert.equal(store.records.get(`${userA}:${referenceHash}`).status, 'pending');
});

test('approval-store failures fail closed before any note database access', async () => {
  const fixture = createFixture({ storeFailure: true });
  const reference = deviceReference;
  const result = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('GET', { reference }));
  assert.equal(result.statusCode, 503);
  assert.equal(result.body.error, 'DEVICE_STATUS_UNAVAILABLE');
  assert.equal(fixture.noteDbCalls.length, 0);
});

test('expired approval is denied by the protected notes handler', async () => {
  const fixture = createFixture();
  const referenceHash = hashDeviceReference(deviceReference);
  fixture.store.records.set(`${userA}:${referenceHash}`, {
    user_id: userA,
    device_ref: referenceHash,
    status: 'approved',
    approved_expires_at: new Date(Date.now() - 1).toISOString(),
  });
  const denied = await fixture.invoke(fixture.handlers.notesHandler,
    fixture.request('GET', { reference: deviceReference }));
  assert.equal(denied.statusCode, 403);
  assert.equal(denied.body.error, 'DEVICE_NOT_APPROVED');
  assert.equal(fixture.store.records.get(`${userA}:${referenceHash}`).status, 'expired');
  assert.equal(fixture.noteDbCalls.length, 0);
});

test('Supabase approval store persists state across store instances and fails closed on expiry', async () => {
  const rows = new Map();
  const baseTime = Date.now();
  let currentTime = baseTime;
  const clientFactory = () => ({
    from(table) {
      assert.equal(table, 'device_approvals');
      return new ApprovalQuery(rows);
    },
    async rpc(name, params) {
      assert.equal(name, 'request_device_approval');
      const key = `${params.p_user_id}:${params.p_device_ref}`;
      const current = rows.get(key);
      if (current?.status === 'approved' && Date.parse(current.approved_expires_at) > currentTime) {
        return { data: [current], error: null };
      }
      const pending = {
        user_id: params.p_user_id,
        device_ref: params.p_device_ref,
        status: 'pending',
        requested_at: new Date(currentTime).toISOString(),
        approved_by: null,
        approved_at: null,
        approved_expires_at: null,
        rejected_at: null,
        revoked_at: null,
      };
      rows.set(key, pending);
      return { data: [pending], error: null };
    },
  });
  const options = { env, clientFactory, now: () => currentTime };
  const referenceHash = hashDeviceReference(deviceReference);
  const first = createSupabaseDeviceApprovalStore(options);
  assert.equal((await first.request(userA, referenceHash)).status, 'pending');
  const afterRestart = createSupabaseDeviceApprovalStore(options);
  assert.equal((await afterRestart.get(userA, referenceHash)).status, 'pending');
  assert.equal((await afterRestart.setStatus(
    userA, referenceHash, 'approved', 'verified-operator', 'pending',
  )).status, 'approved');
  const approved = await createSupabaseDeviceApprovalStore(options).get(userA, referenceHash);
  assert.equal(approved.status, 'approved');
  assert.equal(approved.approved_by, 'verified-operator');
  currentTime = Date.parse(approved.approved_expires_at) + 1;
  assert.equal((await createSupabaseDeviceApprovalStore(options).get(userA, referenceHash)).status, 'expired');
  assert.equal((await createSupabaseDeviceApprovalStore(options).request(userA, referenceHash)).status, 'pending');
});

test('Supabase approval store reads active administrators and pending references server-side', async () => {
  const queries = [];
  const pendingRecord = {
    user_id: userA,
    device_ref: hashDeviceReference(deviceReference),
    status: 'pending',
    requested_at: new Date().toISOString(),
  };
  const clientFactory = () => ({
    from(table) {
      const query = { filters: {}, table };
      queries.push(query);
      return {
        select(columns) { query.columns = columns; return this; },
        eq(field, value) { query.filters[field] = value; return this; },
        order(field, options) { query.order = { field, ...options }; return this; },
        async maybeSingle() {
          return {
            data: query.filters.user_id === userAdmin ? { enabled: true } : { enabled: false },
            error: null,
          };
        },
        async limit(limit) {
          query.limit = limit;
          return { data: [pendingRecord], error: null };
        },
      };
    },
  });
  const store = createSupabaseDeviceApprovalStore({ env, clientFactory });
  assert.equal(await store.isAdmin(userAdmin), true);
  assert.equal(await store.isAdmin(userInactiveAdmin), false);
  assert.deepEqual(await store.listPending(), [pendingRecord]);
  assert.deepEqual(queries.map(query => query.table), [
    'device_approval_admins',
    'device_approval_admins',
    'device_approvals',
  ]);
  assert.equal(queries[0].filters.user_id, userAdmin);
  assert.equal(queries[2].filters.status, 'pending');
  assert.equal(queries[2].limit, 100);

  const failedStore = createSupabaseDeviceApprovalStore({
    env,
    clientFactory: () => ({
      from: () => ({
        select() { return this; },
        eq() { return this; },
        async maybeSingle() { return { data: null, error: new Error('database failure') }; },
      }),
    }),
  });
  await assert.rejects(failedStore.isAdmin(userAdmin), /DEVICE_APPROVAL_STORE_UNAVAILABLE/u);
});

test('device migration limits records to the service role and installs append-only audit logging', async () => {
  const migration = await readFile(new URL('../supabase/migrations/20261014000000_device_approvals.sql', import.meta.url), 'utf8');
  assert.match(migration, /create table if not exists public\.device_approvals/u);
  assert.match(migration, /create table if not exists public\.device_approval_events/u);
  assert.match(migration, /create table if not exists public\.device_approval_admins/u);
  assert.match(migration, /enable row level security/u);
  assert.match(migration, /revoke all privileges on public\.device_approval_events from public, anon, authenticated/u);
  assert.match(migration, /revoke all privileges on public\.device_approval_admins from public, anon, authenticated/u);
  assert.match(migration, /grant select on public\.device_approval_events to service_role/u);
  assert.match(migration, /grant select on public\.device_approval_admins to service_role/u);
  assert.match(migration, /create trigger device_approval_audit/u);
  assert.match(migration, /request_device_approval/u);
  const bootstrap = await readFile(new URL('../supabase/bootstrap/device_approval_admin.sql', import.meta.url), 'utf8');
  assert.match(bootstrap, /REPLACE_WITH_EXISTING_SUPABASE_AUTH_USER_UUID/u);
});
