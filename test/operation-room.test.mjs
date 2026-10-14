import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { test } from 'node:test';
import { createDeviceHandler } from '../api/device.js';
import { CHECKS, operationReport } from '../src/operation-room.mjs';

const userId = '123e4567-e89b-42d3-a456-426614174000';
const reference = Buffer.alloc(32, 4).toString('base64url');
const config = { publicAppUrl: 'https://student.example.test/' };

function responseMock() {
  const headers = new Map();
  return { statusCode: null, body: null,
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    getHeader(name) { return headers.get(name.toLowerCase()); },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; } };
}

test('41종 표는 실제 익명 GET 응답 3건만 측정하고 본문을 가린다', async () => {
  const calls = [];
  const report = await operationReport({ config, deviceStatus: 'approved',
    deployedCommit: 'a'.repeat(40), now: () => new Date('2026-10-15T00:00:00Z'),
    requestIdFactory: () => `request-${calls.length + 1}`,
    fetchImpl: async (url, options) => {
      calls.push({ url: String(url), options });
      if (String(url).endsWith('/aleph.json')) return { status: 200,
        json: async () => ({ step: 12, commit: 'a'.repeat(40), secret: 'must-not-appear' }) };
      return { status: 401, text: async () => 'private note and token' };
    } });
  assert.equal(CHECKS.length, 41);
  assert.deepEqual([...new Set(CHECKS.map(item => item[1]))],
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  assert.deepEqual(report.verification.counts, { pass: 3, fail: 0, notRun: 38 });
  assert.deepEqual(calls.map(item => new URL(item.url).pathname),
    ['/aleph.json', '/api/notes/00000000-0000-4000-8000-000000000001', '/api/notes']);
  assert.ok(calls.every(item => item.options.method === 'GET'
    && item.options.credentials === 'omit' && !item.options.headers.Cookie
    && !item.options.headers.Authorization));
  assert.ok(report.verification.cases.filter(item => item.status === 'PASS').every(item =>
    item.requestId && item.requestIdSource === 'operations-correlation-id'
      && item.checkedAt && item.actual?.httpStatus));
  assert.ok(report.verification.cases.filter(item => item.status === 'NOT_RUN').every(item =>
    item.actual === null && item.requestId === null && item.checkedAt === null));
  assert.equal(report.sources.engine, 'ALEPH SDP 엔진');
  assert.equal(report.detection.status, 'NOT_RUN');
  assert.equal(report.revocation.status, 'NOT_RUN');
  assert.equal(report.recovery.status, 'NOT_RUN');
  assert.equal(report.recovery.version, 'stage10-safe-policy-fixture-v1');
  assert.doesNotMatch(JSON.stringify(report), /must-not-appear|private note and token/u);
});

test('응답 실패는 미실행, 예상과 다른 실제 응답은 FAIL이다', async () => {
  const unavailable = await operationReport({ config, deviceStatus: 'approved',
    fetchImpl: async () => { throw new Error('network down'); } });
  assert.deepEqual(unavailable.verification.counts, { pass: 0, fail: 0, notRun: 41 });
  const mismatch = await operationReport({ config, deviceStatus: 'approved',
    fetchImpl: async () => ({ status: 200, json: async () => ({ step: 11 }) }) });
  assert.deepEqual(mismatch.verification.counts, { pass: 0, fail: 3, notRun: 38 });
});

test('작전실은 인증과 승인 기기를 요구하며 새 함수나 기기 쿠키를 만들지 않는다', async () => {
  let reports = 0;
  const handler = createDeviceHandler({ env: { VERCEL: '1' },
    verifierFactory: () => async () => ({ kind: 'student', userId }),
    storeFactory: () => ({ get: async () => ({ status: 'approved' }) }),
    operationReporter: async () => { reports += 1; return { schema: 'aleph.operations.v1' }; } });
  const anonymous = responseMock();
  await handler({ method: 'GET', url: '/api/operations', headers: {} }, anonymous);
  assert.equal(anonymous.statusCode, 401);
  const missingDevice = responseMock();
  await handler({ method: 'GET', url: '/api/operations',
    headers: { cookie: '__Host-bb_access=fixture' } }, missingDevice);
  assert.equal(missingDevice.statusCode, 403);
  const approved = responseMock();
  await handler({ method: 'GET', url: '/api/operations',
    headers: { cookie: `__Host-bb_access=fixture; __Host-bb_device_ref=${reference}` } }, approved);
  assert.equal(approved.statusCode, 200);
  assert.equal(approved.body.schema, 'aleph.operations.v1');
  assert.equal(approved.getHeader('Set-Cookie'), undefined);
  assert.equal(reports, 1);
  const functions = (await readdir(new URL('../api/', import.meta.url), { recursive: true }))
    .filter(name => /\.js$/u.test(name));
  assert.equal(functions.length, 12);
});
