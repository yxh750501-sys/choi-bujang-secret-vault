import assert from 'node:assert/strict';
import { readdir } from 'node:fs/promises';
import { test } from 'node:test';
import { createDeviceHandler } from '../api/device.js';
import { operationReport } from '../src/operation-room.mjs';
import evidence from '../src/verification-records.json' with { type: 'json' };

const userId = '123e4567-e89b-42d3-a456-426614174000';
const reference = Buffer.alloc(32, 4).toString('base64url');

function responseMock() {
  const headers = new Map();
  return {
    statusCode: null, body: null,
    setHeader(name, value) { headers.set(name.toLowerCase(), value); },
    getHeader(name) { return headers.get(name.toLowerCase()); },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

test('작전실 API 수치는 검증 기록과 같고 현재 기기 상태는 저장소 응답이다', async () => {
  const handler = createDeviceHandler({
    env: { VERCEL: '1' },
    verifierFactory: () => async () => ({ kind: 'student', userId }),
    storeFactory: () => ({ get: async () => ({ status: 'approved' }) }),
  });
  const response = responseMock();
  await handler({ method: 'GET', query: { view: 'operation' },
    headers: { cookie: `__Host-bb_access=local-fixture; __Host-bb_device_ref=${reference}` } }, response);
  assert.equal(response.statusCode, 200);
  assert.equal(response.getHeader('Cache-Control'), 'no-store');
  assert.equal(response.body.deviceApproval.status, 'approved');
  assert.deepEqual(response.body.verification.counts, operationReport('approved').verification.counts);
  assert.equal(response.body.verification.cases.length, 63);
  assert.equal(response.body.verification.counts.pass, 3);
  assert.equal(response.body.verification.counts.fail, 0);
  assert.equal(response.body.verification.counts.notRun, 60);
  assert.equal(response.body.recovery.source, 'local-handler-fixture');
  assert.equal(response.body.revocation.status, 'UNKNOWN');
  assert.equal(response.body.rules.status, 'NOT_RUN');
  assert.equal(response.body.detection.status, 'NOT_RUN');
  assert.equal(JSON.stringify(response.body).includes('local-fixture'), false);
});

test('미인증 작전실은 거부되고 미실행 41건은 PASS가 아니다', async () => {
  const handler = createDeviceHandler();
  const response = responseMock();
  await handler({ method: 'GET', query: { view: 'operation' }, headers: {} }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(response.body.error, 'AUTHENTICATION_REQUIRED');
  const attacks = evidence.cases.filter(item => item.id.startsWith('attack_'));
  assert.equal(attacks.length, 41);
  assert.ok(attacks.every(item => item.status === 'NOT_RUN' && item.actual === null
    && item.requestId === null && item.checkedAt === null));
  assert.ok(evidence.cases.filter(item => item.status === 'PASS').every(item =>
    item.actual && item.requestId && item.checkedAt && item.environment === 'local-handler'));
  const functions = (await readdir(new URL('../api/', import.meta.url), { recursive: true }))
    .filter(name => /\.js$/u.test(name));
  assert.equal(functions.length, 12);
});
