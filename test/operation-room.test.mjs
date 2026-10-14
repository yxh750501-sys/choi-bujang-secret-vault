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
  await handler({ method: 'GET', url: '/api/operations',
    headers: { cookie: `__Host-bb_access=local-fixture; __Host-bb_device_ref=${reference}` } }, response);
  assert.equal(response.statusCode, 200);
  assert.equal(response.getHeader('Cache-Control'), 'no-store');
  assert.equal(response.body.deviceApproval.status, 'approved');
  assert.equal(response.body.provenance.providedEngine, 'ALEPH SDP 엔진');
  assert.equal(response.body.sources.engine, 'ALEPH SDP 엔진');
  assert.ok(response.body.sources.student.includes('src/decider.mjs'));
  assert.ok(response.body.sources.student.includes('src/detect.mjs'));
  assert.deepEqual(response.body.verification.counts, operationReport('approved').verification.counts);
  assert.equal(response.body.verification.cases.length, 41);
  assert.equal(response.body.verification.counts.pass, 3);
  assert.equal(response.body.verification.counts.fail, 0);
  assert.equal(response.body.verification.counts.notRun, 38);
  assert.equal(response.body.recovery.source, 'local-handler-fixture');
  assert.equal(response.body.revocation.status, 'UNKNOWN');
  assert.equal(response.body.rules.status, 'NOT_RUN');
  assert.equal(response.body.detection.status, 'NOT_RUN');
  assert.equal(JSON.stringify(response.body).includes('local-fixture'), false);
  assert.ok(response.body.verification.cases.filter(item => item.status === 'PASS')
    .every(item => item.requestId && item.checkedAt && item.actual?.httpStatus));
});

test('미인증 작전실은 거부되고 미실행 항목은 PASS가 아니다', async () => {
  const handler = createDeviceHandler();
  const response = responseMock();
  await handler({ method: 'GET', url: '/api/operations', headers: {} }, response);
  assert.equal(response.statusCode, 401);
  assert.equal(response.body.error, 'AUTHENTICATION_REQUIRED');
  assert.equal(evidence.cases.length, 41);
  assert.deepEqual([...new Set(evidence.cases.map(item => item.stage))],
    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]);
  assert.ok(evidence.cases.every(item => item.kind && item.request && item.expected));
  const notRun = evidence.cases.filter(item => item.status === 'NOT_RUN');
  assert.equal(notRun.length, 38);
  assert.ok(notRun.every(item => item.actual === null
    && item.requestId === null && item.checkedAt === null));
  assert.ok(evidence.cases.filter(item => item.status === 'PASS').every(item =>
    item.actual && item.requestId && item.checkedAt && item.environment === 'local-handler'));
  const functions = (await readdir(new URL('../api/', import.meta.url), { recursive: true }))
    .filter(name => /\.js$/u.test(name));
  assert.equal(functions.length, 12);
});

test('작전실 조회는 새 기기 쿠키를 발급하지 않는다', async () => {
  const handler = createDeviceHandler({ env: { VERCEL: '1' },
    verifierFactory: () => async () => ({ kind: 'student', userId }),
    storeFactory: () => { throw new Error('store must not be queried'); },
  });
  const response = responseMock();
  await handler({ method: 'GET', url: '/api/operations',
    headers: { cookie: '__Host-bb_access=local-fixture' } }, response);
  assert.equal(response.statusCode, 200);
  assert.equal(response.body.deviceApproval.status, 'unregistered');
  assert.equal(response.getHeader('Set-Cookie'), undefined);
  assert.equal(JSON.stringify(response.body).includes('local-fixture'), false);
});

test('요청 ID나 응답 증거가 없으면 PASS를 공개하지 않는다', () => {
  const measuredCase = structuredClone(evidence.cases.find(item => item.status === 'PASS'));
  measuredCase.actual.cookie = 'must-never-appear';
  assert.equal(JSON.stringify(operationReport('approved', {
    commit: evidence.commit, cases: [measuredCase],
  })).includes('must-never-appear'), false);
  const caseItem = structuredClone(measuredCase);
  caseItem.requestId = null;
  caseItem.actual = { httpStatus: 200, cookie: 'must-never-appear' };
  const report = operationReport('approved', { commit: evidence.commit, cases: [caseItem] });
  assert.deepEqual(report.verification.counts, { pass: 0, fail: 0, notRun: 1 });
  assert.equal(report.verification.cases[0].actual, null);
  assert.equal(JSON.stringify(report).includes('must-never-appear'), false);
});
