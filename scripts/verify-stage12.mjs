import { randomUUID } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import notesHandler from '../api/notes.js';
import { createRestoreHandler } from '../api/restore.js';
import { createDeviceHandler } from '../api/device.js';

const root = resolve(import.meta.dirname, '..');
const commit = '1e06d42f4abb69cad677c159af536d8aa9732553';
const noteId = '623e4567-e89b-42d3-a456-000000000001';
const ownerId = '723e4567-e89b-42d3-a456-000000000001';
const stageNames = [
  '공개 자료 분리', '익명 메모 노출 차단', '인증', '세션과 CSRF', '메모 소유권',
  '등록 기기', '추가 확인', '자원 경계', '탐지 사건', '가상 복구', '관리자 기기 승인',
];

function responseMock() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    getHeader(key) { return this.headers[key.toLowerCase()]; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

const cases = [];
for (let stage = 1; stage <= 11; stage += 1) {
  for (const kind of ['normal', 'forbidden']) {
    cases.push({ id: `stage${stage}_${kind}`, stage,
      name: `${stage}단계 ${stageNames[stage - 1]} ${kind === 'normal' ? '정상' : '금지'} 요청`,
      expected: kind === 'normal' ? '허용' : '거부', actual: null,
      requestId: null, checkedAt: null, environment: null, status: 'NOT_RUN' });
  }
}
for (let number = 1; number <= 41; number += 1) {
  cases.push({ id: `attack_${String(number).padStart(2, '0')}`, stage: null,
    name: `공격 시험 ${number}`, expected: '안전한 거부', actual: null,
    requestId: null, checkedAt: null, environment: null, status: 'NOT_RUN' });
}

async function check(id, handler, request, expectedStatus, expectedError = null) {
  const row = cases.find(item => item.id === id);
  const requestId = randomUUID();
  const response = responseMock();
  try {
    await handler(request, response);
    const error = typeof response.body?.error === 'string' ? response.body.error : null;
    row.actual = { httpStatus: response.statusCode, error };
    if (id === 'stage10_normal' && response.statusCode === 200) {
      row.actual.action = response.body?.action ?? null;
      row.actual.policyVersion = response.body?.policyVersion ?? null;
      row.actual.retests = response.body?.postRestoreRetests?.status ?? null;
    }
    row.status = response.statusCode === expectedStatus && error === expectedError ? 'PASS' : 'FAIL';
  } catch {
    row.actual = { error: 'HANDLER_EXCEPTION' };
    row.status = 'FAIL';
  }
  row.requestId = requestId;
  row.checkedAt = new Date().toISOString();
  row.environment = 'local-handler';
}

await check('stage3_forbidden', notesHandler,
  { method: 'GET', headers: {} }, 401, 'AUTHENTICATION_REQUIRED');
cases.find(item => item.id === 'stage3_forbidden').expected = 'HTTP 401 AUTHENTICATION_REQUIRED';
await check('stage10_normal', createRestoreHandler({
  verifyAuthorization: async () => ({ kind: 'judge', identity: 'b', userId: ownerId,
    runId: 'stage12-local-preview' }),
}), { method: 'POST', headers: { authorization: 'Bearer x',
  'content-type': 'application/json' }, body: { action: 'preview', noteId } }, 200);
cases.find(item => item.id === 'stage10_normal').id = 'stage10_restore_preview';
cases.find(item => item.id === 'stage10_restore_preview').expected = 'HTTP 200 preview, 재시험 NOT_RUN';
await check('stage11_forbidden', createDeviceHandler(),
  { method: 'GET', headers: {} }, 401, 'AUTHENTICATION_REQUIRED');
cases.find(item => item.id === 'stage11_forbidden').expected = 'HTTP 401 AUTHENTICATION_REQUIRED';

const evidence = { schema: 'byteback.verification.v1', commit, cases };
await writeFile(resolve(root, 'src/verification-records.json'),
  `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
const counts = { pass: cases.filter(item => item.status === 'PASS').length,
  fail: cases.filter(item => item.status === 'FAIL').length,
  notRun: cases.filter(item => item.status === 'NOT_RUN').length };
process.stdout.write(`로컬 API 핸들러 실측: ${JSON.stringify(counts)}; 공격 시험 41건은 NOT_RUN\n`);
if (counts.fail) process.exitCode = 1;
