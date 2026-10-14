import { randomUUID } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import notesHandler from '../api/notes.js';
import { createRestoreHandler } from '../api/restore.js';
import { createDeviceHandler } from '../api/device.js';

const root = resolve(import.meta.dirname, '..');
const commit = execFileSync('git', ['-C', root, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
const noteId = '623e4567-e89b-42d3-a456-000000000001';
const ownerId = '723e4567-e89b-42d3-a456-000000000001';
// Each row names a concrete 1~11단계 request or check. Only executed rows gain evidence.
const definitions = [
  ['s01_shell', 1, 'normal', '공개 앱 화면', 'GET /', 'HTTP 200'],
  ['s01_public_sample', 1, 'normal', '공개 가상 자료', 'GET /data.json', '메모 0건 또는 404'],
  ['s02_anonymous_note', 2, 'forbidden', '익명 메모 읽기', 'GET /api/notes/:id', 'HTTP 401 또는 403'],
  ['s02_static_copy', 2, 'forbidden', '정적 메모 사본', 'GET /data.json', '비공개 메모 0건'],
  ['s03_login', 3, 'normal', '정상 로그인', 'POST /api/auth', '검증된 세션 발급'],
  ['s03_anonymous_notes', 3, 'forbidden', '익명 메모 목록', 'GET /api/notes', 'HTTP 401 AUTHENTICATION_REQUIRED'],
  ['s03_logout', 3, 'normal', '로그아웃', 'POST /api/auth logout', '세션 쿠키 제거'],
  ['s03_bad_login', 3, 'forbidden', '잘못된 로그인', 'POST /api/auth', '인증 거부'],
  ['s04_session', 4, 'normal', '유효한 세션 조회', 'GET /api/auth', '인증된 세션'],
  ['s04_csrf', 4, 'forbidden', 'CSRF 없는 변경', 'POST /api/notes', 'HTTP 403'],
  ['s04_expired', 4, 'forbidden', '만료된 세션', 'GET /api/notes', 'HTTP 401'],
  ['s04_origin', 4, 'forbidden', '잘못된 Origin', 'POST /api/notes', 'HTTP 403'],
  ['s05_own_list', 5, 'normal', '소유 메모 목록', 'GET /api/notes', '본인 메모만 반환'],
  ['s05_own_read', 5, 'normal', '소유 메모 읽기', 'GET /api/notes/:id', '본인 메모만 반환'],
  ['s05_cross_read', 5, 'forbidden', '타인 메모 읽기', 'GET /api/notes/:id', 'HTTP 404'],
  ['s05_cross_write', 5, 'forbidden', '타인 메모 수정', 'PUT /api/notes/:id', 'HTTP 404'],
  ['s05_cross_delete', 5, 'forbidden', '타인 메모 삭제', 'DELETE /api/notes/:id', 'HTTP 404'],
  ['s06_approved_device', 6, 'normal', '승인 기기 접근', 'GET /api/notes', '승인 상태에서 허용'],
  ['s06_pending_device', 6, 'forbidden', '승인 대기 기기', 'GET /api/notes', '접근 거부'],
  ['s06_revoked_device', 6, 'forbidden', '승인 취소 기기', 'GET /api/notes', '접근 거부'],
  ['s06_forged_device', 6, 'forbidden', '위조 기기 주장', 'GET /api/notes', '접근 거부'],
  ['s07_normal_decision', 7, 'normal', '정상 가상 판정', 'decide 정상 요청', 'allow'],
  ['s07_risk_step_up', 7, 'forbidden', '복합 위험 가상 판정', 'decide 복합 이상 요청', 'step_up'],
  ['s07_unverified_step_up', 7, 'forbidden', '미확인 추가 인증', 'decide 미확인 복합 이상 요청', 'step_up'],
  ['s08_note_route', 8, 'normal', '허용 메모 경로', 'GET /notes/:id', 'allow'],
  ['s08_query', 8, 'forbidden', '추가 쿼리 경로', 'GET /notes/:id?query', 'deny'],
  ['s08_write', 8, 'forbidden', '쓰기 경로 판정', 'PUT /notes/:id', 'deny'],
  ['s08_prefix', 8, 'forbidden', '상위 경로 판정', 'GET /notes/..', 'deny'],
  ['s08_unknown', 8, 'forbidden', '미등록 서비스', 'GET /unknown', 'deny'],
  ['s09_below_threshold', 9, 'normal', '임계값 아래 사건', 'detect 정상 읽기 사건', 'observe'],
  ['s09_over_threshold', 9, 'forbidden', '과다 읽기 사건', 'detect 연속 읽기 사건', '회수 제안'],
  ['s09_mixed_subjects', 9, 'normal', '주체 분리 사건', 'detect 다른 주체 사건', '주체별 집계'],
  ['s09_no_events', 9, 'normal', '사건 없는 입력', 'detect 빈 사건', '회수 없음'],
  ['s10_restore_preview', 10, 'normal', '가상 복구 미리보기', 'POST /api/restore preview', 'HTTP 200 preview, 재시험 NOT_RUN'],
  ['s10_restore_apply', 10, 'normal', '가상 메모 복구', 'POST /api/restore restore', '검증된 가상 메모만 복구'],
  ['s10_wrong_owner', 10, 'forbidden', '다른 주체 복구', 'POST /api/restore', '접근 거부'],
  ['s10_missing_backup', 10, 'forbidden', '사본 없는 복구', 'POST /api/restore', '복구 거부'],
  ['s11_pwa_shell', 11, 'normal', 'PWA 공개 화면', 'GET /manifest.webmanifest', '공개 manifest'],
  ['s11_anonymous_device', 11, 'forbidden', '익명 작전실 접근', 'GET /api/operations', 'HTTP 401 AUTHENTICATION_REQUIRED'],
  ['s11_admin_forbidden', 11, 'forbidden', '일반 학생의 관리자 승인', 'POST /api/device-approval', '승인 거부'],
  ['s11_offline_api', 11, 'forbidden', '오프라인 보호 자료', 'GET /api/notes offline', '보호 응답 캐시 없음'],
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

const cases = definitions.map(([id, stage, kind, name, request, expected]) => ({
  id, stage, kind, name, request, expected, actual: null,
  requestId: null, checkedAt: null, environment: null, status: 'NOT_RUN',
}));
if (cases.length !== 41 || new Set(cases.map(item => item.id)).size !== 41) {
  throw new Error('1~11단계 검증표는 중복 없는 41종이어야 합니다.');
}

async function check(id, handler, request, expectedStatus, expectedError = null) {
  const row = cases.find(item => item.id === id);
  const requestId = randomUUID();
  request.headers = { ...request.headers, 'x-request-id': requestId };
  const response = responseMock();
  try {
    await handler(request, response);
    const error = typeof response.body?.error === 'string' ? response.body.error : null;
    row.actual = { httpStatus: response.statusCode, error };
    if (id === 's10_restore_preview' && response.statusCode === 200) {
      row.actual.action = response.body?.action ?? null;
      row.actual.policyVersion = response.body?.policyVersion ?? null;
      row.actual.retests = response.body?.postRestoreRetests?.status ?? null;
    }
    row.status = response.statusCode === expectedStatus && error === expectedError ? 'PASS' : 'FAIL';
  } catch {
    row.actual = { error: 'HANDLER_EXCEPTION' };
    row.status = 'FAIL';
  }
  row.requestId = request.headers['x-request-id'];
  row.checkedAt = new Date().toISOString();
  row.environment = 'local-handler';
}

await check('s03_anonymous_notes', notesHandler,
  { method: 'GET', url: '/api/notes', headers: {} }, 401, 'AUTHENTICATION_REQUIRED');
await check('s10_restore_preview', createRestoreHandler({
  verifyAuthorization: async () => ({ kind: 'judge', identity: 'b', userId: ownerId,
    runId: 'stage12-local-preview' }),
}), { method: 'POST', url: '/api/restore', headers: { authorization: 'Bearer x',
  'content-type': 'application/json' }, body: { action: 'preview', noteId } }, 200);
await check('s11_anonymous_device', createDeviceHandler(),
  { method: 'GET', url: '/api/operations', headers: {} }, 401, 'AUTHENTICATION_REQUIRED');

const evidence = { schema: 'byteback.verification.v1', commit, cases };
await writeFile(resolve(root, 'src/verification-records.json'),
  `${JSON.stringify(evidence, null, 2)}\n`, 'utf8');
const counts = { pass: cases.filter(item => item.status === 'PASS').length,
  fail: cases.filter(item => item.status === 'FAIL').length,
  notRun: cases.filter(item => item.status === 'NOT_RUN').length };
process.stdout.write(`41종 로컬 API 핸들러 실측: ${JSON.stringify(counts)}\n`);
if (counts.fail) process.exitCode = 1;
