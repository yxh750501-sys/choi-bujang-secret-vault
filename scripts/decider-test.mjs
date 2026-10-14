import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureRequests } from './fixture-7.mjs';

const RESPONSE_KEYS = 'decision,reasonCode,requestId,ruleIds,schema';

function validResponse(request, response, ruleIds) {
  return response && typeof response === 'object' && !Array.isArray(response)
    && Object.keys(response).sort().join(',') === RESPONSE_KEYS
    && response.schema === 'aleph.decision.v1'
    && response.requestId === request.requestId
    && ['allow', 'deny', 'step_up'].includes(response.decision)
    && typeof response.reasonCode === 'string'
    && /^[a-z][a-z0-9_]{0,63}$/u.test(response.reasonCode)
    && Array.isArray(response.ruleIds) && response.ruleIds.length > 0
    && response.ruleIds.every(id => ruleIds.includes(id))
    && ruleIds.includes('device_registered');
}

// Local practice only. The class engine and the server judge validate live requests separately.
export async function checkDecider({ decide, ruleIds }) {
  if (typeof decide !== 'function' || !Array.isArray(ruleIds)
      || !ruleIds.includes('device_registered')) {
    throw new Error('device_registered 규칙을 먼저 구현하고 RULE_IDS에 적어 주세요.');
  }
  const { normal, suspicious } = fixtureRequests();
  const checks = [
    { name: '등록 기기의 정상 요청', request: normal, decision: 'allow', reasonCode: 'approved' },
    { name: '미등록 기기의 가상 요청', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: false }, decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '등록 정보 누락', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: undefined }, decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '등록 정보 null', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: null }, decision: 'deny', reasonCode: 'device_not_registered' },
    { name: '잘못된 등록 정보 타입', request: { ...normal, requestId: randomUUID(),
      deviceRegistered: 'true' }, decision: 'deny', reasonCode: 'device_not_registered' },
  ];
  if (ruleIds.includes('step_up_required')) {
    checks.push(
      { name: '복합 이상 접속', request: suspicious, decision: 'step_up',
        reasonCode: 'step_up_required' },
      { name: '지역 정보만 다른 접속', request: { ...normal, requestId: randomUUID(),
        signals: { ...normal.signals, region: 'foreign' } },
      decision: 'allow', reasonCode: 'approved' },
      { name: '검증 출처가 없는 이상 신호', request: { ...suspicious,
        requestId: randomUUID(), signals: { ...suspicious.signals, source: 'none' } },
      decision: 'allow', reasonCode: 'approved' },
      { name: '대량 조회가 없는 이상 신호', request: { ...suspicious,
        requestId: randomUUID(), recentEvents: [{ kind: 'risk_signal',
          ageSeconds: 60, count: 1 }] },
      decision: 'allow', reasonCode: 'approved' },
      { name: '추가 인증이 있어도 미등록 기기는 거부', request: { ...suspicious,
        requestId: randomUUID(), deviceRegistered: false,
        stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'deny', reasonCode: 'device_not_registered' },
      { name: '다시 확인한 복합 이상 접속', request: { ...suspicious,
        requestId: randomUUID(), stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'allow', reasonCode: 'approved' },
      { name: '재인증 시각 0초', request: { ...suspicious, requestId: randomUUID(),
        stepUp: { verified: true, authAgeSeconds: 0 } },
      decision: 'allow', reasonCode: 'approved' },
      { name: '재인증 시각 900초', request: { ...suspicious, requestId: randomUUID(),
        stepUp: { verified: true, authAgeSeconds: 900 } },
      decision: 'allow', reasonCode: 'approved' },
    );
    for (const [name, authAgeSeconds] of [
      ['null', null],
      ['undefined', undefined],
      ['NaN', Number.NaN],
      ['Infinity', Number.POSITIVE_INFINITY],
      ['문자열', '60'],
      ['음수', -1],
      ['900초 초과', 901],
    ]) {
      checks.push({
        name: `잘못된 재인증 시각 ${name}`,
        request: { ...suspicious, requestId: randomUUID(),
          stepUp: { verified: true, authAgeSeconds } },
        decision: 'step_up',
        reasonCode: 'step_up_required',
      });
    }
  }
  const results = [];
  for (const item of checks) {
    const response = await decide(item.request);
    const valid = validResponse(item.request, response, ruleIds)
      && response.decision === item.decision
      && response.reasonCode === item.reasonCode;
    results.push({ name: item.name, passed: valid });
  }
  const resourceRequests = [
      { name: '개별 메모의 비 UUID 경로 허용', request: { ...normal, path: '/notes/fictional-id' },
        decision: 'allow', reasonCode: 'approved' },
      { name: '메모 전체 목록 거부', request: { ...normal, path: '/notes', route: 'GET /notes' },
        decision: 'deny', reasonCode: 'resource_access_denied' },
      { name: '메모 ID 누락 거부', request: { ...normal, path: '/notes/', route: 'GET /notes/:id' },
        decision: 'deny', reasonCode: 'resource_access_denied' },
      { name: '추가 경로 구간 거부', request: { ...normal, path: '/notes/demo/export' },
        decision: 'deny', reasonCode: 'resource_access_denied' },
      { name: '인코딩 경로 구간 거부', request: { ...normal, path: '/notes/demo%2Fexport' },
        decision: 'deny', reasonCode: 'resource_access_denied' },
      ...['POST', 'PUT', 'PATCH', 'DELETE'].map(method => ({
        name: `메모 ${method} 쓰기 거부`,
        request: { ...normal, method },
        decision: 'deny',
        reasonCode: 'resource_access_denied',
      })),
      { name: '다른 route 이름 거부', request: { ...normal, route: 'GET /notes/:other' },
        decision: 'deny', reasonCode: 'resource_access_denied' },
      { name: '쿼리 선택 요청 거부', request: { ...normal, queryLength: 6 },
        decision: 'deny', reasonCode: 'resource_access_denied' },
      { name: '반 공지 계약 미정 경로 거부', request: { ...normal, service: 'announcements',
        path: '/announcements', route: 'GET /announcements' },
      decision: 'deny', reasonCode: 'resource_access_denied' },
      { name: '강사 자료 경로 거부', request: { ...normal, service: 'materials',
        path: '/materials/lesson', route: 'GET /materials/:id' },
      decision: 'deny', reasonCode: 'resource_access_denied' },
      { name: '추가 인증으로 자원 거부 우회 불가', request: { ...normal, path: '/notes',
        route: 'GET /notes', stepUp: { verified: true, authAgeSeconds: 60 } },
      decision: 'deny', reasonCode: 'resource_access_denied' },
  ];
  for (const item of resourceRequests) {
    const response = await decide(item.request);
    results.push({
      name: item.name,
      passed: validResponse(item.request, response, ruleIds)
        && response.decision === item.decision
        && response.reasonCode === item.reasonCode
        && (item.decision !== 'deny' || response.ruleIds.includes('resource_boundary')),
    });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { decide, RULE_IDS } = await import('../src/decider.mjs');
    const results = await checkDecider({ decide, ruleIds: RULE_IDS });
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('이 명령은 가상 요청으로 연습하며 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`판정기 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
