import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';

const START = Date.UTC(2026, 9, 1, 0, 0, 0);
const subject = 'learner_fixture';

function reads(count, { intervalMilliseconds = 2000, owner = subject, start = START } = {}) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(start + index * intervalMilliseconds).toISOString(),
    method: 'GET', identity: { sub: owner },
  }));
}

const oneMillisecondOutsideWindow = Array.from({ length: 121 }, (_, index) => ({
  at: new Date(START + Math.floor(index * 600001 / 120)).toISOString(),
  method: 'GET', identity: { sub: subject },
}));

const cases = [
  { name: '정상 조회 30건', events: reads(30), expected: { action: 'observe' } },
  { name: '10분 안에 120건', events: reads(120), expected: { action: 'observe' } },
  { name: '10분 안에 121건', events: reads(121), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '정확히 10분 경계의 121건', events: reads(121,
    { intervalMilliseconds: 5000 }), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '10분 경계를 1밀리초 넘는 121건', events: oneMillisecondOutsideWindow,
    expected: { action: 'observe' } },
  { name: '폭주 조회 200건', events: reads(200), expected: {
    action: 'propose_revocation', reasonCode: 'burst_read', subject } },
  { name: '서로 다른 사용자 각 100건', events: [...reads(100),
    ...reads(100, { owner: 'other_fixture' })].sort((a, b) => a.at.localeCompare(b.at)),
  expected: { action: 'observe' } },
  { name: '10분 밖으로 흩어진 조회 200건', events: reads(200,
    { intervalMilliseconds: 7000 }), expected: { action: 'observe' } },
  { name: '잘못된 사건은 조회 수에 포함하지 않음', events: [
    ...reads(120),
    null,
    [],
    { at: 'invalid-time', method: 'GET', identity: { sub: subject } },
    { at: '2026-02-30T00:00:00.000Z', method: 'GET', identity: { sub: subject } },
    { at: new Date(START).toISOString(), method: 'POST', identity: { sub: subject } },
    { at: new Date(START).toISOString(), method: 'GET', identity: { sub: '   ' } },
  ], expected: { action: 'observe' } },
];

// This is a practice contract, not a live engine assertion or judge score.
export async function checkDetection(detect) {
  if (typeof detect !== 'function') throw new TypeError('src/detect.mjs에서 detect 함수를 내보내야 합니다.');
  const results = [];
  let rejectedNonArray = false;
  try {
    await detect(null);
  } catch (error) {
    rejectedNonArray = error instanceof TypeError
      && error.message === 'invalid_detection_events';
  }
  results.push({ name: '배열이 아닌 입력 거부', passed: rejectedNonArray });
  for (const item of cases) {
    const actual = await detect(item.events);
    const passed = isDeepStrictEqual(actual, item.expected);
    results.push({ name: item.name, passed: Boolean(passed) });
  }
  return results;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const { detect } = await import('../src/detect.mjs');
    const results = await checkDetection(detect);
    for (const item of results) process.stdout.write(`${item.passed ? '통과' : '확인 필요'} · ${item.name}\n`);
    process.stdout.write('가상 사건 연습이며 실제 접속 회수나 심판 통과 증거가 아닙니다.\n');
    if (results.some(item => !item.passed)) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(`탐지 연습 첫 오류: ${error.message}\n`);
    process.exitCode = 1;
  }
}
