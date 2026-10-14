// The isolated judge does not provide request evidence for these checks.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (![2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('2~12단계 공격 점검은 aleph.config.json의 step이 2~12이어야 합니다.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const checks = [{
    attackId: 'anonymous_note_read',
    expected: '비로그인 요청에서 메모 0건 또는 404 응답',
    observed: 'not_run',
  }];
  if (config.step >= 3) checks.push({
    attackId: 'anonymous_notes_api',
    expected: '비로그인 API 요청에서 메모 없이 구조화된 JSON 401 또는 403',
    observed: 'not_run',
  });
  return checks;
}
