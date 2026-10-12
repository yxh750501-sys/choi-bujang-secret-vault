// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('2단계 공격 점검은 aleph.config.json의 step이 2여야 합니다.');
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
  const response = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let safeEmptyResponse = response.status === 404 || response.status === 410;
  let notesExposed = false;
  if (response.ok) {
    try {
      const data = await response.json();
      const keys = Object.keys(data);
      notesExposed = Array.isArray(data?.notes) && data.notes.length > 0;
      safeEmptyResponse = Array.isArray(data?.notes) && data.notes.length === 0
        && keys.every(key => key === 'notes' || key === 'sampleMarker')
        && (data.sampleMarker === undefined || data.sampleMarker === config.sampleMarker);
    } catch {
      // An unparseable success response cannot confirm that notes are private.
    }
  }
  const observed = notesExposed
    ? '비로그인 요청에서 공개 메모가 노출됨'
    : safeEmptyResponse
      ? `비로그인 요청에서 공개 메모가 없음 (HTTP ${response.status})`
      : `비로그인 요청에서 안전한 빈 자료 응답을 확인하지 못함 (HTTP ${response.status})`;
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 요청에서 메모 0건 또는 404 응답', observed }];
}
