// 제출 격리 환경에서 요청 기록을 확인할 수 없는 점검은 성공을 계산하지 않고 미실행으로 남깁니다.
export async function runAttackChecks(config) {
  const app = new URL(config.publicAppUrl);
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('실제 배포 주소가 필요합니다.');
  }
  return [
    { attackId: 'static_note_read', expected: '정적 메모 0건', observed: 'not_run' },
    { attackId: 'anonymous_list', expected: '무로그인 목록 조회 401 또는 403', observed: 'not_run' },
    { attackId: 'anonymous_get', expected: '무로그인 개별 조회 401 또는 403', observed: 'not_run' },
  ];
}
