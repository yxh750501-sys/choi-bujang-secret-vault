// Copied from patterns.json. The isolated judge imports this file alone.
const PATTERNS = Object.freeze([
  { name: 'repeated_sql_injection',
    condition: 'T1190 경보에서 요청 인자에 SQL 결합·비교·명령 구분 구문이 있고 같은 출발 주소의 시도가 8회 이상 반복되며 규칙 수준이 10 이상',
    evidence: 'MITRE ATT&CK T1190: 공개 웹 앱의 SQL 주입 구문은 입력을 쿼리로 해석시키는 악용 신호입니다.' },
  { name: 'repeated_script_injection',
    condition: 'T1190 경보에서 스크립트 태그·실행 속성 표기가 있고 같은 출발 주소의 시도가 8회 이상 반복되며 규칙 수준이 10 이상',
    evidence: 'MITRE ATT&CK T1190: 공개 웹 앱 입력의 스크립트 실행 표기는 주입 악용 신호입니다.' },
  { name: 'repeated_path_traversal',
    condition: 'T1190 경보에서 ../ 경로 이탈 표기가 여러 단계 있고 같은 출발 주소의 시도가 8회 이상 반복되며 규칙 수준이 10 이상',
    evidence: 'MITRE ATT&CK T1190: 공개 웹 앱 입력의 반복 경로 이탈은 허용 경계 밖 파일 접근 시도 신호입니다.' },
  { name: 'possible_web_injection',
    condition: 'T1190 경보 수준이 5 이상이지만 반복 주입의 차단 조건을 충족하지 못함',
    evidence: 'MITRE ATT&CK T1190: 단발성 웹 입력 이상은 정상 검색어와 구별할 추가 확인이 필요합니다.' },
]);

function validAddress(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part => /^(?:0|[1-9]\d{0,2})$/u.test(part)
    && Number(part) <= 255);
}

function countOf(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return 0;
  const text = String(value);
  return /^(?:0|[1-9]\d{0,5})$/u.test(text) ? Number(text) : 0;
}

export function decide(alert) {
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const t1190 = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  const count = countOf(alert?.data?.count);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const rawUrl = typeof alert?.data?.url === 'string' ? alert.data.url.slice(0, 2048) : '';
  let url = rawUrl;
  try { url = decodeURIComponent(rawUrl); } catch { /* malformed encoding is not evidence */ }

  const sql = /\bunion\s+(?:all\s+)?select\b|['"]\s*(?:or|and)\s+['"\w\d]+\s*=|;\s*(?:select|drop|insert|update|delete)\b/iu.test(url)
    || /SQL 구문|SQL 표식|데이터베이스 조회를 이어 붙|명령 구분자/u.test(description);
  const script = /<\s*script\b|javascript\s*:|\bon(?:error|load|click)\s*=/iu.test(url)
    || /스크립트 삽입|스크립트 표식/u.test(description);
  const traversal = /(?:\.\.[/\\]){2,}/u.test(url)
    || /경로를 여러 단계 거슬러|경로 이탈 표기/u.test(description);

  if (t1190 && validAddress(alert?.data?.srcip) && level >= 10 && count >= 8) {
    const pattern = sql ? PATTERNS[0] : script ? PATTERNS[1] : traversal ? PATTERNS[2] : null;
    if (pattern) return { action: 'block', confidence: Math.min(0.99, 0.86 + count / 1000 + (level - 10) * 0.02), reason: pattern.name };
  }
  if (t1190 && level >= 5) {
    return { action: 'alert', confidence: Math.min(0.84, 0.5 + Math.min(level, 10) * 0.01 + Math.min(count, 8) * 0.01), reason: PATTERNS[3].name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_supported_web_injection_pattern' };
}
