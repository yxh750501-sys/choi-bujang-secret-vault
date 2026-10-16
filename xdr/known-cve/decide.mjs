// Copied from patterns.json. The isolated judge imports this file alone.
const PATTERNS = Object.freeze([
  { name: 'complete_log4shell_lookup',
    condition: 'T1190 경보의 요청 머리글 또는 URL 인자에 완전한 ${jndi:ldap://...}, ${jndi:ldaps://...}, ${jndi:rmi://...} 원격 조회 형태가 있고 출발 주소와 규칙 수준 10 이상이 확인됨',
    evidence: 'CVE-2021-44228과 MITRE ATT&CK T1190: Log4j가 기록하는 입력의 JNDI 원격 조회 형태는 공개 앱 악용 신호입니다.' },
  { name: 'possible_known_cve_probe',
    condition: 'T1190 경보 수준 5 이상에서 취약점 이름·불완전한 조회 표기·점검 도구 흔적이 보이지만 완전한 원격 조회 형태는 없음',
    evidence: 'CVE-2021-44228과 MITRE ATT&CK T1190: 취약점 이름 검색과 점검 도구 흔적만으로 악용을 확정할 수 없어 확인이 필요합니다.' },
]);

function validAddress(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part => /^(?:0|[1-9]\d{0,2})$/u.test(part)
    && Number(part) <= 255);
}

function decoded(value) {
  if (typeof value !== 'string') return '';
  const bounded = value.slice(0, 2048);
  try { return decodeURIComponent(bounded); } catch { return bounded; }
}

export function decide(alert) {
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const t1190 = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1190');
  const header = decoded(alert?.data?.useragent);
  const url = decoded(alert?.data?.url);
  const remoteLookup = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi):\/\/[^}\s]+\}/iu;
  const complete = remoteLookup.test(header) || remoteLookup.test(url);

  if (t1190 && level >= 10 && validAddress(alert?.data?.srcip) && complete) {
    return { action: 'block', confidence: Math.min(0.99, 0.87 + (level - 10) * 0.03),
      reason: PATTERNS[0].name };
  }
  if (t1190 && level >= 5) {
    return { action: 'alert', confidence: Math.min(0.84, 0.5 + Math.min(level, 10) * 0.02),
      reason: PATTERNS[1].name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_supported_known_cve_pattern' };
}
