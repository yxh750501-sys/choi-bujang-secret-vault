// Copied from patterns.json. This file runs alone in the isolated judge.
const PATTERNS = Object.freeze([
  { name: 'rapid_source_failures',
    condition: 'T1110 경보에서 한 출발 주소의 짧은 시간 로그인 실패가 20건 이상이고 규칙 수준이 10 이상',
    evidence: 'MITRE ATT&CK T1110: 짧은 시간에 반복되는 인증 실패는 무차별 대입 신호입니다.' },
  { name: 'multi_account_spray',
    condition: 'T1110 경보에서 같은 주소가 여러 계정을 시도하고 15건 이상 실패하거나 8계정 이상을 시도하며 규칙 수준이 10 이상',
    evidence: 'MITRE ATT&CK T1110: 여러 계정에 비밀번호를 반복 대입하는 방식은 password spraying입니다.' },
  { name: 'limited_login_failures',
    condition: 'T1110 경보에 로그인 실패가 3건 이상 있으나 차단 기준보다 약한 경우',
    evidence: 'MITRE ATT&CK T1110: 소수의 실패는 공격 신호일 수 있으나 정상 사용자의 오입력과 구별해야 합니다.' },
]);

function countOf(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return 0;
  const text = String(value);
  return /^(?:0|[1-9]\d{0,5})$/u.test(text) ? Number(text) : 0;
}

function accountCount(value) {
  const accounts = Array.isArray(value) ? value : typeof value === 'string' ? value.split(',') : [];
  return new Set(accounts.filter(item => typeof item === 'string' && item.trim()).map(item => item.trim())).size;
}

export function decide(alert) {
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const count = countOf(alert?.data?.count);
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const source = alert?.data?.srcip;
  const parts = typeof source === 'string' ? source.split('.') : [];
  const hasSource = parts.length === 4 && parts.every(part => /^(?:0|[1-9]\d{0,2})$/u.test(part)
    && Number(part) <= 255);
  const t1110 = Array.isArray(alert?.rule?.mitre) && alert.rule.mitre.includes('T1110');
  const accounts = accountCount(alert?.data?.accounts);
  const spraying = accounts >= 8 || /여러 계정|계정 이름을 바꿔|계정\s*\d+개|서로 다른 계정/u.test(description);
  const failed = /로그인 실패|실패|비밀번호.*바꿔 넣/u.test(description);

  if (t1110 && hasSource && level >= 10 && (failed || accounts >= 8)
      && (count >= 20 || (spraying && (count >= 15 || accounts >= 8)))) {
    return { action: 'block', confidence: Math.min(0.99,
      0.86 + Math.min(count, 100) / 1000 + Math.min(level - 10, 3) * 0.02),
    reason: count >= 20 ? PATTERNS[0].name : PATTERNS[1].name };
  }
  if (t1110 && hasSource && level >= 5 && count >= 3 && failed) {
    return { action: 'alert', confidence: Math.min(0.84,
      0.5 + Math.min(count, 10) * 0.015 + Math.min(level, 8) * 0.01),
    reason: PATTERNS[2].name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_supported_brute_force_pattern' };
}
