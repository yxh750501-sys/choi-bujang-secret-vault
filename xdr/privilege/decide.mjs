// Copied from patterns.json. The isolated judge imports this file alone.
const PATTERNS = Object.freeze([
  { name: 'unexpected_admin_membership',
    condition: 'T1078 경보 수준 10 이상에서 일반 계정이 administrators 그룹에 새로 들어가거나 제거 직후 재추가됨',
    evidence: 'MITRE ATT&CK T1078: 정상 계정을 탈취한 공격자는 높은 권한의 그룹 멤버십을 악용할 수 있습니다.' },
  { name: 'unusual_admin_execution',
    condition: 'T1068 또는 T1078 경보 수준 10 이상에서 새 관리자 권한·다른 계정 권한으로 명령을 실행하거나 업무 시간 밖 낯선 주소에서 관리자 명령을 실행함',
    evidence: 'MITRE ATT&CK T1068 및 T1078: 권한 상승 직후의 관리자 명령과 낯선 맥락의 권한 사용은 악용 신호입니다.' },
  { name: 'possible_privilege_change',
    condition: 'T1068 또는 T1078 경보 수준 5 이상이지만 관리자 멤버십·명령 실행의 명확한 악용 조건은 충족하지 못함',
    evidence: 'MITRE ATT&CK T1068 및 T1078: 단발성 권한 변경은 승인된 관리 작업일 수 있어 추가 확인이 필요합니다.' },
]);

export function decide(alert) {
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const t1068 = mitre.includes('T1068');
  const t1078 = mitre.includes('T1078');
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const adminGroup = typeof alert?.data?.group === 'string'
    && alert.data.group.toLowerCase() === 'administrators';
  const membership = t1078 && adminGroup
    && (/관리자 그룹.*추가|관리자 그룹에 들어가|다시 관리자로 들어/u.test(description)
      || /관리자 그룹 추가/u.test(description));
  const adminCommand = /관리자 명령|권한 명령/u.test(description);
  const elevatedContext = /방금 관리자가 된|수업 시간 밖|업무처럼 보이지 않는 시각|다른 계정의 권한|처음 보는 주소/u.test(description);
  const changedSession = /세션이 관리자 권한으로 바뀌/u.test(description)
    && /처음 봅니다|처음 보는/u.test(description);
  const execution = (t1068 || t1078) && ((adminCommand && elevatedContext) || changedSession);

  if (level >= 10 && (membership || execution)) {
    const pattern = membership ? PATTERNS[0] : PATTERNS[1];
    return { action: 'block', confidence: Math.min(0.99, 0.87 + (level - 10) * 0.03),
      reason: pattern.name };
  }
  if (level >= 5 && (t1068 || t1078)) {
    return { action: 'alert', confidence: Math.min(0.84, 0.5 + Math.min(level, 10) * 0.02),
      reason: PATTERNS[2].name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_supported_privilege_pattern' };
}
