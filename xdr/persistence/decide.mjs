// Copied from patterns.json. The isolated judge imports this file alone.
const PATTERNS = Object.freeze([
  { name: 'unsigned_service_persistence',
    condition: 'T1543 경보 수준 10 이상에서 서명 없는 새 서비스·바뀐 실행 파일 또는 평소 목록에 없는 지속 서비스 등록이 확인됨',
    evidence: 'MITRE ATT&CK T1543: 악성코드는 시스템 서비스 생성·변경으로 재시작 뒤에도 실행될 수 있습니다.' },
  { name: 'unknown_scheduled_task',
    condition: 'T1053 경보 수준 10 이상에서 처음 보는 예약 작업이나 임의 이름 작업이 임시 파일을 실행하거나 시작 프로그램과 같은 임시 파일을 가리킴',
    evidence: 'MITRE ATT&CK T1053: 예약 작업은 공격자가 실행을 반복하고 지속성을 유지하는 수단입니다.' },
  { name: 'unknown_startup_entry',
    condition: 'T1543 경보 수준 10 이상에서 평소 목록에 없는 시작 폴더 프로그램이 추가되거나 예약 작업과 같은 임시 파일을 가리킴',
    evidence: 'MITRE ATT&CK T1543 및 T1053: 비정상 시작 항목과 예약 작업의 결합은 재시작 뒤 실행을 유지하는 신호입니다.' },
  { name: 'possible_persistence_change',
    condition: 'T1543 또는 T1053 경보 수준 5 이상이지만 서명·평소 목록·실행 경로의 근거가 부족해 격리 조건은 충족하지 못함',
    evidence: 'MITRE ATT&CK T1543 및 T1053: 단발성 서비스·예약 작업 변경은 정상 관리 작업과 구분할 추가 확인이 필요합니다.' },
]);

export function decide(alert) {
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const serviceTechnique = mitre.includes('T1543');
  const taskTechnique = mitre.includes('T1053');
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const path = typeof alert?.data?.path === 'string' ? alert.data.path : '';
  const tempFile = /임시 파일|임시 폴더|\\temp\\|\/tmp\//iu.test(description + ' ' + path);
  const service = serviceTechnique && /서비스/u.test(description)
    && (/서명 없|서명이 없/u.test(description)
      || (/평소 목록에 없는/u.test(description) && /등록|다시 켜도/u.test(description)));
  const task = taskTechnique && /예약 작업/u.test(description) && tempFile
    && /처음 보는|임의 문자열|같은 임시 파일/u.test(description);
  const startup = serviceTechnique && /시작 폴더|시작 프로그램/u.test(description)
    && /평소 목록에 없는|같은 임시 파일/u.test(description);

  if (level >= 10 && (service || task || startup)) {
    const pattern = service ? PATTERNS[0] : task ? PATTERNS[1] : PATTERNS[2];
    return { action: 'block', confidence: Math.min(0.99, 0.87 + (level - 10) * 0.03),
      reason: pattern.name };
  }
  if (level >= 5 && (serviceTechnique || taskTechnique)) {
    return { action: 'alert', confidence: Math.min(0.84, 0.5 + Math.min(level, 10) * 0.02),
      reason: PATTERNS[3].name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_supported_persistence_pattern' };
}
