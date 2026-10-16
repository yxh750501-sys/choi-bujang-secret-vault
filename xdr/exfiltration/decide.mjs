// Copied from patterns.json. The isolated judge imports this file alone.
const PATTERNS = Object.freeze([
  { name: 'large_new_destination_transfer',
    condition: 'T1041 또는 T1048 경보 수준 10 이상에서 처음 보는 외부 목적지로 5천만 바이트 이상 전송됨',
    evidence: 'MITRE ATT&CK T1041 및 T1048: 낯선 외부 목적지로의 대량 전송은 자료 반출 신호입니다.' },
  { name: 'after_hours_archive_transfer',
    condition: 'T1048 경보 수준 10 이상에서 업무 시간 밖 압축 자료 또는 반복 전송이 5천만 바이트 이상 확인됨',
    evidence: 'MITRE ATT&CK T1048: 업무 시간 밖 압축 파일의 큰 외부 전송은 다른 프로토콜을 이용한 반출 신호입니다.' },
  { name: 'repeated_bulk_exfiltration',
    condition: 'T1041 또는 T1048 경보 수준 10 이상에서 대용량 반복·평소와 다른 포트·자료실 전체 복사가 5천만 바이트 이상 확인됨',
    evidence: 'MITRE ATT&CK T1041 및 T1048: 반복 대량 전송과 평소와 다른 통로는 반출 가능성을 높입니다.' },
  { name: 'possible_exfiltration',
    condition: 'T1041 또는 T1048 경보 수준 5 이상이지만 대량 외부 전송의 차단 근거는 부족함',
    evidence: 'MITRE ATT&CK T1041 및 T1048: 단발성 또는 작은 전송은 정상 백업·동기화와 구별할 확인이 필요합니다.' },
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
  return /^(?:0|[1-9]\d{0,12})$/u.test(text) ? Number(text) : 0;
}

export function decide(alert) {
  const level = Number.isInteger(alert?.rule?.level) ? alert.rule.level : 0;
  const mitre = Array.isArray(alert?.rule?.mitre) ? alert.rule.mitre : [];
  const t1041 = mitre.includes('T1041');
  const t1048 = mitre.includes('T1048');
  const description = typeof alert?.rule?.description === 'string' ? alert.rule.description : '';
  const bytes = countOf(alert?.data?.bytes);
  const repeated = countOf(alert?.data?.count) >= 8;
  const newDestination = /처음 보는 목적지|처음 보는 주소/u.test(description);
  const afterHours = /수업 시간 밖|업무 시간 밖/u.test(description)
    && /압축 파일|전송이 \d+번/u.test(description);
  const unusualBulk = (repeated && /대용량|전송이 \d+번|명령 통로/u.test(description))
    || /평소에 쓰지 않던 포트|자료실 전체/u.test(description);

  if (level >= 10 && (t1041 || t1048) && validAddress(alert?.data?.dstip)
      && bytes >= 50_000_000) {
    const pattern = newDestination ? PATTERNS[0]
      : t1048 && afterHours ? PATTERNS[1]
        : unusualBulk ? PATTERNS[2] : null;
    if (pattern) return { action: 'block', confidence: Math.min(0.99,
      0.86 + Math.min(bytes, 300_000_000) / 10_000_000_000 + (level - 10) * 0.02),
    reason: pattern.name };
  }
  if (level >= 5 && (t1041 || t1048)) {
    return { action: 'alert', confidence: Math.min(0.84, 0.5 + Math.min(level, 10) * 0.02),
      reason: PATTERNS[3].name };
  }
  return { action: 'record', confidence: 0.1, reason: 'no_supported_exfiltration_pattern' };
}
