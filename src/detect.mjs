// 9단계에서 학생이 채우는 탐지 함수입니다. 운영 엔진이 검증한 사건만 사용합니다.
// 브라우저가 보낸 사용자 번호를 신원으로 취급하지 않습니다.
function eventTime(value) {
  if (typeof value !== 'string'
      || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/u.test(value)) return null;
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) return null;
  const canonical = new Date(timestamp).toISOString();
  const normalized = value.replace(/\.(\d{1,3})Z$/u,
    (_match, fraction) => `.${fraction.padEnd(3, '0')}Z`);
  return normalized === canonical || normalized === canonical.replace('.000Z', 'Z')
    ? timestamp
    : null;
}

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const bySubject = new Map();
  for (const event of events) {
    if (!event || typeof event !== 'object' || Array.isArray(event)
        || event.method !== 'GET' || typeof event.identity?.sub !== 'string'
        || !event.identity.sub.trim()) continue;
    const at = eventTime(event.at);
    if (at === null) continue;
    const subject = event.identity.sub;
    const times = bySubject.get(subject) ?? [];
    times.push(at);
    bySubject.set(subject, times);
  }

  for (const [subject, times] of bySubject.entries()) {
    const sortedTimes = [...times].sort((a, b) => a - b);
    const window = [];
    for (const at of sortedTimes) {
      window.push(at);
      while (window.length > 0 && at - window[0] > 10 * 60 * 1000) {
        window.shift();
      }
      if (window.length > 120) {
        return {
          action: 'propose_revocation',
          reasonCode: 'burst_read',
          subject,
        };
      }
    }
  }

  return { action: 'observe' };
}
