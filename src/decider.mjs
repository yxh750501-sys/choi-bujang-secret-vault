// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 계약에 있는 값만 사용하고, 브라우저가 보낸 사용자/기기/위치 정보를 믿지 않습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

function isSuspiciousRequest(request) {
  const signals = request?.signals ?? {};
  const recentEvents = Array.isArray(request?.recentEvents) ? request.recentEvents : [];
  const hour = signals.hour;
  const riskEvent = recentEvents.some(event => (
    event && typeof event === 'object'
    && event.kind === 'risk_signal'
    && typeof event.ageSeconds === 'number'
    && Number.isFinite(event.ageSeconds)
    && event.ageSeconds <= 300
    && typeof event.count === 'number'
    && Number.isFinite(event.count)
    && event.count > 0
  ));
  return signals.region === 'foreign'
    || signals.network === 'unusual'
    || (typeof hour === 'number' && Number.isInteger(hour) && (hour < 6 || hour > 22))
    || riskEvent;
}

export async function decide(request) {
  const response = {
    schema: 'aleph.decision.v1',
    requestId: request?.requestId,
    decision: 'allow',
    reasonCode: 'approved',
    ruleIds: ['device_registered'],
  };

  if (request?.deviceRegistered !== true) {
    return {
      ...response,
      decision: 'deny',
      reasonCode: 'device_not_registered',
      ruleIds: ['device_registered'],
    };
  }

  const stepUp = request?.stepUp ?? {};
  const authAgeSeconds = stepUp.authAgeSeconds;
  if (stepUp.verified === true
      && typeof authAgeSeconds === 'number'
      && Number.isInteger(authAgeSeconds)
      && authAgeSeconds >= 0
      && authAgeSeconds <= 900) {
    return response;
  }

  if (isSuspiciousRequest(request)) {
    return {
      ...response,
      decision: 'step_up',
      reasonCode: 'step_up_required',
      ruleIds: ['device_registered', 'step_up_required'],
    };
  }

  return response;
}
