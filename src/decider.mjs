// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 계약에 있는 값만 사용하고, 브라우저가 보낸 사용자/기기/위치 정보를 믿지 않습니다.
export const RULE_IDS = Object.freeze([
  'device_registered',
  'resource_boundary',
  'step_up_required',
]);

function isAllowedResourceRequest(request) {
  if (request?.method !== 'GET' || request.queryLength !== 0
      || typeof request.path !== 'string') return false;

  if (request.service === 'announcements') {
    return request.path === '/announcements' && request.route === 'GET /announcements';
  }
  if (request.service !== 'notes' || request.route !== 'GET /notes/:id') return false;

  const match = /^\/notes\/([^/%?#\\]+)$/u.exec(request.path);
  return Boolean(match && match[1] !== '.' && match[1] !== '..'
    && !/[\u0000-\u0020\u007f]/u.test(match[1]));
}

function isSuspiciousRequest(request) {
  const signals = request?.signals;
  if (!signals || signals.source !== 'judge_fixture') return false;

  const recentEvents = Array.isArray(request?.recentEvents) ? request.recentEvents : [];
  const hour = signals.hour;
  const unusualHour = typeof hour === 'number' && Number.isInteger(hour)
    && hour >= 0 && hour <= 23 && (hour < 6 || hour > 22);
  const bulkLookup = recentEvents.some(event => (
    event && typeof event === 'object'
    && event.kind === 'risk_signal'
    && typeof event.ageSeconds === 'number'
    && Number.isFinite(event.ageSeconds)
    && event.ageSeconds >= 0
    && event.ageSeconds <= 300
    && typeof event.count === 'number'
    && Number.isFinite(event.count)
    && Number.isInteger(event.count)
    && event.count >= 10
  ));

  return unusualHour && signals.network === 'unusual' && bulkLookup;
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

  response.ruleIds = ['device_registered', 'resource_boundary'];
  if (!isAllowedResourceRequest(request)) {
    return {
      ...response,
      decision: 'deny',
      reasonCode: 'resource_access_denied',
      ruleIds: ['device_registered', 'resource_boundary'],
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
