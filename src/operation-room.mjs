import { RULE_IDS } from './decider.mjs';
import records from './verification-records.json' with { type: 'json' };

const safeStatuses = new Set(['PASS', 'FAIL', 'NOT_RUN']);
const requestIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu;
const deviceStatuses = new Set(['unregistered', 'pending', 'approved', 'rejected', 'revoked', 'expired']);

function measured(item) {
  return requestIdPattern.test(item.requestId ?? '')
    && typeof item.checkedAt === 'string' && Number.isFinite(Date.parse(item.checkedAt))
    && item.environment === 'local-handler'
    && Number.isInteger(item.actual?.httpStatus)
    && item.actual.httpStatus >= 100 && item.actual.httpStatus <= 599;
}

function safeActual(item) {
  if (!measured(item)) return null;
  const value = item.actual;
  return {
    httpStatus: value.httpStatus,
    error: typeof value.error === 'string' && /^[A-Z][A-Z0-9_]{0,63}$/u.test(value.error)
      ? value.error : null,
    ...(value.action === 'preview' ? { action: 'preview' } : {}),
    ...(typeof value.policyVersion === 'string' && /^[a-z0-9-]{1,80}$/u.test(value.policyVersion)
      ? { policyVersion: value.policyVersion } : {}),
    ...(['not_run', 'pass', 'fail', 'partial'].includes(value.retests)
      ? { retests: value.retests } : {}),
  };
}

export function operationReport(deviceStatus, evidence = records) {
  const cases = evidence.cases.map(item => ({
    id: item.id,
    stage: item.stage,
    kind: item.kind,
    name: item.name,
    request: item.request,
    expected: item.expected,
    actual: safeActual(item),
    requestId: measured(item) ? item.requestId : null,
    checkedAt: measured(item) ? item.checkedAt : null,
    environment: measured(item) ? item.environment : null,
    status: measured(item) && safeStatuses.has(item.status) ? item.status : 'NOT_RUN',
  }));
  const counts = {
    pass: cases.filter(item => item.status === 'PASS').length,
    fail: cases.filter(item => item.status === 'FAIL').length,
    notRun: cases.filter(item => item.status === 'NOT_RUN').length,
  };
  const recoveryPreview = cases.find(item => item.id === 's10_restore_preview');
  return {
    schema: 'byteback.operation.v1',
    evidenceCommit: evidence.commit,
    provenance: {
      studentImplementation: 'BYTE BACK 학생 구현',
      providedEngine: 'ALEPH SDP 엔진',
      localEvidence: 'local-handler',
    },
    sources: {
      student: ['src/decider.mjs', 'src/detect.mjs', 'api/notes.js', 'public/manifest.webmanifest'],
      engine: 'ALEPH SDP 엔진',
    },
    rules: { ids: [...RULE_IDS], status: 'NOT_RUN', source: 'production-engine-unverified' },
    detection: { status: 'NOT_RUN', source: 'production-events-unavailable' },
    revocation: { status: 'UNKNOWN', source: 'production-engine-unavailable' },
    recovery: {
      version: recoveryPreview?.actual?.policyVersion ?? null,
      status: recoveryPreview?.status ?? 'NOT_RUN',
      source: 'local-handler-fixture',
    },
    deviceApproval: { status: deviceStatuses.has(deviceStatus) ? deviceStatus : 'unknown' },
    verification: { counts, cases },
  };
}
