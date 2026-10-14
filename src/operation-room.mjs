import { RULE_IDS } from './decider.mjs';
import records from './verification-records.json' with { type: 'json' };

const safeStatuses = new Set(['PASS', 'FAIL', 'NOT_RUN']);

export function operationReport(deviceStatus, evidence = records) {
  const cases = evidence.cases.map(item => ({
    id: item.id,
    stage: item.stage,
    name: item.name,
    expected: item.expected,
    actual: item.actual,
    requestId: item.requestId,
    checkedAt: item.checkedAt,
    environment: item.environment,
    status: safeStatuses.has(item.status) ? item.status : 'NOT_RUN',
  }));
  const counts = {
    pass: cases.filter(item => item.status === 'PASS').length,
    fail: cases.filter(item => item.status === 'FAIL').length,
    notRun: cases.filter(item => item.status === 'NOT_RUN').length,
  };
  const recoveryPreview = cases.find(item => item.id === 'stage10_restore_preview');
  return {
    schema: 'byteback.operation.v1',
    evidenceCommit: evidence.commit,
    rules: { ids: [...RULE_IDS], status: 'NOT_RUN', source: 'production-engine-unverified' },
    detection: { status: 'NOT_RUN', source: 'production-events-unavailable' },
    revocation: { status: 'UNKNOWN', source: 'production-engine-unavailable' },
    recovery: {
      version: recoveryPreview?.actual?.policyVersion ?? null,
      status: recoveryPreview?.status ?? 'NOT_RUN',
      source: 'local-handler-fixture',
    },
    deviceApproval: { status: deviceStatus },
    verification: { counts, cases },
  };
}
