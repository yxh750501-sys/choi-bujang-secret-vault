import { appendFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const root = new URL('../', import.meta.url);
const defaultLog = new URL('../alerts.log', import.meta.url);
const lifetimeMs = 15 * 60 * 1000;

function validDeviceRef(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9:_-]{1,128}$/u.test(value);
}

// The engine must provide its verified device reference. The Wazuh agent name
// and any browser-provided device identifier are not trusted ZTNA identities.
export function checkIsolationRules(trustedDeviceRef, rules, at = new Date()) {
  if (!validDeviceRef(trustedDeviceRef) || !Array.isArray(rules)) return { effect: 'pass' };
  const matched = rules.find(rule => rule?.effect === 'deny'
    && rule.deviceRef === trustedDeviceRef
    && Date.parse(rule.expiresAt) > at.getTime());
  return matched ? { effect: 'deny', ruleId: matched.ruleId,
    evidenceAlertId: matched.evidenceAlertId } : { effect: 'pass' };
}

export async function respond(alerts, decisions, { now = () => new Date(),
  logPath = defaultLog, resolveTrustedDevice = async () => null,
  installRule = async () => {} } = {}) {
  if (!Array.isArray(alerts) || !Array.isArray(decisions)) throw new Error('INVALID_REPLAY');
  const byId = new Map(decisions.map(item => [item.alertId, item]));
  const candidates = [];
  let notifications = 0;
  for (const alert of alerts) {
    const id = alert?.id;
    if (typeof id !== 'string' || !/^[a-z0-9-]{1,80}$/u.test(id)) continue;
    const verified = decide(alert);
    const recorded = byId.get(id);
    if (recorded?.action !== verified.action || recorded.confidence !== verified.confidence
        || recorded.reason !== verified.reason || verified.action === 'record') continue;
    let rulePrepared = false;
    if (verified.action === 'block' && verified.confidence >= 0.85
        && typeof alert?.agent?.name === 'string') {
      const deviceRef = await resolveTrustedDevice(alert.agent.name);
      if (validDeviceRef(deviceRef)) {
        const rule = { ruleId: 'xdr.persistence.device_isolation', effect: 'deny',
          deviceRef, evidenceAlertId: id, reason: verified.reason,
          expiresAt: new Date(now().getTime() + lifetimeMs).toISOString() };
        await installRule(rule);
        candidates.push(rule);
        rulePrepared = true;
      }
    }
    await appendFile(logPath, `${JSON.stringify({ at: now().toISOString(), alertId: id,
      action: verified.action, reason: verified.reason, rulePrepared })}\n`, 'utf8');
    notifications += 1;
  }
  return { candidates, notifications };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixture = JSON.parse(await readFile(new URL('fixtures/persistence.json', root), 'utf8'));
  const result = JSON.parse(await readFile(new URL('persistence/result.json', root), 'utf8'));
  const outcome = await respond(fixture.alerts, result.decisions, {
    // A fixture-only mapping exercises the adapter without claiming an engine install.
    resolveTrustedDevice: async name => name === 'choi-bujang-pc' ? 'fixture-pc-1' : null,
  });
  process.stdout.write(`기기 격리 규칙 후보 ${outcome.candidates.length}건 · 알림 ${outcome.notifications}건\n`);
}
