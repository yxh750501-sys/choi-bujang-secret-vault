import { appendFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const root = new URL('../', import.meta.url);
const defaultLog = new URL('../alerts.log', import.meta.url);
const lifetimeMs = 15 * 60 * 1000;

function validAddress(value) {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  return parts.length === 4 && parts.every(part => /^(?:0|[1-9]\d{0,2})$/u.test(part)
    && Number(part) <= 255);
}

// The engine must provide the verified egress destination. An untrusted
// browser field must not select an outbound deny rule.
export function checkDenyRules(trustedDestinationAddress, rules, at = new Date()) {
  if (!validAddress(trustedDestinationAddress) || !Array.isArray(rules)) return { effect: 'pass' };
  const matched = rules.find(rule => rule?.effect === 'deny'
    && rule.destinationAddress === trustedDestinationAddress
    && Date.parse(rule.expiresAt) > at.getTime());
  return matched ? { effect: 'deny', ruleId: matched.ruleId,
    evidenceAlertId: matched.evidenceAlertId } : { effect: 'pass' };
}

export async function respond(alerts, decisions, { now = () => new Date(),
  logPath = defaultLog, installRule = async () => {} } = {}) {
  if (!Array.isArray(alerts) || !Array.isArray(decisions)) throw new Error('INVALID_REPLAY');
  const byId = new Map(decisions.map(item => [item.alertId, item]));
  const benignDestinations = new Set(alerts.filter(alert => decide(alert).action === 'record')
    .map(alert => alert?.data?.dstip));
  const candidates = [];
  let notifications = 0;
  for (const alert of alerts) {
    const id = alert?.id;
    if (typeof id !== 'string' || !/^[a-z0-9-]{1,80}$/u.test(id)) continue;
    const verified = decide(alert);
    const recorded = byId.get(id);
    if (recorded?.action !== verified.action || recorded.confidence !== verified.confidence
        || recorded.reason !== verified.reason || verified.action === 'record') continue;
    const destination = alert?.data?.dstip;
    let rulePrepared = false;
    if (verified.action === 'block' && verified.confidence >= 0.85
        && validAddress(destination) && !benignDestinations.has(destination)) {
      const rule = { ruleId: 'xdr.exfiltration.destination_address', effect: 'deny',
        destinationAddress: destination, evidenceAlertId: id, reason: verified.reason,
        expiresAt: new Date(now().getTime() + lifetimeMs).toISOString() };
      await installRule(rule);
      candidates.push(rule);
      rulePrepared = true;
    }
    await appendFile(logPath, `${JSON.stringify({ at: now().toISOString(), alertId: id,
      action: verified.action, reason: verified.reason, rulePrepared })}\n`, 'utf8');
    notifications += 1;
  }
  return { candidates, notifications };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixture = JSON.parse(await readFile(new URL('fixtures/exfiltration.json', root), 'utf8'));
  const result = JSON.parse(await readFile(new URL('exfiltration/result.json', root), 'utf8'));
  const outcome = await respond(fixture.alerts, result.decisions);
  process.stdout.write(`목적지 거부 규칙 후보 ${outcome.candidates.length}건 · 알림 ${outcome.notifications}건\n`);
}
