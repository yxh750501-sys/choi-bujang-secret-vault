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

// The engine must supply the verified address; the existing decider request
// does not contain one, and a browser-provided address must never select a rule.
export function checkDenyRules(trustedSourceAddress, rules, at = new Date()) {
  if (!validAddress(trustedSourceAddress) || !Array.isArray(rules)) return { effect: 'pass' };
  const matched = rules.find(rule => rule?.effect === 'deny'
    && rule.sourceAddress === trustedSourceAddress
    && Date.parse(rule.expiresAt) > at.getTime());
  return matched ? { effect: 'deny', ruleId: matched.ruleId,
    evidenceAlertId: matched.evidenceAlertId } : { effect: 'pass' };
}

export async function respond(alerts, decisions, { now = () => new Date(),
  logPath = defaultLog, installRule = async () => {} } = {}) {
  if (!Array.isArray(alerts) || !Array.isArray(decisions)) throw new Error('INVALID_REPLAY');
  const byId = new Map(decisions.map(item => [item.alertId, item]));
  const benignSources = new Set(alerts.filter(alert => decide(alert).action === 'record')
    .map(alert => alert?.data?.srcip));
  const installed = [];
  let notifications = 0;
  for (const alert of alerts) {
    const id = alert?.id;
    if (typeof id !== 'string' || !/^[a-z0-9-]{1,80}$/u.test(id)) continue;
    const verified = decide(alert);
    const recorded = byId.get(id);
    if (recorded?.action !== verified.action || recorded.confidence !== verified.confidence
        || recorded.reason !== verified.reason || verified.action === 'record') continue;
    const source = alert?.data?.srcip;
    let ruleInstalled = false;
    if (verified.action === 'block' && verified.confidence >= 0.85
        && validAddress(source) && !benignSources.has(source)) {
      const rule = { ruleId: 'xdr.known_cve.source_address', effect: 'deny',
        sourceAddress: source, evidenceAlertId: id, reason: verified.reason,
        expiresAt: new Date(now().getTime() + lifetimeMs).toISOString() };
      await installRule(rule);
      installed.push(rule);
      ruleInstalled = true;
    }
    await appendFile(logPath, `${JSON.stringify({ at: now().toISOString(), alertId: id,
      action: verified.action, reason: verified.reason, ruleInstalled })}\n`, 'utf8');
    notifications += 1;
  }
  return { installed, notifications };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const fixture = JSON.parse(await readFile(new URL('fixtures/known-cve.json', root), 'utf8'));
  const result = JSON.parse(await readFile(new URL('known-cve/result.json', root), 'utf8'));
  const outcome = await respond(fixture.alerts, result.decisions);
  process.stdout.write(`거부 규칙 후보 ${outcome.installed.length}건 · 알림 ${outcome.notifications}건\n`);
}
