import { appendFile, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';

const root = new URL('../', import.meta.url);
const defaultLog = new URL('../alerts.log', import.meta.url);
const lifetimeMs = 15 * 60 * 1000;

function validUserRef(value) {
  return typeof value === 'string' && /^[a-zA-Z0-9:_-]{1,128}$/u.test(value);
}

// The engine must supply a server-verified user reference. A Wazuh account
// label or browser-provided identity is not an authenticated ZTNA user ID.
export function checkDenyRules(trustedUserRef, rules, at = new Date()) {
  if (!validUserRef(trustedUserRef) || !Array.isArray(rules)) return { effect: 'pass' };
  const matched = rules.find(rule => rule?.effect === 'deny'
    && rule.userRef === trustedUserRef
    && Date.parse(rule.expiresAt) > at.getTime());
  return matched ? { effect: 'deny', ruleId: matched.ruleId,
    evidenceAlertId: matched.evidenceAlertId } : { effect: 'pass' };
}

export async function respond(alerts, decisions, { now = () => new Date(),
  logPath = defaultLog, resolveTrustedUser = async () => null,
  revokeSessions = async () => {}, installRule = async () => {} } = {}) {
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
        && typeof alert?.data?.srcuser === 'string') {
      const userRef = await resolveTrustedUser(alert.data.srcuser);
      if (validUserRef(userRef)) {
        const rule = { ruleId: 'xdr.privilege.session_revoke', effect: 'deny',
          userRef, evidenceAlertId: id, reason: verified.reason,
          expiresAt: new Date(now().getTime() + lifetimeMs).toISOString() };
        await revokeSessions(userRef, id);
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
  const fixture = JSON.parse(await readFile(new URL('fixtures/privilege.json', root), 'utf8'));
  const result = JSON.parse(await readFile(new URL('privilege/result.json', root), 'utf8'));
  const outcome = await respond(fixture.alerts, result.decisions, {
    // Fixture-only mapping; no production sessions are revoked by this replay.
    resolveTrustedUser: async account => /^user\d{2}$/u.test(account) ? `fixture:${account}` : null,
  });
  process.stdout.write(`세션 회수 규칙 후보 ${outcome.candidates.length}건 · 알림 ${outcome.notifications}건\n`);
}
