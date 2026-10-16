import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const fixtureUrl = new URL('../fixtures/known-cve.json', import.meta.url);

function safeText(value) {
  if (typeof value !== 'string') return null;
  return value.replace(/-----BEGIN [\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu, '[REDACTED]')
    .replace(/\bBearer\s+\S+/giu, 'Bearer [REDACTED]')
    .replace(/\b(?:password|passwd|token|secret|api[_-]?key|비밀번호)\s*[:=]\s*\S+/giu, '[REDACTED]')
    .replace(/\bsb_secret_[A-Za-z0-9_-]+\b|\bsk-[A-Za-z0-9_-]{16,}\b/gu, '[REDACTED]')
    .replace(/\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/gu, '[REDACTED]')
    .replace(/[\r\n]+/gu, ' ').slice(0, 240);
}

export function projectAlert(alert) {
  const account = safeText(alert?.data?.srcuser);
  return {
    timestamp: safeText(alert?.timestamp),
    sourceAddress: safeText(alert?.data?.srcip),
    account: account?.includes('@') ? '[ACCOUNT_REDACTED]' : account,
    ruleLevel: Number.isInteger(alert?.rule?.level) ? alert.rule.level : null,
    description: safeText(alert?.rule?.description),
  };
}

export async function readAlerts(url = fixtureUrl) {
  const fixture = JSON.parse(await readFile(url, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'known-cve'
      || !Array.isArray(fixture.alerts)) throw new Error('INVALID_KNOWN_CVE_FIXTURE');
  return fixture.alerts.map(projectAlert);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  for (const row of await readAlerts()) process.stdout.write(`${JSON.stringify(row)}\n`);
}
