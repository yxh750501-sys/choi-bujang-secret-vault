import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readAlerts, projectAlert } from '../xdr/known-cve/read-alerts.mjs';
import { decide } from '../xdr/known-cve/decide.mjs';
import { checkDenyRules, respond } from '../xdr/known-cve/respond.mjs';

const root = new URL('../', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('xdr/fixtures/known-cve.json', root), 'utf8'));

test('경보 읽기는 원본 24건을 다섯 안전 필드로 투영한다', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]), ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  assert.equal(JSON.stringify(rows).includes('jndi:'), false);
  const secret = projectAlert({ data: { srcuser: 'person@example.com', srcip: '192.0.2.1' },
    rule: { level: 2, description: 'token=hidden-value Bearer hidden-value' } });
  assert.equal(secret.account, '[ACCOUNT_REDACTED]');
  assert.doesNotMatch(secret.description, /hidden-value/u);
});

test('완전한 원격 조회만 차단하고 불확실한 단서는 알림으로 남긴다', async () => {
  const decisions = fixture.alerts.map(decide);
  assert.deepEqual(decisions.reduce((counts, item) => {
    counts[item.action] += 1;
    return counts;
  }, { block: 0, alert: 0, record: 0 }), { block: 8, alert: 8, record: 8 });
  assert.ok(decisions.slice(16).every(item => item.action === 'record'));
  assert.ok(decisions.every(item => item.confidence >= 0 && item.confidence <= 1));
  const patterns = JSON.parse(await readFile(new URL('xdr/known-cve/patterns.json', root), 'utf8'));
  assert.ok(patterns.every(item => item.evidence.includes('CVE-2021-44228') && item.evidence.includes('T1190')));
  assert.ok(decisions.filter(item => item.action !== 'record')
    .every(item => patterns.some(pattern => pattern.name === item.reason)));
  const strong = fixture.alerts[0];
  assert.equal(decide({ ...strong, rule: { ...strong.rule, mitre: [] } }).action, 'record');
  assert.equal(decide({ ...strong, rule: { ...strong.rule, level: 6 } }).action, 'alert');
  assert.equal(decide({ ...strong, data: { ...strong.data, srcip: 'invalid' } }).action, 'alert');
  const source = await readFile(new URL('xdr/known-cve/decide.mjs', root), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\breadFile\b|\bfetch\s*\(/u);
});

test('거부 어댑터는 근거가 확인된 주소만 임시 차단하고 정상 주소를 통과시킨다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'known-cve-'));
  try {
    const installed = [];
    const now = new Date('2026-10-16T00:00:00Z');
    const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const outcome = await respond(fixture.alerts, decisions, { now: () => now,
      logPath: join(dir, 'alerts.log'), installRule: async rule => { installed.push(rule); } });
    assert.equal(outcome.installed.length, 8);
    assert.equal(outcome.notifications, 16);
    assert.ok(installed.every(rule => rule.evidenceAlertId && rule.expiresAt === '2026-10-16T00:15:00.000Z'));
    const normalAddress = fixture.alerts[16].data.srcip;
    assert.deepEqual(checkDenyRules(normalAddress, installed, now), { effect: 'pass' });
    const blockedAddress = fixture.alerts[0].data.srcip;
    assert.equal(checkDenyRules(blockedAddress, installed, now).effect, 'deny');
    assert.deepEqual(checkDenyRules(blockedAddress, installed, new Date('2026-10-16T00:15:00Z')), { effect: 'pass' });
    const lines = (await readFile(join(dir, 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(lines.length, 16);
    assert.ok(lines.every(line => !line.includes('useragent') && !line.includes('url') && !line.includes('jndi:')));
    const mixed = [...fixture.alerts, { ...fixture.alerts[16], id: 'kc-normal-shared',
      data: { ...fixture.alerts[16].data, srcip: blockedAddress } }];
    const mixedDecisions = mixed.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const mixedOutcome = await respond(mixed, mixedDecisions, { now: () => now,
      logPath: join(dir, 'mixed.log') });
    assert.ok(mixedOutcome.installed.every(rule => rule.sourceAddress !== blockedAddress));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
