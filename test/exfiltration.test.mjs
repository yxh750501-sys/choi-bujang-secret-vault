import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readAlerts, projectAlert } from '../xdr/exfiltration/read-alerts.mjs';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { checkDenyRules, respond } from '../xdr/exfiltration/respond.mjs';

const root = new URL('../', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('xdr/fixtures/exfiltration.json', root), 'utf8'));

test('경보 읽기는 원본 30건을 다섯 안전 필드로 투영한다', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]), ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  const secret = projectAlert({ data: { srcuser: 'person@example.com', srcip: '192.0.2.1' },
    rule: { level: 2, description: 'token=hidden-value Bearer hidden-value' } });
  assert.equal(secret.account, '[ACCOUNT_REDACTED]');
  assert.doesNotMatch(secret.description, /hidden-value/u);
});

test('명확한 대량 반출만 차단 후보, 애매한 전송은 알림, 정상 사건은 기록한다', async () => {
  const decisions = fixture.alerts.map(decide);
  assert.deepEqual(decisions.reduce((counts, item) => {
    counts[item.action] += 1;
    return counts;
  }, { block: 0, alert: 0, record: 0 }), { block: 10, alert: 10, record: 10 });
  assert.ok(decisions.slice(20).every(item => item.action === 'record'));
  assert.ok(decisions.every(item => item.confidence >= 0 && item.confidence <= 1));
  const patterns = JSON.parse(await readFile(new URL('xdr/exfiltration/patterns.json', root), 'utf8'));
  assert.ok(patterns.every(item => item.evidence.includes('T1041') || item.evidence.includes('T1048')));
  assert.ok(decisions.filter(item => item.action !== 'record')
    .every(item => patterns.some(pattern => pattern.name === item.reason)));
  const strong = fixture.alerts[0];
  assert.equal(decide({ ...strong, rule: { ...strong.rule, mitre: [] } }).action, 'record');
  assert.equal(decide({ ...strong, rule: { ...strong.rule, level: 6 } }).action, 'alert');
  assert.equal(decide({ ...strong, data: { ...strong.data, bytes: '1000' } }).action, 'alert');
  assert.equal(decide({ ...strong, data: { ...strong.data, dstip: 'invalid' } }).action, 'alert');
  const source = await readFile(new URL('xdr/exfiltration/decide.mjs', root), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\breadFile\b|\bfetch\s*\(/u);
});

test('명확한 목적지에만 임시 거부 후보를 만들고 정상 목적지는 통과시킨다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'exfiltration-'));
  try {
    const now = new Date('2026-10-16T00:00:00Z');
    const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const installed = [];
    const outcome = await respond(fixture.alerts, decisions, { now: () => now,
      logPath: join(dir, 'alerts.log'), installRule: async rule => { installed.push(rule); } });
    assert.equal(outcome.candidates.length, 10);
    assert.equal(outcome.notifications, 20);
    assert.equal(installed.length, 10);
    assert.ok(installed.every(rule => rule.evidenceAlertId && rule.expiresAt === '2026-10-16T00:15:00.000Z'));
    const normalDestination = fixture.alerts[20].data.dstip;
    assert.deepEqual(checkDenyRules(normalDestination, installed, now), { effect: 'pass' });
    const blockedDestination = fixture.alerts[0].data.dstip;
    assert.equal(checkDenyRules(blockedDestination, installed, now).effect, 'deny');
    assert.deepEqual(checkDenyRules(blockedDestination, installed,
      new Date('2026-10-16T00:15:00Z')), { effect: 'pass' });
    const lines = (await readFile(join(dir, 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(lines.length, 20);
    assert.ok(lines.every(line => !line.includes('dstip') && !line.includes('bytes')));
    const mixed = [...fixture.alerts, { ...fixture.alerts[20], id: 'ex-normal-shared',
      data: { ...fixture.alerts[20].data, dstip: blockedDestination } }];
    const mixedDecisions = mixed.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const mixedOutcome = await respond(mixed, mixedDecisions, { now: () => now,
      logPath: join(dir, 'mixed.log') });
    assert.ok(mixedOutcome.candidates.every(rule => rule.destinationAddress !== blockedDestination));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
