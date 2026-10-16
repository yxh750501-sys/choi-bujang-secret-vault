import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readAlerts, projectAlert } from '../xdr/persistence/read-alerts.mjs';
import { decide } from '../xdr/persistence/decide.mjs';
import { checkIsolationRules, respond } from '../xdr/persistence/respond.mjs';

const root = new URL('../', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('xdr/fixtures/persistence.json', root), 'utf8'));

test('경보 읽기는 원본 24건을 다섯 안전 필드로 투영한다', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]), ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  const secret = projectAlert({ data: { srcuser: 'person@example.com', srcip: '192.0.2.1' },
    rule: { level: 2, description: 'token=hidden-value Bearer hidden-value' } });
  assert.equal(secret.account, '[ACCOUNT_REDACTED]');
  assert.doesNotMatch(secret.description, /hidden-value/u);
});

test('명확한 지속성 설치만 격리 후보로, 애매한 변경은 알림으로, 정상 사건은 기록한다', async () => {
  const decisions = fixture.alerts.map(decide);
  assert.deepEqual(decisions.reduce((counts, item) => {
    counts[item.action] += 1;
    return counts;
  }, { block: 0, alert: 0, record: 0 }), { block: 8, alert: 8, record: 8 });
  assert.ok(decisions.slice(16).every(item => item.action === 'record'));
  assert.ok(decisions.every(item => item.confidence >= 0 && item.confidence <= 1));
  const patterns = JSON.parse(await readFile(new URL('xdr/persistence/patterns.json', root), 'utf8'));
  assert.ok(patterns.every(item => item.evidence.includes('T1543') || item.evidence.includes('T1053')));
  assert.ok(decisions.filter(item => item.action !== 'record')
    .every(item => patterns.some(pattern => pattern.name === item.reason)));
  const strong = fixture.alerts[0];
  assert.equal(decide({ ...strong, rule: { ...strong.rule, mitre: [] } }).action, 'record');
  assert.equal(decide({ ...strong, rule: { ...strong.rule, level: 6 } }).action, 'alert');
  const source = await readFile(new URL('xdr/persistence/decide.mjs', root), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\breadFile\b|\bfetch\s*\(/u);
});

test('검증된 기기 매핑이 있을 때만 임시 격리 후보를 만들고 다른 기기는 통과한다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'persistence-'));
  try {
    const now = new Date('2026-10-16T00:00:00Z');
    const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const installed = [];
    const outcome = await respond(fixture.alerts, decisions, { now: () => now,
      logPath: join(dir, 'alerts.log'),
      resolveTrustedDevice: async name => name === 'choi-bujang-pc' ? 'fixture-pc-1' : null,
      installRule: async rule => { installed.push(rule); } });
    assert.equal(outcome.candidates.length, 8);
    assert.equal(outcome.notifications, 16);
    assert.equal(installed.length, 8);
    assert.ok(installed.every(rule => rule.evidenceAlertId && rule.expiresAt === '2026-10-16T00:15:00.000Z'));
    assert.equal(checkIsolationRules('fixture-pc-1', installed, now).effect, 'deny');
    assert.deepEqual(checkIsolationRules('fixture-normal-pc', installed, now), { effect: 'pass' });
    assert.deepEqual(checkIsolationRules('fixture-pc-1', installed, new Date('2026-10-16T00:15:00Z')), { effect: 'pass' });
    const lines = (await readFile(join(dir, 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(lines.length, 16);
    assert.ok(lines.every(line => !line.includes('deviceRef') && !line.includes('path')));
    const unverified = await respond(fixture.alerts, decisions, { now: () => now,
      logPath: join(dir, 'unverified.log') });
    assert.equal(unverified.candidates.length, 0);
    const normalOnly = await respond(fixture.alerts.slice(16), decisions.slice(16), { now: () => now,
      logPath: join(dir, 'normal.log'), resolveTrustedDevice: async () => 'fixture-normal-pc' });
    assert.equal(normalOnly.candidates.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
