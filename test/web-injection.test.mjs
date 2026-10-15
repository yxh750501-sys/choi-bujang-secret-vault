import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { readAlerts, projectAlert } from '../xdr/web-injection/read-alerts.mjs';
import { decide } from '../xdr/web-injection/decide.mjs';
import { checkDenyRules, respond } from '../xdr/web-injection/respond.mjs';

const root = new URL('../', import.meta.url);
const fixture = JSON.parse(await readFile(new URL('xdr/fixtures/web-injection.json', root), 'utf8'));

test('경보 읽기는 원본 26건을 다섯 안전 필드로 투영한다', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.deepEqual(Object.keys(rows[0]), ['timestamp', 'sourceAddress', 'account', 'ruleLevel', 'description']);
  const secret = projectAlert({ data: { srcuser: 'person@example.com', srcip: '192.0.2.1' },
    rule: { level: 2, description: 'token=hidden-value Bearer hidden-value' } });
  assert.equal(secret.account, '[ACCOUNT_REDACTED]');
  assert.doesNotMatch(secret.description, /hidden-value/u);
});

test('T1190 반복 주입은 차단, 단발 경보는 알림, 정상 사건은 기록한다', async () => {
  const decisions = fixture.alerts.map(decide);
  assert.deepEqual(decisions.reduce((counts, item) => {
    counts[item.action] += 1;
    return counts;
  }, { block: 0, alert: 0, record: 0 }), { block: 8, alert: 9, record: 9 });
  assert.ok(decisions.slice(17).every(item => item.action === 'record'));
  assert.ok(decisions.every(item => item.confidence >= 0 && item.confidence <= 1));
  const patterns = JSON.parse(await readFile(new URL('xdr/web-injection/patterns.json', root), 'utf8'));
  assert.ok(patterns.every(item => item.evidence.includes('T1190')));
  assert.ok(decisions.filter(item => item.action !== 'record')
    .every(item => patterns.some(pattern => pattern.name === item.reason)));
  const base = { rule: { level: 11, mitre: ['T1190'], description: '웹 요청' },
    data: { srcip: '192.0.2.80', count: '9', url: '/search?q=' } };
  for (const [url, reason] of [
    ['/search?q=%27%20OR%201%3D1', 'repeated_sql_injection'],
    ['/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E', 'repeated_script_injection'],
    ['/files?path=../../private', 'repeated_path_traversal'],
  ]) assert.equal(decide({ ...base, data: { ...base.data, url } }).reason, reason);
  assert.equal(decide({ ...base, data: { ...base.data, url: '/search?q=select-course' } }).action, 'alert');
  assert.equal(decide({ ...base, rule: { ...base.rule, mitre: [] },
    data: { ...base.data, url: '/files?path=../../private' } }).action, 'record');
  assert.equal(decide({ ...base, data: { ...base.data, count: '1',
    url: '/files?path=../../private' } }).action, 'alert');
  const source = await readFile(new URL('xdr/web-injection/decide.mjs', root), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\breadFile\b|\bfetch\s*\(/u);
});

test('거부 어댑터는 명확한 출발 주소만 임시 규칙으로 넣고 정상 주소를 통과시킨다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'web-injection-'));
  try {
    const installed = [];
    const now = new Date('2026-10-15T00:00:00Z');
    const decisions = fixture.alerts.map((alert) => ({ alertId: alert.id, ...decide(alert) }));
    const outcome = await respond(fixture.alerts, decisions, { now: () => now,
      logPath: join(dir, 'alerts.log'), installRule: async rule => { installed.push(rule); } });
    assert.equal(outcome.installed.length, 8);
    assert.equal(outcome.notifications, 17);
    assert.equal(installed.length, 8);
    assert.ok(installed.every(rule => rule.evidenceAlertId && rule.expiresAt === '2026-10-15T00:15:00.000Z'));
    const normalAddress = fixture.alerts[17].data.srcip;
    assert.deepEqual(checkDenyRules(normalAddress, installed, now), { effect: 'pass' });
    const blockedAddress = fixture.alerts[0].data.srcip;
    assert.equal(checkDenyRules(blockedAddress, installed, now).effect, 'deny');
    assert.deepEqual(checkDenyRules(blockedAddress, installed, new Date('2026-10-15T00:15:00Z')), { effect: 'pass' });
    const lines = (await readFile(join(dir, 'alerts.log'), 'utf8')).trim().split('\n');
    assert.equal(lines.length, 17);
    assert.ok(lines.every(line => !line.includes('url') && !line.includes('srcuser')));

    const mixed = [...fixture.alerts, { ...fixture.alerts[17], id: 'wi-normal-shared',
      data: { ...fixture.alerts[17].data, srcip: blockedAddress } }];
    const mixedDecisions = mixed.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const mixedOutcome = await respond(mixed, mixedDecisions, { now: () => now,
      logPath: join(dir, 'mixed.log') });
    assert.ok(mixedOutcome.installed.every(rule => rule.sourceAddress !== blockedAddress));
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
