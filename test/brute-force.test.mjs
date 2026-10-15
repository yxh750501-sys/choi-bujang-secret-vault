import assert from 'node:assert/strict';
import { readFile, mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { decide } from '../xdr/brute-force/decide.mjs';
import { projectAlert, readAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { checkDenyRules, respond } from '../xdr/brute-force/respond.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url)));

test('경보 읽기는 원본 28건을 다섯 안전 필드로 투영하고 비밀 모양을 가린다', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.ok(rows.every(row => Object.keys(row).sort().join(',')
    === 'account,description,ruleLevel,sourceAddress,timestamp'));
  const secret = projectAlert({ timestamp: '2026-09-27T09:00:00Z',
    data: { srcip: '192.0.2.9', srcuser: 'person@example.test' },
    rule: { level: 10, description: `password=${'p'.repeat(24)} Bearer ${'t'.repeat(24)}` } });
  assert.equal(secret.account, '[ACCOUNT_REDACTED]');
  assert.doesNotMatch(JSON.stringify(secret), /p{24}|t{24}/u);
});

test('T1110 근거 패턴은 명확한 공격·애매한 실패·정상 이벤트를 구분한다', async () => {
  const patterns = JSON.parse(await readFile(new URL('../xdr/brute-force/patterns.json', import.meta.url)));
  assert.ok(patterns.every(item => typeof item.name === 'string'
    && typeof item.condition === 'string' && item.condition.length > 10
    && typeof item.evidence === 'string' && item.evidence.includes('T1110')
    && !item.evidence.includes('\n')));
  const source = await readFile(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /\bimport\b|\brequire\s*\(|\bfetch\s*\(|node:fs|node:https/u);
  for (const pattern of patterns) assert.ok(source.includes(pattern.name));
  const results = fixture.alerts.map(decide);
  const counts = results.reduce((acc, item) => (acc[item.action] += 1, acc),
    { block: 0, alert: 0, record: 0 });
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
  assert.ok(results.every(item => Number.isFinite(item.confidence) && item.confidence >= 0
    && item.confidence <= 1 && !item.reason.includes('\n')));
  assert.ok(results.every(item => item.action !== 'block' || item.confidence >= 0.85));
  assert.ok(results.every(item => item.action !== 'alert'
    || (item.confidence >= 0.5 && item.confidence < 0.85)));
  assert.ok(fixture.alerts.every((alert, index) => alert.rule.level > 3
    || results[index].action === 'record'));
  const invalid = structuredClone(fixture.alerts[0]);
  invalid.data.srcip = '999.999.999.999';
  assert.equal(decide(invalid).action, 'record');
});

test('거부 어댑터는 확실한 주소에만 만료 규칙을 넣고 정상 주소는 통과시킨다', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'byteback-brute-'));
  try {
    const at = new Date('2026-09-27T10:00:00Z');
    const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const installed = [];
    const logPath = join(dir, 'alerts.log');
    const output = await respond(fixture.alerts, decisions, {
      now: () => at, logPath, installRule: async rule => { installed.push(rule); },
    });
    assert.equal(output.installed.length, 10);
    assert.equal(installed.length, 10);
    assert.equal(output.notifications, 19);
    assert.equal((await readFile(logPath, 'utf8')).trim().split('\n').length, 19);
    const normalAddresses = new Set(fixture.alerts.filter(alert => decide(alert).action === 'record')
      .map(alert => alert.data.srcip));
    assert.ok(installed.every(rule => rule.effect === 'deny' && rule.evidenceAlertId
      && !normalAddresses.has(rule.sourceAddress)));
    assert.equal(checkDenyRules(installed[0].sourceAddress, installed, at).effect, 'deny');
    assert.equal(checkDenyRules(installed[0].sourceAddress, installed,
      new Date(at.getTime() + 16 * 60_000)).effect, 'pass');
    assert.ok([...normalAddresses].every(address =>
      checkDenyRules(address, installed, at).effect === 'pass'));
    const sharedNormal = structuredClone(fixture.alerts[20]);
    sharedNormal.data.srcip = fixture.alerts[0].data.srcip;
    const shared = [fixture.alerts[0], sharedNormal];
    const sharedDecisions = shared.map(alert => ({ alertId: alert.id, ...decide(alert) }));
    const withheld = await respond(shared, sharedDecisions, { now: () => at,
      logPath: join(dir, 'shared.log') });
    assert.equal(withheld.installed.length, 0);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
