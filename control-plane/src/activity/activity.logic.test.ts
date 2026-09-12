import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { buildActivityRecord, buildAuditRecord, normaliseIp } from './activity.logic.js';
import { REDACTED } from './redaction.logic.js';

describe('buildActivityRecord', () => {
  const valid = {
    serverId: 'server-1',
    userId: 'user-1',
    kind: 'docker.container.restart',
    resourceType: 'container',
    resourceId: 'estatify-api',
    summary: 'Restarted Estatify API',
  };

  it('accepts a well-formed activity', () => {
    const result = buildActivityRecord(valid);
    assert.ok(result.ok);
    assert.equal(result.value.kind, 'docker.container.restart');
    assert.equal(result.value.result, 'SUCCEEDED');
  });

  it('defaults metadata to an empty object', () => {
    const result = buildActivityRecord(valid);
    assert.ok(result.ok);
    assert.deepEqual(result.value.metadata, {});
  });

  it('redacts metadata on the way in', () => {
    const result = buildActivityRecord({ ...valid, metadata: { password: 'hunter2' } });
    assert.ok(result.ok);
    assert.equal(result.value.metadata['password'], REDACTED);
    assert.ok(!JSON.stringify(result.value).includes('hunter2'));
  });

  it('rejects a kind that is not a dotted lower-case name', () => {
    for (const kind of ['Docker.Restart', 'restart', 'docker..restart', 'docker restart', '']) {
      const result = buildActivityRecord({ ...valid, kind });
      assert.ok(!result.ok, `expected ${kind} to be rejected`);
      assert.equal(result.code, 'activity_kind_invalid');
    }
  });

  it('rejects an unknown resource type shape', () => {
    const result = buildActivityRecord({ ...valid, resourceType: 'Container!' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'activity_resource_type_invalid');
  });

  it('collapses whitespace in the summary', () => {
    const result = buildActivityRecord({ ...valid, summary: '  Restarted\n\tEstatify   API ' });
    assert.ok(result.ok);
    assert.equal(result.value.summary, 'Restarted Estatify API');
  });

  it('rejects an empty summary', () => {
    const result = buildActivityRecord({ ...valid, summary: '   \n ' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'activity_summary_empty');
  });

  it('truncates an over-long summary rather than rejecting it', () => {
    const result = buildActivityRecord({ ...valid, summary: 'x'.repeat(1000) });
    assert.ok(result.ok);
    assert.equal(result.value.summary.length, 280);
    assert.ok(result.value.summary.endsWith('…'));
  });

  it('normalises absent and empty ids to null', () => {
    const result = buildActivityRecord({
      kind: 'server.connect',
      resourceType: 'server',
      summary: 'Connected',
      serverId: '',
      resourceId: '  ',
    });
    assert.ok(result.ok);
    assert.equal(result.value.serverId, null);
    assert.equal(result.value.userId, null);
    assert.equal(result.value.resourceId, null);
  });

  it('carries a FAILED result through', () => {
    const result = buildActivityRecord({ ...valid, result: 'FAILED' });
    assert.ok(result.ok);
    assert.equal(result.value.result, 'FAILED');
  });
});

describe('normaliseIp', () => {
  it('accepts an IPv4 address', () => {
    assert.equal(normaliseIp('185.12.33.7'), '185.12.33.7');
  });

  it('rejects an IPv4 address with an out-of-range octet', () => {
    assert.equal(normaliseIp('999.1.1.1'), null);
  });

  it('unwraps an IPv4-mapped IPv6 address, so one client is one address', () => {
    assert.equal(normaliseIp('::ffff:185.12.33.7'), '185.12.33.7');
  });

  it('accepts an IPv6 address and lower-cases it', () => {
    assert.equal(normaliseIp('2001:DB8::1'), '2001:db8::1');
  });

  it('strips an IPv6 zone index', () => {
    assert.equal(normaliseIp('fe80::1%eth0'), 'fe80::1');
  });

  it('drops junk rather than storing it', () => {
    assert.equal(normaliseIp('not-an-ip'), null);
    assert.equal(normaliseIp(''), null);
    assert.equal(normaliseIp('   '), null);
    assert.equal(normaliseIp(null), null);
    assert.equal(normaliseIp(12345), null);
    assert.equal(normaliseIp('a'.repeat(100)), null);
  });
});

describe('buildAuditRecord', () => {
  const valid = {
    actor: 'user-1',
    action: 'auth.login',
    outcome: 'SUCCEEDED' as const,
  };

  it('accepts a minimal audit record', () => {
    const result = buildAuditRecord(valid);
    assert.ok(result.ok);
    assert.equal(result.value.actorType, 'user');
    assert.equal(result.value.targetType, null);
  });

  it('records a non-user actor type', () => {
    const result = buildAuditRecord({ ...valid, actorType: 'agent' });
    assert.ok(result.ok);
    assert.equal(result.value.actorType, 'agent');
  });

  it('rejects an empty actor — an unattributable audit row is worthless', () => {
    const result = buildAuditRecord({ ...valid, actor: '   ' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'audit_actor_invalid');
  });

  it('rejects an over-long actor', () => {
    const result = buildAuditRecord({ ...valid, actor: 'a'.repeat(200) });
    assert.ok(!result.ok);
    assert.equal(result.code, 'audit_actor_invalid');
  });

  it('rejects a malformed action name', () => {
    const result = buildAuditRecord({ ...valid, action: 'LOGIN' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'audit_action_invalid');
  });

  it('rejects a malformed target type', () => {
    const result = buildAuditRecord({ ...valid, targetType: 'Server Thing' });
    assert.ok(!result.ok);
    assert.equal(result.code, 'audit_target_invalid');
  });

  it('normalises the ip', () => {
    const result = buildAuditRecord({ ...valid, ip: '::ffff:10.0.0.1' });
    assert.ok(result.ok);
    assert.equal(result.value.ip, '10.0.0.1');
  });

  it('truncates an over-long user agent', () => {
    const result = buildAuditRecord({ ...valid, userAgent: 'U'.repeat(2000) });
    assert.ok(result.ok);
    assert.equal(result.value.userAgent?.length, 512);
  });

  it('redacts metadata', () => {
    const result = buildAuditRecord({
      ...valid,
      metadata: { attemptedToken: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlZGF0YQ' },
    });
    assert.ok(result.ok);
    assert.equal(result.value.metadata['attemptedToken'], REDACTED);
  });

  it('records a denial', () => {
    const result = buildAuditRecord({ ...valid, outcome: 'DENIED' });
    assert.ok(result.ok);
    assert.equal(result.value.outcome, 'DENIED');
  });
});
