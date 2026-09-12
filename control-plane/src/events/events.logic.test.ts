import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { fail, ok, type Result } from '../common/result.logic.js';
import {
  authoriseConnection,
  buildActivityEvent,
  buildStatusEvent,
  decideSubscription,
  extractToken,
  initialRooms,
  roomForServer,
  roomForUser,
  routeFor,
} from './events.logic.js';

const USER_ID = '11111111-1111-4111-8111-111111111111';
const SERVER_ID = '22222222-2222-4222-8222-222222222222';
const OTHER_SERVER_ID = '33333333-3333-4333-8333-333333333333';
const AT = new Date('2026-09-12T10:00:00.000Z');

const acceptAll: (token: string) => Result<{ sub: string; sid: string }> = () =>
  ok({ sub: USER_ID, sid: 'session-1' });
const rejectAll: (token: string) => Result<{ sub: string; sid: string }> = () =>
  fail('token_expired', 'Your session is no longer valid. Sign in again.');

describe('room names', () => {
  it('namespaces a server room', () => {
    assert.equal(roomForServer(SERVER_ID), `server:${SERVER_ID}`);
  });

  it('namespaces a user room', () => {
    assert.equal(roomForUser(USER_ID), `user:${USER_ID}`);
  });

  it('lower-cases so one server is one room', () => {
    assert.equal(roomForServer(SERVER_ID.toUpperCase()), `server:${SERVER_ID}`);
  });

  it('refuses to build a room name from a non-UUID', () => {
    assert.throws(() => roomForServer('*'), /non-UUID/);
    assert.throws(() => roomForServer('../admin'), /non-UUID/);
    assert.throws(() => roomForUser('all'), /non-UUID/);
  });
});

describe('extractToken', () => {
  it('prefers auth.token', () => {
    assert.equal(
      extractToken({
        auth: { token: 'from-auth' },
        headers: { authorization: 'Bearer from-header' },
        query: { token: 'from-query' },
      }),
      'from-auth',
    );
  });

  it('falls back to the Authorization header', () => {
    assert.equal(extractToken({ headers: { authorization: 'Bearer abc.def.ghi' } }), 'abc.def.ghi');
  });

  it('accepts a lower-case bearer keyword', () => {
    assert.equal(extractToken({ headers: { authorization: 'bearer abc' } }), 'abc');
  });

  it('accepts the capitalised header name', () => {
    assert.equal(extractToken({ headers: { Authorization: 'Bearer abc' } }), 'abc');
  });

  it('ignores a non-bearer authorization scheme', () => {
    assert.equal(extractToken({ headers: { authorization: 'Basic dXNlcjpwdw==' } }), null);
  });

  it('falls back to the query string last', () => {
    assert.equal(extractToken({ query: { token: 'from-query' } }), 'from-query');
  });

  it('returns null when there is nothing to find', () => {
    assert.equal(extractToken({}), null);
    assert.equal(extractToken({ auth: {}, headers: {}, query: {} }), null);
  });

  it('ignores non-string values', () => {
    assert.equal(extractToken({ auth: { token: 12345 } }), null);
    assert.equal(extractToken({ auth: { token: '' } }), null);
  });
});

describe('authoriseConnection', () => {
  it('accepts a socket with a valid token', () => {
    const result = authoriseConnection({ auth: { token: 'good' } }, acceptAll);
    assert.ok(result.ok);
    assert.equal(result.value.userId, USER_ID);
    assert.equal(result.value.sessionId, 'session-1');
  });

  it('rejects a socket with no token', () => {
    const result = authoriseConnection({}, acceptAll);
    assert.ok(!result.ok);
    assert.equal(result.code, 'unauthorized');
  });

  it('passes the verifier failure through, so the client knows to refresh', () => {
    const result = authoriseConnection({ auth: { token: 'expired' } }, rejectAll);
    assert.ok(!result.ok);
    assert.equal(result.code, 'token_expired');
  });

  it('never echoes the presented token', () => {
    const result = authoriseConnection({ auth: { token: 'super-secret-token' } }, rejectAll);
    assert.ok(!JSON.stringify(result).includes('super-secret-token'));
  });
});

describe('decideSubscription', () => {
  const identity = { userId: USER_ID, sessionId: 'session-1' };

  it('allows a server the user owns', () => {
    const result = decideSubscription({
      identity,
      serverId: SERVER_ID,
      ownedServerIds: [SERVER_ID],
    });
    assert.ok(result.ok);
    assert.equal(result.value, `server:${SERVER_ID}`);
  });

  it('is case-insensitive about the id', () => {
    const result = decideSubscription({
      identity,
      serverId: SERVER_ID.toUpperCase(),
      ownedServerIds: [SERVER_ID],
    });
    assert.ok(result.ok);
    assert.equal(result.value, `server:${SERVER_ID}`);
  });

  it("denies a server the user doesn't own", () => {
    const result = decideSubscription({
      identity,
      serverId: OTHER_SERVER_ID,
      ownedServerIds: [SERVER_ID],
    });
    assert.ok(!result.ok);
    assert.equal(result.code, 'subscription_denied');
  });

  it('denies when the user owns nothing', () => {
    assert.ok(!decideSubscription({ identity, serverId: SERVER_ID, ownedServerIds: [] }).ok);
  });

  it('rejects a non-UUID server id before it can become a room name', () => {
    for (const serverId of ['*', '', '../admin', 'server:*', null, 42, {}]) {
      const result = decideSubscription({ identity, serverId, ownedServerIds: [SERVER_ID] });
      assert.ok(!result.ok, `expected ${String(serverId)} to be rejected`);
      assert.equal(result.code, 'subscription_invalid');
    }
  });

  it('gives an unowned and a nonexistent server the same sentence', () => {
    const denied = decideSubscription({
      identity,
      serverId: OTHER_SERVER_ID,
      ownedServerIds: [SERVER_ID],
    });
    const invalid = decideSubscription({ identity, serverId: 'nope', ownedServerIds: [] });
    assert.ok(!denied.ok && !invalid.ok);
    assert.equal(denied.message, invalid.message);
  });
});

describe('initialRooms', () => {
  it('joins the account room only', () => {
    assert.deepEqual(initialRooms({ userId: USER_ID, sessionId: 's' }), [`user:${USER_ID}`]);
  });
});

describe('event envelopes', () => {
  it('builds a status event', () => {
    const event = buildStatusEvent(
      SERVER_ID,
      {
        status: 'DEGRADED',
        health: { state: 'warning', reason: 'Storage is 82% full.', primaryAction: 'server.storage' },
        lastSeenAt: AT.toISOString(),
      },
      AT,
    );
    assert.equal(event.type, 'server.status');
    assert.equal(event.serverId, SERVER_ID);
    assert.equal(event.at, '2026-09-12T10:00:00.000Z');
    assert.equal(event.payload.health.state, 'warning');
  });

  it('builds an activity event', () => {
    const event = buildActivityEvent(
      SERVER_ID,
      { id: 'a1', kind: 'docker.container.restart', summary: 'Restarted API', result: 'SUCCEEDED' },
      AT,
    );
    assert.equal(event.type, 'activity.created');
    assert.equal(event.payload.summary, 'Restarted API');
  });

  it('allows an account-level activity with no server', () => {
    const event = buildActivityEvent(
      null,
      { id: 'a1', kind: 'server.create', summary: 'Added Production', result: 'SUCCEEDED' },
      AT,
    );
    assert.equal(event.serverId, null);
  });

  it('is JSON-serialisable, which is what goes on the wire', () => {
    const event = buildActivityEvent(
      SERVER_ID,
      { id: 'a1', kind: 'server.create', summary: 'x', result: 'SUCCEEDED' },
      AT,
    );
    assert.doesNotThrow(() => JSON.stringify(event));
  });
});

describe('routeFor', () => {
  it('routes a server event to the server room', () => {
    const event = buildActivityEvent(
      SERVER_ID,
      { id: 'a', kind: 'server.update', summary: 's', result: 'SUCCEEDED' },
      AT,
    );
    assert.equal(routeFor(event, USER_ID), `server:${SERVER_ID}`);
  });

  it('routes an account event to the account room', () => {
    const event = buildActivityEvent(
      null,
      { id: 'a', kind: 'server.create', summary: 's', result: 'SUCCEEDED' },
      AT,
    );
    assert.equal(routeFor(event, USER_ID), `user:${USER_ID}`);
  });
});
