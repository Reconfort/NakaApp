import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  ACTIONS,
  CPU_WARNING_PERCENT,
  DISK_CRITICAL_PERCENT,
  DISK_WARNING_PERCENT,
  MEMORY_WARNING_PERCENT,
  OFFLINE_AFTER_SECONDS,
  computeHealth,
  describeSilence,
  shouldRecordStatusChange,
  statusForVerdict,
  type HealthInput,
  type ServerStatusValue,
} from './health.logic.js';

const NOW = new Date('2026-09-12T10:00:00.000Z');

/** A server that is fine in every respect; each test perturbs one thing. */
function healthy(overrides: Partial<HealthInput> = {}): HealthInput {
  return {
    cpuPercent: 23,
    memoryPercent: 61,
    diskPercent: 48,
    agentLastSeenAt: new Date(NOW.getTime() - 5_000),
    containersStopped: 0,
    servicesFailed: 0,
    ...overrides,
  };
}

function verdict(overrides: Partial<HealthInput> = {}) {
  return computeHealth(healthy(overrides), NOW);
}

describe('computeHealth — healthy', () => {
  it('reports healthy with nothing to say and nothing to do', () => {
    const result = verdict();
    assert.equal(result.state, 'healthy');
    assert.equal(result.reason, null);
    assert.equal(result.primaryAction, null);
  });

  it('stays healthy at a freshly seen agent with idle metrics', () => {
    assert.equal(verdict({ cpuPercent: 0, memoryPercent: 0, diskPercent: 0 }).state, 'healthy');
  });

  it('stays healthy one point below every warning threshold', () => {
    const result = verdict({
      diskPercent: DISK_WARNING_PERCENT - 1,
      cpuPercent: CPU_WARNING_PERCENT - 1,
      memoryPercent: MEMORY_WARNING_PERCENT - 1,
    });
    assert.equal(result.state, 'healthy');
  });

  it('stays healthy when metrics have not been reported yet but the agent is live', () => {
    const result = verdict({ cpuPercent: null, memoryPercent: null, diskPercent: null });
    assert.equal(result.state, 'healthy');
  });
});

describe('computeHealth — offline', () => {
  it('is offline when the agent has never been seen', () => {
    const result = verdict({ agentLastSeenAt: null });
    assert.equal(result.state, 'offline');
    assert.equal(result.reason, "ServerOS hasn't connected to this server yet.");
    assert.equal(result.primaryAction, ACTIONS.reconnect);
  });

  it('is offline once the agent has been silent past the threshold', () => {
    const result = verdict({
      agentLastSeenAt: new Date(NOW.getTime() - (OFFLINE_AFTER_SECONDS + 1) * 1000),
    });
    assert.equal(result.state, 'offline');
    assert.equal(result.primaryAction, ACTIONS.reconnect);
  });

  it('is not offline exactly at the threshold', () => {
    const result = verdict({
      agentLastSeenAt: new Date(NOW.getTime() - OFFLINE_AFTER_SECONDS * 1000),
    });
    assert.notEqual(result.state, 'offline');
  });

  it('is offline for a very stale agent', () => {
    const result = verdict({ agentLastSeenAt: new Date(NOW.getTime() - 86_400_000) });
    assert.equal(result.state, 'offline');
    assert.match(result.reason ?? '', /1 days|24 hours/);
  });

  it('outranks a failed service — stale telemetry cannot be trusted', () => {
    const result = verdict({
      agentLastSeenAt: new Date(NOW.getTime() - 600_000),
      servicesFailed: 3,
      diskPercent: 99,
    });
    assert.equal(result.state, 'offline');
  });

  it('handles an invalid timestamp without crashing', () => {
    const result = verdict({ agentLastSeenAt: new Date('not a date') });
    assert.equal(result.state, 'offline');
    assert.ok(result.reason !== null);
  });

  it('does not go offline when the agent clock is slightly ahead of ours', () => {
    const result = verdict({ agentLastSeenAt: new Date(NOW.getTime() + 5_000) });
    assert.equal(result.state, 'healthy');
  });
});

describe('computeHealth — critical', () => {
  it('is critical when one service has failed', () => {
    const result = verdict({ servicesFailed: 1 });
    assert.equal(result.state, 'critical');
    assert.equal(result.reason, 'A service has failed and is not running.');
    assert.equal(result.primaryAction, ACTIONS.services);
  });

  it('pluralises multiple failed services', () => {
    const result = verdict({ servicesFailed: 4 });
    assert.equal(result.reason, '4 services have failed and are not running.');
  });

  it('is critical at the disk critical threshold', () => {
    const result = verdict({ diskPercent: DISK_CRITICAL_PERCENT });
    assert.equal(result.state, 'critical');
    assert.equal(result.reason, 'Storage is 95% full and about to run out.');
    assert.equal(result.primaryAction, ACTIONS.storage);
  });

  it('is critical at a completely full disk', () => {
    assert.equal(verdict({ diskPercent: 100 }).state, 'critical');
  });

  it('is only a warning one point below the critical disk threshold', () => {
    const result = verdict({ diskPercent: DISK_CRITICAL_PERCENT - 1 });
    assert.equal(result.state, 'warning');
  });

  it('ranks a failed service above a full disk', () => {
    const result = verdict({ servicesFailed: 1, diskPercent: 99 });
    assert.equal(result.reason, 'A service has failed and is not running.');
    assert.equal(result.primaryAction, ACTIONS.services);
  });

  it('outranks every warning', () => {
    const result = verdict({
      servicesFailed: 1,
      cpuPercent: 99,
      memoryPercent: 99,
      containersStopped: 5,
    });
    assert.equal(result.state, 'critical');
  });
});

describe('computeHealth — warning', () => {
  it('warns at the disk warning threshold', () => {
    const result = verdict({ diskPercent: DISK_WARNING_PERCENT });
    assert.equal(result.state, 'warning');
    assert.equal(result.reason, 'Storage is 80% full.');
    assert.equal(result.primaryAction, ACTIONS.storage);
  });

  it('rounds a fractional disk percentage for display', () => {
    assert.equal(verdict({ diskPercent: 82.4183 }).reason, 'Storage is 82% full.');
  });

  it('warns at sustained high CPU', () => {
    const result = verdict({ cpuPercent: CPU_WARNING_PERCENT });
    assert.equal(result.state, 'warning');
    assert.equal(result.reason, 'CPU has been at 90% for a sustained period.');
    assert.equal(result.primaryAction, ACTIONS.processes);
  });

  it('warns at high memory', () => {
    const result = verdict({ memoryPercent: MEMORY_WARNING_PERCENT });
    assert.equal(result.state, 'warning');
    assert.equal(result.reason, 'Memory is 90% used.');
  });

  it('warns when a single container is stopped, in the singular', () => {
    const result = verdict({ containersStopped: 1 });
    assert.equal(result.state, 'warning');
    assert.equal(result.reason, '1 container is stopped.');
    assert.equal(result.primaryAction, ACTIONS.docker);
  });

  it('pluralises multiple stopped containers', () => {
    assert.equal(verdict({ containersStopped: 3 }).reason, '3 containers are stopped.');
  });

  it('ranks disk pressure above CPU', () => {
    const result = verdict({ diskPercent: 85, cpuPercent: 99 });
    assert.equal(result.primaryAction, ACTIONS.storage);
  });

  it('ranks CPU above memory', () => {
    const result = verdict({ cpuPercent: 95, memoryPercent: 95 });
    assert.match(result.reason ?? '', /^CPU/);
  });

  it('ranks memory above a stopped container', () => {
    const result = verdict({ memoryPercent: 95, containersStopped: 2 });
    assert.match(result.reason ?? '', /^Memory/);
  });

  it('returns exactly one reason even when everything is wrong at once', () => {
    const result = verdict({
      diskPercent: 88,
      cpuPercent: 99,
      memoryPercent: 99,
      containersStopped: 9,
    });
    assert.equal(result.state, 'warning');
    assert.equal((result.reason ?? '').split('.').filter((s) => s.trim() !== '').length, 1);
  });
});

describe('computeHealth — hostile inputs', () => {
  it('treats NaN as unknown rather than as zero', () => {
    // Clamping NaN to 0 would report a full disk as healthy.
    assert.equal(verdict({ diskPercent: Number.NaN }).state, 'healthy');
  });

  it('treats Infinity as unknown', () => {
    assert.equal(verdict({ cpuPercent: Number.POSITIVE_INFINITY }).state, 'healthy');
  });

  it('treats an out-of-range percentage as unknown', () => {
    assert.equal(verdict({ diskPercent: 1000 }).state, 'healthy');
    assert.equal(verdict({ diskPercent: -5 }).state, 'healthy');
  });

  it('treats a negative container count as zero', () => {
    assert.equal(verdict({ containersStopped: -3 }).state, 'healthy');
  });

  it('floors a fractional count', () => {
    assert.equal(verdict({ containersStopped: 2.9 }).reason, '2 containers are stopped.');
  });

  it('treats a NaN failure count as zero', () => {
    assert.equal(verdict({ servicesFailed: Number.NaN }).state, 'healthy');
  });

  it('never returns a reason without an action, or an action without a reason', () => {
    const cases: Array<Partial<HealthInput>> = [
      {},
      { servicesFailed: 1 },
      { diskPercent: 99 },
      { diskPercent: 85 },
      { cpuPercent: 95 },
      { memoryPercent: 95 },
      { containersStopped: 1 },
      { agentLastSeenAt: null },
    ];
    for (const override of cases) {
      const result = verdict(override);
      assert.equal(
        result.reason === null,
        result.primaryAction === null,
        `reason/action disagree for ${JSON.stringify(override)}`,
      );
    }
  });

  it('always ends a reason with a full stop', () => {
    const cases: Array<Partial<HealthInput>> = [
      { servicesFailed: 1 },
      { servicesFailed: 7 },
      { diskPercent: 99 },
      { diskPercent: 85 },
      { cpuPercent: 95 },
      { memoryPercent: 95 },
      { containersStopped: 1 },
      { containersStopped: 4 },
      { agentLastSeenAt: null },
      { agentLastSeenAt: new Date(NOW.getTime() - 3_600_000) },
    ];
    for (const override of cases) {
      const reason = verdict(override).reason;
      assert.ok(reason !== null && reason.endsWith('.'), `not a sentence: ${String(reason)}`);
    }
  });

  it('never leaks a raw metric name into user-facing copy', () => {
    const cases: Array<Partial<HealthInput>> = [
      { diskPercent: 85 },
      { cpuPercent: 95 },
      { memoryPercent: 95 },
      { containersStopped: 1 },
    ];
    for (const override of cases) {
      assert.doesNotMatch(verdict(override).reason ?? '', /Percent|null|undefined|NaN/);
    }
  });

  it('defaults `now` to the current time when not supplied', () => {
    const result = computeHealth(healthy({ agentLastSeenAt: new Date() }));
    assert.equal(result.state, 'healthy');
  });
});

describe('describeSilence', () => {
  it('softens a short silence', () => {
    assert.equal(describeSilence(91), 'the last minute or so');
  });

  it('counts whole minutes', () => {
    assert.equal(describeSilence(600), '10 minutes');
  });

  it('uses the singular for one hour', () => {
    assert.equal(describeSilence(3_600), 'an hour');
  });

  it('counts hours up to two days', () => {
    assert.equal(describeSilence(7_200), '2 hours');
  });

  it('switches to days beyond that', () => {
    assert.equal(describeSilence(60 * 60 * 72), '3 days');
  });
});

describe('statusForVerdict', () => {
  const cases: Array<[ReturnType<typeof verdict>['state'], ServerStatusValue]> = [
    ['healthy', 'CONNECTED'],
    ['warning', 'DEGRADED'],
    ['critical', 'DEGRADED'],
    ['offline', 'OFFLINE'],
  ];

  for (const [state, expected] of cases) {
    it(`maps ${state} to ${expected}`, () => {
      assert.equal(
        statusForVerdict({ state, reason: null, primaryAction: null }, 'CONNECTED'),
        expected,
      );
    });
  }

  it('keeps a never-enrolled server PENDING regardless of telemetry', () => {
    assert.equal(
      statusForVerdict({ state: 'healthy', reason: null, primaryAction: null }, 'PENDING'),
      'PENDING',
    );
    assert.equal(
      statusForVerdict({ state: 'offline', reason: null, primaryAction: null }, 'PENDING'),
      'PENDING',
    );
  });
});

describe('shouldRecordStatusChange', () => {
  it('records a transition', () => {
    assert.ok(shouldRecordStatusChange('CONNECTED', 'OFFLINE'));
  });

  it('does not record a heartbeat that changes nothing', () => {
    assert.ok(!shouldRecordStatusChange('CONNECTED', 'CONNECTED'));
  });
});
