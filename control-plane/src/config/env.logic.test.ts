import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { loadConfig, loadConfigOrThrow, type RawEnv } from './env.logic.js';

const GOOD: RawEnv = {
  NODE_ENV: 'production',
  PORT: '3000',
  DATABASE_URL: 'postgresql://serveros:pw@localhost:5432/serveros',
  REDIS_URL: 'redis://localhost:6379',
  JWT_SECRET: 'J'.repeat(48),
  CURSOR_SECRET: 'C'.repeat(48),
};

describe('loadConfig — happy path', () => {
  it('resolves a complete environment', () => {
    const result = loadConfig(GOOD);
    assert.ok(result.ok);
    assert.equal(result.value.nodeEnv, 'production');
    assert.equal(result.value.port, 3000);
  });

  it('applies defaults for optional values', () => {
    const result = loadConfig(GOOD);
    assert.ok(result.ok);
    assert.equal(result.value.jwtIssuer, 'serveros-control-plane');
    assert.equal(result.value.jwtAudience, 'serveros-app');
    assert.equal(result.value.logLevel, 'info');
    assert.equal(result.value.trustProxy, false);
    assert.deepEqual(result.value.corsOrigins, []);
  });

  it('defaults NODE_ENV to development and PORT to 3000', () => {
    const { NODE_ENV: _env, PORT: _port, ...rest } = GOOD;
    const result = loadConfig(rest);
    assert.ok(result.ok);
    assert.equal(result.value.nodeEnv, 'development');
    assert.equal(result.value.port, 3000);
  });

  it('parses a CORS origin list', () => {
    const result = loadConfig({ ...GOOD, CORS_ORIGINS: 'https://a.test, https://b.test ,' });
    assert.ok(result.ok);
    assert.deepEqual(result.value.corsOrigins, ['https://a.test', 'https://b.test']);
  });

  it('only trusts the proxy when explicitly told to', () => {
    assert.ok(loadConfig({ ...GOOD, TRUST_PROXY: 'yes' }).ok);
    const yes = loadConfig({ ...GOOD, TRUST_PROXY: 'true' });
    const almost = loadConfig({ ...GOOD, TRUST_PROXY: '1' });
    assert.ok(yes.ok && almost.ok);
    assert.equal(yes.value.trustProxy, true);
    assert.equal(almost.value.trustProxy, false);
  });
});

describe('loadConfig — refusals', () => {
  const expectFailure = (env: RawEnv, code: string): void => {
    const result = loadConfig(env);
    assert.ok(!result.ok, 'expected configuration to be rejected');
    assert.equal(result.code, code);
  };

  it('refuses a missing DATABASE_URL', () => {
    const { DATABASE_URL: _omitted, ...rest } = GOOD;
    expectFailure(rest, 'config_missing');
  });

  it('refuses a DATABASE_URL that is not a postgres connection string', () => {
    expectFailure({ ...GOOD, DATABASE_URL: 'mysql://localhost/db' }, 'config_invalid');
  });

  it('refuses a missing REDIS_URL', () => {
    const { REDIS_URL: _omitted, ...rest } = GOOD;
    expectFailure(rest, 'config_missing');
  });

  it('accepts rediss:// for TLS', () => {
    assert.ok(loadConfig({ ...GOOD, REDIS_URL: 'rediss://redis.internal:6380' }).ok);
  });

  it('refuses a missing JWT_SECRET', () => {
    const { JWT_SECRET: _omitted, ...rest } = GOOD;
    expectFailure(rest, 'config_missing');
  });

  it('refuses a JWT_SECRET shorter than 32 bytes', () => {
    expectFailure({ ...GOOD, JWT_SECRET: 'tooshort' }, 'config_weak_secret');
  });

  it('refuses a placeholder secret that survived into deployment', () => {
    for (const placeholder of ['change-me-'.repeat(4), `secret${'x'.repeat(40)}`]) {
      expectFailure({ ...GOOD, JWT_SECRET: placeholder }, 'config_weak_secret');
    }
  });

  it('refuses an empty secret that is present but blank', () => {
    expectFailure({ ...GOOD, JWT_SECRET: '   ' }, 'config_missing');
  });

  it('refuses reusing one secret for tokens and cursors', () => {
    expectFailure({ ...GOOD, CURSOR_SECRET: GOOD['JWT_SECRET'] }, 'config_invalid');
  });

  it('refuses an out-of-range port', () => {
    expectFailure({ ...GOOD, PORT: '0' }, 'config_invalid');
    expectFailure({ ...GOOD, PORT: '70000' }, 'config_invalid');
    expectFailure({ ...GOOD, PORT: 'abc' }, 'config_invalid');
  });

  it('refuses an unknown NODE_ENV', () => {
    expectFailure({ ...GOOD, NODE_ENV: 'staging' }, 'config_invalid');
  });

  it('refuses an unknown LOG_LEVEL', () => {
    expectFailure({ ...GOOD, LOG_LEVEL: 'verbose' }, 'config_invalid');
  });

  it('names the offending variable so an operator can act on it', () => {
    const result = loadConfig({ ...GOOD, JWT_SECRET: 'short' });
    assert.ok(!result.ok);
    assert.match(result.message, /JWT_SECRET/);
  });

  it('never echoes a secret value back in the failure', () => {
    const result = loadConfig({ ...GOOD, JWT_SECRET: 'change-me-super-secret-value-here' });
    assert.ok(!result.ok);
    assert.ok(!result.message.includes('super-secret-value-here'));
  });
});

describe('loadConfigOrThrow', () => {
  it('returns the config when valid', () => {
    assert.equal(loadConfigOrThrow(GOOD).port, 3000);
  });

  it('throws with the operator sentence when not', () => {
    assert.throws(() => loadConfigOrThrow({}), /Configuration error: DATABASE_URL is not set\./);
  });
});
