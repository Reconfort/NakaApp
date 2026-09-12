import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import {
  AppError,
  isHttpExceptionLike,
  isPrismaKnownError,
  isSchemaErrorLike,
  looksSafeSentence,
  mapErrorToEnvelope,
} from './error-mapping.logic.js';

/** Stands in for a Prisma known-request error without importing Prisma. */
function prismaError(code: string, message: string, meta?: unknown): unknown {
  const error = new Error(message) as Error & { code: string; meta?: unknown };
  error.code = code;
  if (meta !== undefined) error.meta = meta;
  return error;
}

/** Stands in for a Nest HttpException without importing @nestjs/common. */
function httpException(status: number, response: unknown): unknown {
  return {
    getStatus: () => status,
    getResponse: () => response,
    message: typeof response === 'string' ? response : 'Http Exception',
  };
}

describe('recognisers', () => {
  it('recognises a Prisma error by its code shape', () => {
    assert.ok(isPrismaKnownError(prismaError('P2002', 'Unique failed')));
    assert.ok(!isPrismaKnownError(new Error('plain')));
    assert.ok(!isPrismaKnownError({ code: 'ENOENT' }));
    assert.ok(!isPrismaKnownError({ code: 'P22' }));
    assert.ok(!isPrismaKnownError(null));
  });

  it('recognises an HttpException structurally', () => {
    assert.ok(isHttpExceptionLike(httpException(404, 'Not Found')));
    assert.ok(!isHttpExceptionLike(new Error('plain')));
  });

  it('recognises a zod error structurally', () => {
    assert.ok(isSchemaErrorLike({ issues: [] }));
    assert.ok(!isSchemaErrorLike({ issues: 'nope' }));
  });
});

describe('AppError', () => {
  it('passes its code, sentence and status through', () => {
    const mapped = mapErrorToEnvelope(
      new AppError('enrollment_code_expired', 'That code has expired.', 410),
    );
    assert.equal(mapped.status, 410);
    assert.equal(mapped.body.error.code, 'enrollment_code_expired');
    assert.equal(mapped.body.error.message, 'That code has expired.');
    assert.equal(mapped.logLevel, 'warn');
  });

  it('carries an explicit detail through', () => {
    const mapped = mapErrorToEnvelope(new AppError('x_failed', 'It failed.', 400, 'field: name'));
    assert.equal(mapped.body.error.detail, 'field: name');
  });

  it('omits detail entirely when there is none', () => {
    const mapped = mapErrorToEnvelope(new AppError('x_failed', 'It failed.', 400));
    assert.ok(!('detail' in mapped.body.error));
    assert.ok(!JSON.stringify(mapped.body).includes('detail'));
  });

  it('logs at error level for a 5xx AppError', () => {
    assert.equal(mapErrorToEnvelope(new AppError('x', 'y', 503)).logLevel, 'error');
  });
});

describe('Prisma mapping', () => {
  it('maps P2002 to 409 already_exists', () => {
    const mapped = mapErrorToEnvelope(prismaError('P2002', 'Unique constraint failed'));
    assert.equal(mapped.status, 409);
    assert.equal(mapped.body.error.code, 'already_exists');
  });

  it('names the violated constraint in detail, not in the sentence', () => {
    const mapped = mapErrorToEnvelope(
      prismaError('P2002', 'Unique constraint failed', { target: ['ownerId', 'name'] }),
    );
    assert.equal(mapped.body.error.detail, 'unique constraint: ownerId, name');
    assert.doesNotMatch(mapped.body.error.message, /ownerId/);
  });

  it('handles a string target', () => {
    const mapped = mapErrorToEnvelope(
      prismaError('P2002', 'Unique constraint failed', { target: 'User_email_key' }),
    );
    assert.equal(mapped.body.error.detail, 'unique constraint: User_email_key');
  });

  it('maps P2025 to 404 not_found', () => {
    const mapped = mapErrorToEnvelope(prismaError('P2025', 'Record to update not found'));
    assert.equal(mapped.status, 404);
    assert.equal(mapped.body.error.code, 'not_found');
  });

  it('maps P2003 to 409', () => {
    const mapped = mapErrorToEnvelope(prismaError('P2003', 'Foreign key constraint failed'));
    assert.equal(mapped.status, 409);
    assert.equal(mapped.body.error.code, 'related_record_missing');
  });

  it('maps P2000 to 400', () => {
    const mapped = mapErrorToEnvelope(prismaError('P2000', 'Value too long for column'));
    assert.equal(mapped.status, 400);
    assert.equal(mapped.body.error.code, 'value_too_long');
  });

  it('collapses an unmapped Prisma code to a generic 500', () => {
    const mapped = mapErrorToEnvelope(
      prismaError('P2021', 'The table `public.Server` does not exist in the current database.'),
    );
    assert.equal(mapped.status, 500);
    assert.equal(mapped.body.error.code, 'internal_error');
    assert.equal(mapped.body.error.message, 'Something went wrong on our side.');
  });

  it('never lets a Prisma message reach the client', () => {
    const mapped = mapErrorToEnvelope(
      prismaError('P2002', 'Unique constraint failed on the fields: (`email`)'),
    );
    const serialised = JSON.stringify(mapped.body);
    assert.ok(!serialised.includes('Unique constraint failed on the fields'));
  });

  it('keeps the Prisma code and message in the log detail', () => {
    const mapped = mapErrorToEnvelope(prismaError('P2002', 'Unique constraint failed'));
    assert.match(mapped.logDetail, /prisma P2002/);
    assert.match(mapped.logDetail, /Unique constraint failed/);
  });
});

describe('schema validation mapping', () => {
  it('maps a zod error to 400 validation_failed', () => {
    const mapped = mapErrorToEnvelope({
      issues: [{ path: ['hostname'], code: 'invalid_string', message: 'Invalid' }],
    });
    assert.equal(mapped.status, 400);
    assert.equal(mapped.body.error.code, 'validation_failed');
    assert.equal(mapped.body.error.message, 'Some of those details were not valid.');
  });

  it('lists field paths in detail', () => {
    const mapped = mapErrorToEnvelope({
      issues: [
        { path: ['hostname'], code: 'invalid_string' },
        { path: ['sshPort'], code: 'too_big' },
      ],
    });
    assert.equal(mapped.body.error.detail, 'hostname: invalid_string, sshPort: too_big');
  });

  it('never includes the submitted value', () => {
    const mapped = mapErrorToEnvelope({
      issues: [{ path: ['password'], code: 'too_small', message: 'received "hunter2"' }],
    });
    assert.ok(!JSON.stringify(mapped.body).includes('hunter2'));
  });

  it('caps a long issue list', () => {
    const mapped = mapErrorToEnvelope({
      issues: Array.from({ length: 40 }, (_, i) => ({ path: [`f${i}`], code: 'invalid' })),
    });
    assert.match(mapped.body.error.detail ?? '', /and 28 more/);
  });

  it('handles an empty issue list without an empty detail key', () => {
    const mapped = mapErrorToEnvelope({ issues: [] });
    assert.ok(!('detail' in mapped.body.error));
  });

  it('handles an issue with no path', () => {
    const mapped = mapErrorToEnvelope({ issues: [{ code: 'invalid_type' }] });
    assert.equal(mapped.body.error.detail, 'invalid_type');
  });
});

describe('HttpException mapping', () => {
  it('maps a 404 to not_found with a human sentence', () => {
    const mapped = mapErrorToEnvelope(httpException(404, 'Not Found'));
    assert.equal(mapped.status, 404);
    assert.equal(mapped.body.error.code, 'not_found');
  });

  it("replaces Nest's reason phrase with our own copy", () => {
    // `throw new ForbiddenException()` yields the response "Forbidden", which
    // is a status name rather than something a person should be shown.
    const mapped = mapErrorToEnvelope(httpException(403, 'Forbidden'));
    assert.equal(mapped.body.error.message, "You don't have access to that.");
  });

  it('adopts a finished sentence a handler wrote deliberately', () => {
    const mapped = mapErrorToEnvelope(httpException(409, 'That server is already registered.'));
    assert.equal(mapped.body.error.message, 'That server is already registered.');
  });

  it('maps a 401 to unauthorized', () => {
    assert.equal(mapErrorToEnvelope(httpException(401, 'Unauthorized')).body.error.code, 'unauthorized');
  });

  it('maps a 429 to rate_limited', () => {
    assert.equal(mapErrorToEnvelope(httpException(429, 'Too Many')).body.error.code, 'rate_limited');
  });

  it('adopts a code our own guard already chose', () => {
    const mapped = mapErrorToEnvelope(
      httpException(401, { error: { code: 'token_expired', message: 'Sign in again.' } }),
    );
    assert.equal(mapped.body.error.code, 'token_expired');
    assert.equal(mapped.body.error.message, 'Sign in again.');
  });

  it('forces a generic sentence for a 5xx however it was phrased', () => {
    const mapped = mapErrorToEnvelope(
      httpException(500, 'ServersService.findOne failed at /app/src/servers/servers.service.ts'),
    );
    assert.equal(mapped.body.error.message, 'Something went wrong on our side.');
    assert.equal(mapped.logLevel, 'error');
  });

  it('refuses a framework message that looks like a stack trace', () => {
    const mapped = mapErrorToEnvelope(
      httpException(400, 'at ServersService.create (/app/src/servers/servers.service.ts:42:11)'),
    );
    assert.equal(mapped.body.error.message, 'That request was not valid.');
  });

  it('refuses a framework message containing SQL', () => {
    const mapped = mapErrorToEnvelope(httpException(400, 'SELECT * FROM "Server" WHERE id = $1'));
    assert.equal(mapped.body.error.message, 'That request was not valid.');
  });

  it('refuses a class-validator array of messages', () => {
    const mapped = mapErrorToEnvelope(
      httpException(400, { statusCode: 400, message: ['name must be a string'] }),
    );
    assert.equal(mapped.body.error.message, 'That request was not valid.');
  });

  it('normalises a nonsense status to 500', () => {
    assert.equal(mapErrorToEnvelope(httpException(99, 'weird')).status, 500);
    assert.equal(mapErrorToEnvelope(httpException(Number.NaN, 'weird')).status, 500);
  });
});

describe('unknown throwables', () => {
  it('maps a plain Error to a generic 500', () => {
    const mapped = mapErrorToEnvelope(new Error('connect ECONNREFUSED 10.0.0.5:5432'));
    assert.equal(mapped.status, 500);
    assert.equal(mapped.body.error.code, 'internal_error');
    assert.equal(mapped.body.error.message, 'Something went wrong on our side.');
  });

  it('never leaks a stack trace to the client', () => {
    const mapped = mapErrorToEnvelope(new Error('boom'));
    assert.ok(!JSON.stringify(mapped.body).includes('error-mapping.logic.test'));
    assert.match(mapped.logDetail, /error-mapping.logic.test/);
  });

  it('never leaks a connection string to the client', () => {
    const mapped = mapErrorToEnvelope(new Error('postgres://app:hunter2@db:5432/serveros'));
    assert.ok(!JSON.stringify(mapped.body).includes('hunter2'));
  });

  it('handles a thrown string', () => {
    const mapped = mapErrorToEnvelope('something broke');
    assert.equal(mapped.status, 500);
    assert.equal(mapped.logDetail, 'something broke');
  });

  it('handles a thrown null and undefined', () => {
    assert.equal(mapErrorToEnvelope(null).status, 500);
    assert.equal(mapErrorToEnvelope(undefined).status, 500);
  });

  it('handles a thrown object with a circular reference', () => {
    const circular: Record<string, unknown> = { a: 1 };
    circular['self'] = circular;
    assert.doesNotThrow(() => mapErrorToEnvelope(circular));
    assert.equal(mapErrorToEnvelope(circular).status, 500);
  });
});

describe('envelope invariants', () => {
  const samples: unknown[] = [
    new AppError('a_code', 'A sentence.', 400),
    prismaError('P2002', 'Unique constraint failed'),
    prismaError('P2021', 'Table does not exist'),
    { issues: [{ path: ['a'], code: 'x' }] },
    httpException(403, 'Forbidden'),
    httpException(500, 'Internal Server Error'),
    new Error('boom'),
    'thrown string',
    null,
  ];

  it('always produces a snake_case code', () => {
    for (const sample of samples) {
      assert.match(mapErrorToEnvelope(sample).body.error.code, /^[a-z][a-z0-9_]*$/);
    }
  });

  it('always produces a sentence ending in a full stop', () => {
    for (const sample of samples) {
      assert.match(mapErrorToEnvelope(sample).body.error.message, /\.$/);
    }
  });

  it('always produces a status in the 4xx/5xx range', () => {
    for (const sample of samples) {
      const { status } = mapErrorToEnvelope(sample);
      assert.ok(status >= 400 && status <= 599, `bad status ${status}`);
    }
  });

  it('matches the agent envelope shape exactly', () => {
    for (const sample of samples) {
      const { body } = mapErrorToEnvelope(sample);
      assert.deepEqual(Object.keys(body), ['error']);
      const keys = Object.keys(body.error).sort();
      assert.ok(
        keys.join(',') === 'code,message' || keys.join(',') === 'code,detail,message',
        `unexpected envelope keys: ${keys.join(',')}`,
      );
    }
  });

  it('never sends a null detail — absent means absent, as in the agent', () => {
    for (const sample of samples) {
      const serialised = JSON.stringify(mapErrorToEnvelope(sample).body);
      assert.ok(!serialised.includes('"detail":null'));
    }
  });

  it('always produces a log line', () => {
    for (const sample of samples) {
      assert.ok(mapErrorToEnvelope(sample).logDetail.length > 0);
    }
  });
});

describe('looksSafeSentence', () => {
  it('accepts an ordinary sentence', () => {
    assert.ok(looksSafeSentence('That server is already registered.'));
  });

  it('rejects an empty or enormous string', () => {
    assert.ok(!looksSafeSentence(''));
    assert.ok(!looksSafeSentence(`${'a'.repeat(500)}.`));
  });

  it('rejects a bare HTTP reason phrase — a status name is not copy', () => {
    for (const phrase of ['Forbidden', 'Not Found', 'Unauthorized', 'Internal Server Error']) {
      assert.ok(!looksSafeSentence(phrase), `expected ${phrase} to be rejected`);
    }
  });

  it('accepts a question, which is still a finished sentence', () => {
    assert.ok(looksSafeSentence('Did you mean to delete that server?'));
  });

  it('rejects multi-line text', () => {
    assert.ok(!looksSafeSentence('line one\nline two'));
  });

  it('rejects a file path', () => {
    assert.ok(!looksSafeSentence('failed in /home/app/src/main.ts'));
    assert.ok(!looksSafeSentence('failed in C:\\app\\main.ts'));
  });

  it('rejects a URL or connection string', () => {
    assert.ok(!looksSafeSentence('could not reach https://internal.svc'));
    assert.ok(!looksSafeSentence('postgres connection lost'));
  });

  it('rejects errno codes', () => {
    assert.ok(!looksSafeSentence('ECONNREFUSED'));
    assert.ok(!looksSafeSentence('EACCES opening the socket'));
  });
});
