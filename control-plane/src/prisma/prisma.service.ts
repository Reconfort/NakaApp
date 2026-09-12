import { Injectable, type OnModuleDestroy, type OnModuleInit } from '@nestjs/common';
import { PrismaPg } from '@prisma/adapter-pg';

// Generated client, imported from the generator's `output` directory — NOT from
// `@prisma/client`. Prisma 7 made `output` mandatory and removed the implicit
// node_modules target (docs/reference/backend-stack.md §2.3). The `.js`
// extension is required by ESM resolution even though the source is `.ts`.
import { PrismaClient } from '../generated/prisma/client.js';

/**
 * The database handle, as a Nest provider.
 *
 * Two Prisma 7 constraints are load-bearing here and should not be "simplified"
 * back to the older shape:
 *
 *   1. **The driver adapter is mandatory.** The Rust query engine is gone, so
 *      `new PrismaClient()` with no adapter throws at construction. See
 *      docs/reference/backend-stack.md §2.5.
 *   2. **`$use` middleware no longer exists.** The append-only guard below is a
 *      client extension (`$extends`), which is the replacement. Any 2024-era
 *      `prisma.$use(async (params, next) => …)` snippet will not compile.
 */
@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    super({
      adapter: new PrismaPg({ connectionString: process.env['DATABASE_URL'] ?? '' }),
      // `error` and `warn` only: Prisma's `query` log writes the full SQL
      // including bound parameters, which for this schema means password
      // hashes and token hashes in the application log.
      log: ['error', 'warn'],
    });
  }

  async onModuleInit(): Promise<void> {
    await this.$connect();
  }

  async onModuleDestroy(): Promise<void> {
    await this.$disconnect();
  }
}

/**
 * Wraps a client so `Activity` and `AuditLog` can only ever be appended to.
 *
 * Both tables are evidence. Enforcing that in one extension is stronger than
 * relying on nobody writing `activity.deleteMany()` during a cleanup task, and
 * it is the Prisma 7 replacement for the `$use` middleware that would have done
 * this before.
 *
 * Returned as a separate value rather than applied inside the constructor
 * because `$extends` returns a structurally different client type; consumers
 * that need the guard inject this, and migrations that legitimately need to
 * prune old rows use the raw client explicitly.
 */
export function withAppendOnlyGuard(client: PrismaClient): ReturnType<PrismaClient['$extends']> {
  const protectedModels = new Set(['Activity', 'AuditLog']);
  const forbidden = new Set([
    'update',
    'updateMany',
    'delete',
    'deleteMany',
    'upsert',
    'updateManyAndReturn',
  ]);

  return client.$extends({
    name: 'append-only-audit',
    query: {
      $allModels: {
        async $allOperations({ model, operation, args, query }): Promise<unknown> {
          if (model !== undefined && protectedModels.has(model) && forbidden.has(operation)) {
            throw new Error(
              `${model} is append-only; ${operation} is not permitted through this client.`,
            );
          }
          return query(args);
        },
      },
    },
  });
}
