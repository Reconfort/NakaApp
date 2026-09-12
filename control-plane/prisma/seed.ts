/**
 * Development seed.
 *
 * Run with `npx prisma db seed` — Prisma 7 no longer runs it automatically
 * after a migration (docs/reference/backend-stack.md §4.3).
 *
 * Refuses to run against a production database. A seed that creates a known
 * account with a known password is a backdoor if it ever runs somewhere real,
 * so the guard is a hard exit rather than a warning.
 */

import 'dotenv/config';

import argon2 from 'argon2';
import { PrismaPg } from '@prisma/adapter-pg';

import { PrismaClient } from '../src/generated/prisma/client.js';

async function main(): Promise<void> {
  if (process.env['NODE_ENV'] === 'production') {
    throw new Error('Refusing to seed a production database.');
  }

  const adapter = new PrismaPg({ connectionString: process.env['DATABASE_URL'] ?? '' });
  const prisma = new PrismaClient({ adapter });

  try {
    const email = 'dev@serveros.local';
    const passwordHash = await argon2.hash('development-passphrase', {
      type: argon2.argon2id,
      memoryCost: 65_536,
      timeCost: 3,
      parallelism: 4,
    });

    const user = await prisma.user.upsert({
      where: { email },
      update: {},
      create: { email, name: 'Development User', passwordHash },
    });

    await prisma.server.upsert({
      where: { ownerId_name: { ownerId: user.id, name: 'Production' } },
      update: {},
      create: {
        ownerId: user.id,
        name: 'Production',
        hostname: 'prod.example.test',
        sshUsername: 'deploy',
        os: 'Ubuntu 24.04',
        arch: 'x86_64',
        tags: ['prod'],
      },
    });

    process.stdout.write(`Seeded ${email}\n`);
  } finally {
    await prisma.$disconnect();
  }
}

await main();
