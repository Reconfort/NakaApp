// Prisma 7 configuration.
//
// `import "dotenv/config"` is NOT optional and must stay first: Prisma 7 no
// longer auto-loads `.env` (docs/reference/backend-stack.md §2.4). Without it,
// `env("DATABASE_URL")` resolves to undefined and every CLI command fails with
// an unhelpful connection error that looks like a database problem.
import 'dotenv/config';
import { defineConfig, env } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    // Seeding no longer runs automatically in v7; invoke `prisma db seed`.
    seed: 'tsx prisma/seed.ts',
  },
  // `url` lives here rather than in the `datasource` block — `url`,
  // `directUrl` and `shadowDatabaseUrl` are all deprecated there in v7.
  datasource: {
    url: env('DATABASE_URL'),
  },
});
