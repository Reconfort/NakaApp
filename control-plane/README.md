# ServerOS Control Plane

Identity, the server registry, enrollment, projects, activity and the live event
stream for ServerOS.

NestJS 12 · Prisma 7 · PostgreSQL 16 · Redis 7 · TypeScript · ESM.

---

## What this service is — and is not

The control plane owns **metadata and identity**. It does not proxy server
operations.

```
macOS app ──HTTPS──▶ Control plane        (accounts, registry, history)
    │
    └────SSH-forwarded channel────▶ Rust agent on the Linux box
```

Restarting a container, reading a log, listing processes: the Mac app talks to
the agent directly. The control plane never connects to a managed server, never
runs a command on one, and — this is the part that constrains the schema —
**never holds a credential for one**.

`model Server` therefore has no `privateKey`, no `password`, no `agentToken`
column, and none may be added. SSH keys and agent secrets live only in the
user's macOS Keychain. The consequence bought deliberately: a full compromise of
this database cannot be turned into shell access anywhere. See the comment above
`model Server` in `prisma/schema.prisma` before changing it.

---

## Setup

```bash
# 1. Dependencies (postgres + redis, bound to 127.0.0.1 only)
docker compose up -d

# 2. Node packages. Requires Node 24.x (Active LTS).
npm install

# 3. Environment
cp .env.example .env
# Then fill in JWT_SECRET and CURSOR_SECRET — both are required, both must be
# at least 32 bytes, and they must differ from each other:
#   openssl rand -base64 48

# 4. Database
npx prisma migrate dev

# 5. Run
npm run start:dev
```

`npm install` runs `prisma generate` via `postinstall`. The client is emitted to
`src/generated/prisma` (git-ignored) — Prisma 7 requires an explicit `output`
and no longer writes into `node_modules`.

### Scripts

| Script | What it does |
|---|---|
| `npm run build` | `prisma generate && nest build` |
| `npm start` | Runs `dist/main.js` |
| `npm run start:dev` | Watch mode |
| `npm test` | The pure-logic suite — needs only `tsx`, no `node_modules` |
| `npm run test:logic` | Same suite, named for clarity |
| `npm run typecheck` | Full project — needs the whole `node_modules` |
| `npm run typecheck:logic` | Pure layer only — needs just `@types/node` |
| `npm run prisma:generate` | Regenerate the client |
| `npm run prisma:migrate` | `prisma migrate dev` |

---

## Architecture: the `.logic.ts` split

Every feature folder is two layers.

- **`*.logic.ts`** — pure. Imports nothing but Node built-ins and other
  `.logic.ts` files. No NestJS, no Prisma, no network, no clock (time is always
  a parameter). Holds every decision: token verification, the health rollup, the
  enrollment state machine, refresh-token reuse detection, metadata redaction,
  cursor signing, error mapping.
- **The Nest layer** — controllers, services, gateway, guards. Loads rows, calls
  the logic layer, writes rows.

This is not ceremony. It means the security-critical code runs its full test
matrix with **zero installed dependencies and no database**, and it means
`tsconfig.logic.json` can enforce stricter settings (`noUncheckedIndexedAccess`,
`exactOptionalPropertyTypes`) than the framework layer can satisfy.

Rule for contributors: if adding an import to a `*.logic.ts` file breaks
`npm run typecheck:logic`, the import belongs in the Nest layer.

### The error envelope

Every failure — from this service and from the Rust agent — is the same shape,
so the macOS app has one rendering path:

```json
{ "error": { "code": "snake_case_code", "message": "Human sentence.", "detail": "optional technical string" } }
```

`detail` is **omitted** when absent, never `null` — matching
`agent/crates/http/src/response.rs`. A stack trace, a SQL fragment, a Prisma
message or a connection string never reaches a client;
`mapErrorToEnvelope` returns those separately as `logDetail` for the server log.

---

## API

| Method | Path | Auth | |
|---|---|---|---|
| POST | `/v1/auth/register` | public | |
| POST | `/v1/auth/login` | public | |
| POST | `/v1/auth/refresh` | public | rotates; reuse kills the family |
| POST | `/v1/auth/logout` | public | revokes the family |
| GET | `/v1/users/me` | bearer | |
| GET/POST | `/v1/servers` | bearer | |
| GET/PUT/DELETE | `/v1/servers/:id` | bearer | |
| POST | `/v1/servers/:id/heartbeat` | bearer | telemetry relayed by the Mac app |
| POST | `/v1/servers/:id/enrollment` | bearer | mints a one-time code |
| POST | `/v1/enrollment/consume` | public | redeemed by the agent |
| GET/POST | `/v1/servers/:serverId/projects` | bearer | |
| PUT/DELETE | `/v1/projects/:id` | bearer | |
| GET | `/v1/activity` | bearer | cursor-paginated |
| WS | `/v1/events` | bearer | rooms per server |
| GET | `/healthz`, `/readyz` | public | liveness / readiness |

Authentication is **deny-by-default**: `JwtAuthGuard` is registered as a global
`APP_GUARD`, and public routes opt out with `@Public()`. A new controller is
protected before anyone remembers to protect it.

Access tokens are HS256, 15 minutes. Refresh tokens are opaque 256-bit strings
stored only as SHA-256, 30 days, rotated on every use, with reuse detection that
revokes the whole token family.

---

## Verification status

Be precise about this: the environment this was authored in had **no npm
registry access**, so nothing requiring `node_modules` could be run.

### Verified — actually executed

- **517 tests pass** across 79 suites (`npm test`, Node's built-in runner via
  `tsx`) — with `node_modules` **absent entirely**, which is the property the
  logic split exists to buy. Covers: JWT signing and verification (56 cases —
  `alg: none`,
  algorithm substitution, tampered header and payload, non-canonical base64url,
  clock skew both directions, over-long lifetimes, claim type confusion), the
  health rollup (50 cases including threshold boundaries, precedence ordering,
  NaN/Infinity/out-of-range inputs and copy invariants), enrollment (38 cases
  including expiry, double-consume, timing-safe comparison and the concurrent
  race), metadata redaction (71 cases), error mapping, cursor pagination and
  tamper rejection, refresh rotation and reuse detection, password policy and
  the anti-enumeration invariant, config validation, and server/project/user
  input validation.
- **`npm run typecheck:logic` passes with zero errors** — every `*.logic.ts` and
  `*.test.ts` file under `strict` plus `noUncheckedIndexedAccess` and
  `exactOptionalPropertyTypes`. No `any` anywhere in the pure layer. Run with
  `typescript@6.0.3` and `@types/node@25.6.2`; `@types/node` is the one package
  it needs, since the pure layer uses `node:crypto` and the tests use
  `node:test`.

### Not verified — could not be run here

- **`npm run typecheck` (full project) does not pass** without dependencies. All
  108 errors are `TS2307` (unresolved `@nestjs/*`, `@prisma/*`, `zod`,
  `socket.io`, `argon2`) and their knock-on effects (`TS2339` on
  `PrismaService.<model>` because the generated client is absent, `TS7006`/
  `TS7031` on callback parameters whose types come from it, `TS2882` for
  `reflect-metadata`). Run it again after `npm install && npx prisma generate`;
  any error that is *not* in those categories is a real one.
- **The application has never been started.** `nest build`, `nest start`,
  `prisma generate` and `prisma migrate` were all unrunnable.
- **No endpoint has been exercised.** There are no integration or e2e tests.
- **`prisma/migrations/00000000000000_init/migration.sql` is hand-written** to
  match the schema, and has never been applied to a database. Verify it before
  trusting it:

  ```bash
  npx prisma migrate diff \
    --from-migrations prisma/migrations \
    --to-schema-datamodel prisma/schema.prisma \
    --shadow-database-url "$SHADOW_DATABASE_URL" \
    --exit-code
  ```

  A zero exit code means schema and migration agree. If they differ, trust the
  schema and regenerate the migration.
- **The NestJS 12 / Prisma 7 API usages are written from
  `docs/reference/backend-stack.md`, not from a successful compile.** The most
  likely places for a surprise are `StandardSchemaValidationPipe`'s
  `@Body({ schema })` option, the `$extends` append-only guard in
  `PrismaService`, and `prisma/config`'s `defineConfig` signature.
- **Argon2id parameters are stated but unbenchmarked.** 64 MiB / t=3 / p=4 is
  the OWASP recommendation; measure it on the target hardware and raise the cost
  until a hash takes roughly 100 ms.

### Deviations from `docs/reference/backend-stack.md`

1. **`typescript` is pinned to `6.0.3`, not `7.0.2`.** §4.4 of the doc flags
   that TS 7 does not address decorator behaviour and advises verifying
   `experimentalDecorators` + `emitDecoratorMetadata` before committing, keeping
   6.0.3 as the fallback. That verification was impossible here, and 6.0.3 is
   the compiler the logic typecheck actually ran on — so the honest pin is the
   one that was tested. Revisit once TS 7 can be exercised against NestJS.
2. **`@nestjs/jwt` is not a dependency.** Token signing and verification are
   implemented directly in `src/auth/token.logic.ts` over `node:crypto`. The
   reason is testability of the failure modes: rejecting `alg: none`, rejecting
   an algorithm the service did not configure, comparing signatures in constant
   time, and enforcing a maximum token lifetime are all *omissions* in the
   typical integration, and they are only verifiable here because the code is
   ours. 56 tests cover it.
3. **`@nestjs/config` is not used.** §4.2 notes its 12.x Standard Schema
   migration, which would work — but the rules that matter ("these two secrets
   must differ", "at least 32 bytes", "this still looks like the placeholder")
   are decisions rather than shape checks. They live in
   `src/config/env.logic.ts`, tested, and adding `ConfigModule` on top would put
   the same rules in two places. `dotenv` is still a dependency because
   `prisma.config.ts` needs it (§2.4).
4. **`ioredis` is pinned to `5.11.1`**, as §1.3 advises over the newer 6.0.0. It
   is declared for the planned multi-instance event fan-out; the current
   single-instance gateway does not use it yet.

### Known gaps, deliberately left

- No rate limiting on `/v1/auth/login` or `/v1/enrollment/consume`. Both need it
  before this is public.
- The event stream is single-instance. Multiple replicas need a Redis adapter
  for socket.io — which is what `REDIS_URL` is reserved for.
- `ApiKey` is modelled and migrated but has no service or routes yet.
- No OpenAPI document. `@nestjs/swagger` is not wired up.

---

## Testing

```bash
npm test                   # 517 tests; runs with node_modules absent
npm run typecheck:logic    # needs @types/node only
```

`scripts/test.sh` finds every `src/**/*.test.ts` and runs it through `tsx` into
Node's built-in test runner. It resolves `tsx` from `node_modules` first and
falls back to a global install, so it works in a checkout that has never had
`npm install` run.

New rules live in the logic layer with tests; the Nest layer stays thin enough
that there is little left in it to get wrong.
