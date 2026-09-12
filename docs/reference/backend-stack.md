# Backend Stack Reference — ServerOS Control Plane

Verified September 12, 2026. Versions resolved from upstream git tags
(`git ls-remote --tags`) and official documentation. npm registry was unavailable,
so these are the latest **stable release tags**, which for all these projects
correspond to the published `latest` dist-tag.

---

## 1. Current versions (September 2026)

### 1.1 Recommended `package.json` for ServerOS

```jsonc
{
  "type": "module",
  "engines": { "node": ">=24.0.0" },
  "dependencies": {
    "@nestjs/common":           "^12.0.1",
    "@nestjs/core":             "^12.0.1",
    "@nestjs/platform-express": "^12.0.1",
    "@nestjs/websockets":       "^12.0.1",
    "@nestjs/platform-socket.io":"^12.0.1",
    "@nestjs/jwt":              "^12.0.1",
    "@nestjs/config":           "^12.0.0",
    "@prisma/client":           "^7.10.0",
    "@prisma/adapter-pg":       "^7.10.0",
    "argon2":                   "^0.45.1",
    "ioredis":                  "^5.11.1",
    "reflect-metadata":         "^0.2.2",
    "rxjs":                     "^7.8.1",
    "zod":                      "^4.6.2"
  },
  "devDependencies": {
    "prisma":                   "^7.10.0",
    "typescript":               "^7.0.2"
  }
}
```

### 1.2 Version table

| Package | Latest stable | Notes |
|---|---|---|
| `@nestjs/core` | **12.0.1** | NestJS 12 is out. ESM-first. |
| `@nestjs/common` | **12.0.1** | Same monorepo version. |
| `@nestjs/platform-express` | **12.0.1** | Express **5** since Nest 11. |
| `@nestjs/websockets` | **12.0.1** | Pair with `@nestjs/platform-socket.io`. |
| `@nestjs/jwt` | **12.0.1** | Realigned to framework major. |
| `@nestjs/config` | **12.0.0** | **Jumped 4.x → 12.x.** See §4. |
| `@nestjs/swagger` | **12.0.1** | |
| `prisma` / `@prisma/client` | **7.10.0** | v8 is Early Access only. See §2.1. |
| `typescript` | **7.0.2** | Native Go compiler. 6.0.3 is the JS-based line. |
| Node.js | **24.x "Krypton" (Active LTS)** | 26.x is Current; becomes Active LTS 2026‑10‑28. Latest 26.8.2. |
| `ioredis` | **6.0.0** | 5.11.1 is the last 5.x. See §1.3. |
| `zod` | **4.6.2** | v4 API. |
| `argon2` | **0.45.1** | Recommended over bcrypt. |
| `bcrypt` | **6.0.0** | Alternative. |

Sources:
- https://github.com/nestjs/nest/releases
- https://github.com/prisma/prisma/releases
- https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/
- https://nodejs.org/en/about/previous-releases
- https://github.com/nodejs/Release/blob/main/README.md

### 1.3 Version choices worth pinning deliberately

**Node: use 24.x (Active LTS), not 26.x.** Node 24 "Krypton" entered Active LTS 2025‑10‑28 and moves to Maintenance 2026‑10‑20. Node 26 is still *Current* until 2026‑10‑28. NestJS 12 requires **v20.19+ or v22.12+ to run**, but the **Nest CLI requires v22.22.3+, v24.15+, or v26+**. The NestJS docs recommend "the latest active LTS" because it satisfies both. Node 21.x is explicitly unsupported.

**TypeScript: 7.0.2 works, but read §5 before adopting.** TypeScript 7.0 (released 2026‑07‑08) is the native Go port — 8–12x faster builds. It changes compiler *defaults* aggressively. `typescript@6.0.3` remains supported and is the conservative choice for a first build-out; `@typescript/typescript6` allows side-by-side operation.

**ioredis: 5.11.1 unless you have verified 6.0.0.** ioredis 6.0.0 is a new major released recently; for a control plane that only needs pub/sub fan-out and a token cache, the 5.x line is lower-risk.

**argon2 over bcrypt.** `argon2@0.45.1` wraps Argon2id, which is the current OWASP recommendation for password hashing. bcrypt caps input at 72 bytes and has no memory-hardness. Use `argon2.hash(password)` / `argon2.verify(hash, password)`; defaults are already sensible (Argon2id, 64 MiB, t=3, p=4).

---

## 2. Prisma

### 2.1 Which major to use

**Use Prisma ORM 7 (7.10.0).** Prisma ORM 8 is in **Early Access** (announced May 2026) and is not GA. Prisma 8 introduces `prisma-next`, a `prisma/contract.prisma` authoring model, TypeScript schemas, a SQL query builder and an extensions system — a substantial departure. Prisma states v7 "will continue receiving long-term support" and that both can run in parallel.

**Trap:** `prisma.io/docs` now serves **Prisma 8 Early Access** content at the unversioned URLs. Prisma 7 documentation lives under `https://www.prisma.io/docs/orm/v7/...`. If you follow the default docs you will write `contract.prisma` / `prisma-next` code against a package you are not installing.

- v7 docs root: https://www.prisma.io/docs/orm/v7/
- v8 roadmap: https://www.prisma.io/blog/prisma-next-roadmap
- v7 release post: https://www.prisma.io/blog/announcing-prisma-orm-7-0-0

### 2.2 Is `prisma generate` still needed?

**Yes.** It is still required, and v7 made it stricter: the generator `output` path is now mandatory, so there is no implicit `node_modules/.prisma/client` target to fall back on.

Run it after:
- changing your Prisma schema
- updating generator configuration
- enabling features that affect the client API
- pulling schema changes from another branch or teammate

Prisma: it "makes sense to run `prisma generate` in `postinstall` or before your production build."

```jsonc
"scripts": {
  "postinstall": "prisma generate",
  "build": "prisma generate && nest build"
}
```

Doc: https://www.prisma.io/docs/orm/v7/prisma-client/setup-and-configuration/generating-prisma-client

### 2.3 Minimal `schema.prisma` header — verbatim

```prisma
generator client {
  provider = "prisma-client"
  output   = "../src/generated/prisma"
}

datasource db {
  provider = "postgresql"
}

model Server {
  id        String   @id @default(uuid())
  name      String
  hostname  String
  createdAt DateTime @default(now())
}
```

Three things changed from 2024-era Prisma:

1. **`provider = "prisma-client"`, not `"prisma-client-js"`.** The `prisma-client-js` provider is deprecated in v7.
2. **`output` is required.** There is no default location any more.
3. **`url` has moved out of `datasource`.** `url`, `directUrl` and `shadowDatabaseUrl` are deprecated in the datasource block; connection configuration lives in `prisma.config.ts`.

Full generator options (only `output` is required; the rest have defaults or are inferred from your environment and `tsconfig.json`):

```prisma
generator client {
  provider               = "prisma-client"
  output                 = "../src/generated/prisma"
  engineType             = "client"      // default
  runtime                = "nodejs"      // default
  moduleFormat           = "esm"         // inferred
  generatedFileExtension = "ts"          // default
  importFileExtension    = "ts"          // inferred
}
```

Doc: https://www.prisma.io/docs/orm/v7/prisma-schema/overview/generators

### 2.4 `prisma.config.ts` — required in v7

Create at the project root:

```ts
import "dotenv/config";
import { defineConfig, env } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  migrations: {
    path: "prisma/migrations",
    seed: "tsx prisma/seed.ts",
  },
  datasource: {
    url: env("DATABASE_URL"),
  },
});
```

**`import "dotenv/config"` is not optional.** Prisma v7 **no longer auto-loads `.env`**. Without it, `env("DATABASE_URL")` resolves to undefined and every CLI command fails with an unhelpful connection error.

Doc: https://www.prisma.io/docs/orm/v7/reference/prisma-config-reference

### 2.5 Driver adapter — now mandatory

v7 removed the Rust query engine. **Every database connection requires an explicit driver adapter passed to the `PrismaClient` constructor.**

```ts
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client.js";

const adapter = new PrismaPg({ connectionString: process.env.DATABASE_URL });
export const prisma = new PrismaClient({ adapter });
```

Omitting it throws: `Using engine type "client" requires either "adapter" or "accelerateUrl" to be provided to PrismaClient constructor.`

Note the import path: `./generated/prisma/client` — pointing at your `output` directory, **not** `@prisma/client`.

As a NestJS provider:

```ts
import { Injectable, OnModuleInit, OnModuleDestroy } from "@nestjs/common";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "../generated/prisma/client.js";

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  constructor() {
    super({ adapter: new PrismaPg({ connectionString: process.env.DATABASE_URL! }) });
  }
  async onModuleInit()   { await this.$connect(); }
  async onModuleDestroy() { await this.$disconnect(); }
}
```

Doc: https://www.prisma.io/docs/guides/upgrade-prisma-orm/v7

---

## 3. NestJS conventions

### 3.1 `main.ts` — still `NestFactory.create(AppModule)`

Yes, unchanged in shape. What changed is ESM:

```ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(process.env.PORT ?? 3000);
}
await bootstrap();
```

Three ESM-era differences from 2024 code:
- **`.js` extension on relative imports** (`./app.module.js`), even though the source is `.ts`.
- **Top-level `await bootstrap()`** rather than a bare `bootstrap();` call.
- `__dirname` / `__filename` are gone — use `import.meta.dirname`.

Doc: https://docs.nestjs.com/first-steps

### 3.2 Validation — two supported paths

**A. `ValidationPipe` + class-validator** (still fully supported; correct if your DTOs are classes):

```ts
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
}));
```

Requires `class-validator` and `class-transformer`.

**B. `StandardSchemaValidationPipe` + zod** (new in Nest 12; recommended for ServerOS since you already want zod):

```ts
app.useGlobalPipes(new StandardSchemaValidationPipe({ transform: true }));
```

Then attach schemas directly on route parameter decorators:

```ts
@Post()
create(@Body({ schema: createServerSchema }) body: CreateServerDto) {
  return this.servers.create(body);
}
```

`@Body()`, `@Query()` and `@Param()` all accept a `schema` option, compatible with any Standard Schema implementation — zod, Valibot, ArkType.

NestJS's own guidance: "Use this approach when your schemas already live outside of class-based DTOs. If your project relies on `class-validator` decorators, `ValidationPipe` remains the right choice."

**Recommendation for ServerOS:** use B. One schema definition serves runtime validation, static types (`z.infer`), and can be shared with the Swift client's contract generation. Do not mix both globally.

Doc: https://docs.nestjs.com/techniques/validation

### 3.3 WebSocket gateway API

Unchanged decorator API; install `@nestjs/websockets` and `@nestjs/platform-socket.io`.

```ts
import {
  WebSocketGateway, WebSocketServer, SubscribeMessage,
  MessageBody, ConnectedSocket,
  OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect,
} from '@nestjs/websockets';
import { Server, Socket } from 'socket.io';

@WebSocketGateway({ namespace: '/metrics', cors: { origin: false } })
export class MetricsGateway
  implements OnGatewayInit, OnGatewayConnection, OnGatewayDisconnect
{
  @WebSocketServer() server!: Server;

  afterInit(server: Server) { /* ... */ }
  handleConnection(client: Socket)  { /* authenticate here */ }
  handleDisconnect(client: Socket)  { /* ... */ }

  @SubscribeMessage('subscribe:server')
  onSubscribe(
    @MessageBody() serverId: string,
    @ConnectedSocket() client: Socket,
  ) {
    client.join(`server:${serverId}`);
    return { event: 'subscribed', data: serverId };
  }
}
```

| Symbol | Role |
|---|---|
| `@WebSocketGateway(port?, options?)` | Class decorator. Options include `namespace`, `cors`, `transports`. |
| `@WebSocketServer()` | Property decorator; injects the native server/namespace. |
| `@SubscribeMessage('event')` | Method decorator; subscribes to a named event. |
| `@MessageBody(key?)` | Extracts the payload (optionally one property). |
| `@ConnectedSocket()` | Injects the platform socket. |
| `@Ack()` | Injects the acknowledgment callback. |
| `OnGatewayInit` | Requires `afterInit(server)`. |
| `OnGatewayConnection` | Requires `handleConnection(client)`. |
| `OnGatewayDisconnect` | Requires `handleDisconnect(client)`. |

Handlers may return a value, a `Promise`, or an `Observable` (for multiple emissions — a natural fit for a metrics stream).

**New in v12:** request-scoped gateways, giving per-connection state via DI with the `REQUEST` token.

Doc: https://docs.nestjs.com/websockets/gateways

---

## 4. Breaking changes that bite 2024-era code

### 4.1 NestJS 11 (from 10)

- **Express 5 is the default** in `@nestjs/platform-express`. Path matching changed: **wildcards must be named.** `@Get('*')` is now `@Get('*splat')`; `@Get('files/*')` → `@Get('files/*splat')`. Unnamed `*` throws at startup. This is the most common upgrade break.
- **Termination lifecycle hook order reversed** — `OnModuleDestroy`, `OnApplicationShutdown` now run in the opposite order from Nest 10.
- **`CacheModule` uses cache-manager v6 / Keyv.** Old store adapters do not work.
- **`ConfigService#get` resolution order changed**, plus a new `skipProcessEnv` option.

Source: https://trilon.io/blog/announcing-nestjs-11-whats-new

### 4.2 NestJS 12 (from 11)

- **Core packages are now ESM-only.** CommonJS apps still work via Node's `require(esm)`, but relative imports need `.js` extensions and `__dirname`/`__filename` must become `import.meta.dirname`. Custom build tooling and test runners need review.
- **Node 21.x support dropped.** Requires v20.19+ / v22.12+ to run; CLI requires v22.22.3+ / v24.15+ / v26+.
- **Lifecycle hooks now execute by component hierarchy level**, which can reorder `onModuleInit` / `onApplicationBootstrap` across dependent providers.
- **`@nestjs/config` moved to Standard Schema.** `validationSchema` accepts any Standard Schema. Joi works only at **v18+**, and Joi-specific settings must move under `validationOptions.libraryOptions`.
- **`@nestjs/config` version jumped 4.x → 12.x.** `"@nestjs/config": "^4.0.0"` in a package.json silently pins you to the pre-Standard-Schema release.
- **NATS:** `nats` package replaced by `@nats-io/transport-node`; payloads serialize as JSON strings and custom deserializers receive the full NATS message.
- **GraphQL:** `subscriptions-transport-ws` removed — use `graphql-ws` (a wire-level change, clients must update). GraphiQL replaces the playground as default.
- **Tooling:** Webpack deprecated in favour of **Rspack**; new ESM starters use **Vitest** and **oxlint** instead of Jest and ESLint. CommonJS projects keep Jest.
- New: `nest upgrade` and `nest deploy` CLI commands; `@nestjs/observe` observability SDK.

Sources:
- https://docs.nestjs.com/migration-guide
- https://github.com/nestjs/nest/releases/tag/v12.0.0
- https://trilon.io/blog/nestjs-12-is-coming

### 4.3 Prisma 7 (from 6 / 5)

- **`prisma-client-js` provider deprecated** → use `prisma-client`.
- **`output` is now required** in the generator block.
- **Driver adapters are mandatory** — `new PrismaClient({ adapter })`. The Rust query engine is gone.
- **`url` / `directUrl` / `shadowDatabaseUrl` deprecated in `datasource`** → moved to `prisma.config.ts`.
- **`.env` is no longer auto-loaded** — `import "dotenv/config"` explicitly.
- **Seeding no longer runs automatically**; invoke `prisma db seed`.
- **Client middleware (`$use`) removed** → use Client Extensions (`$extends`). Any 2024-era `prisma.$use(async (params, next) => ...)` audit-logging or soft-delete middleware must be rewritten.
- **Metrics preview feature removed.**
- Import path changes from `@prisma/client` to your generated `output` directory.

Source: https://www.prisma.io/docs/guides/upgrade-prisma-orm/v7

### 4.4 TypeScript 7 (from 5.x)

`tsc` is now a native Go binary (8–12x faster). Compiler **defaults changed**, which silently alters behaviour of an inherited `tsconfig.json`:

- **`strict` is now on by default.**
- **`target` defaults to the current stable ECMAScript**, not ES5.
- **`types` defaults to `[]`** instead of auto-including every `@types` package in `node_modules`. Ambient globals you relied on (e.g. `node`, `jest`) must be listed explicitly. This is the most likely first breakage in a NestJS project.
- **`rootDir` defaults to `./`** — a `src/` layout needs it set explicitly.
- **Removed:** ES5 targeting, `downlevelIteration`, AMD/UMD/SystemJS modules, and **`baseUrl`**. Path aliases must use `paths` without `baseUrl`.

Decorator behaviour is not addressed in the 7.0 announcement. NestJS depends on `experimentalDecorators` + `emitDecoratorMetadata`; **verify these still function on TS 7 before committing**, and keep `typescript@6.0.3` as the fallback (`@typescript/typescript6` supports side-by-side installs).

Minimum `tsconfig.json` for NestJS on TS 7:

```jsonc
{
  "compilerOptions": {
    "module": "nodenext",
    "moduleResolution": "nodenext",
    "rootDir": "./src",
    "outDir": "./dist",
    "types": ["node"],
    "experimentalDecorators": true,
    "emitDecoratorMetadata": true,
    "strict": true,
    "strictPropertyInitialization": false
  }
}
```

(`strictPropertyInitialization: false` is conventional for NestJS DTOs and injected properties.)

Source: https://devblogs.microsoft.com/typescript/announcing-typescript-7-0/

### 4.5 zod 4

`zod@4.6.2`. The v3 → v4 migration changed error customization (`message` → `error`), `z.string().email()` moved to top-level `z.email()`, and `.default()` semantics changed. Write new schemas against the v4 API rather than adapting v3 snippets.
