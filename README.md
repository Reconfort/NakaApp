# ServerOS

A premium native macOS control centre for Linux infrastructure — connect a server
once, then manage its health, containers, services, databases, users, files and
logs without opening a terminal.

```
macOS app  ──SSH (direct-tcpip port forward)──▶  127.0.0.1:8723 on the server  ──▶  agent
     │
     └──HTTPS──▶ control plane (identity, registry, audit)
```

The desktop app talks to each server's agent **directly**, through a port
forwarded over the SSH connection it already holds. The control plane owns
identity and metadata and is deliberately *not* in the path of every operation.

---

## Repository layout

```
NakaApp/
├── macos/                     Native macOS app (Swift / SwiftUI)
│   ├── ServerOS.xcodeproj     ← open this
│   ├── ServerOS/
│   │   ├── App/               entry point, navigation, session state, palette
│   │   ├── Core/DesignSystem/ colours, type, spacing, components, states
│   │   ├── Features/          one folder per screen
│   │   ├── Kit/               domain, networking, SSH, security, demo data
│   │   └── Resources/         Info.plist, entitlements
│   ├── ServerOSTests/         XCTest suites + captured API fixtures
│   └── fixtures/              real agent responses, used by the tests
├── agent/                     Linux agent (Rust, Cargo workspace)
│   └── crates/{json,crypto,http,linux,fsops,systemd,docker,pg,agent}
├── control-plane/             Backend (NestJS + Prisma + PostgreSQL + Redis)
├── docs/                      architecture, security, platform references
└── scripts/                   project generation and off-Mac verification
```

---

## Build and run

### 1. The macOS app

```bash
open macos/ServerOS.xcodeproj
```

Then **⌘R**. On first open Xcode resolves three Swift packages
(`swift-nio`, `swift-nio-ssh`, `swift-crypto`) — that needs a network connection
and takes a minute.

From the command line:

```bash
xcodebuild -project macos/ServerOS.xcodeproj -scheme ServerOS \
           -configuration Debug -destination 'platform=macOS' build
```

Or double-click **`build.command`** in Finder. It builds, runs the test suite if
the build succeeds, then stays open; creating a `.build-request` file next to it
starts another build, so iterating needs no further action. It writes
`build-errors.txt` (just the diagnostics), `build-status.txt` (one
machine-readable line), `build.log` and `test.log`.

**Requirements:** macOS 14.0+ to run, Xcode 16+ to build (the project uses
`objectVersion = 77` folder-synchronized groups). Language mode is Swift 5.

Regenerate the project file after adding a *folder* (individual files are picked
up automatically):

```bash
python3 scripts/generate-xcodeproj.py
```

### 2. Demo mode — no server needed

Launch the app and choose **Explore with Demo Data** on the empty state, or
Settings → Servers → Demo mode. Three servers appear, all prefixed `Demo `, with
metrics that move, containers you can start and stop, logs, users, services and
PostgreSQL inventory.

Demo data is confined to `macos/ServerOS/Kit/Demo/DemoData.swift`, every demo
server carries `isDemo = true`, and the UI labels them. **Real-server mode never
falls back to demo data** — an unreachable server shows an error, not fiction.

### 3. The Linux agent

```bash
cd agent
cargo build --release          # target/release/serveros-agent
cargo test --workspace         # 1,081 tests
```

Run it locally:

```bash
sudo ./target/release/serveros-agent enroll   # prints the enrollment bundle once
sudo ./target/release/serveros-agent serve
./target/release/serveros-agent status        # over the local Unix socket
```

Config lives at `/etc/serveros/agent.json`; the shared secret is a separate
`/etc/serveros/agent.key`, mode 0600. The agent binds **loopback only** by
default and refuses to start on a routable address unless
`allow_public_bind` is explicitly set.

### 4. The control plane

```bash
cd control-plane
cp .env.example .env            # then fill in the secrets it names
docker compose up -d            # PostgreSQL 16 + Redis 7
npm install
npx prisma generate
npx prisma migrate deploy
npm run start:dev               # http://localhost:3000
npm test                        # 517 logic tests (no dependencies needed)
```

Required environment variables are documented in `.env.example`; at minimum
`DATABASE_URL`, `REDIS_URL`, `JWT_SECRET` and `REFRESH_SECRET` (the last two
must differ and be at least 32 bytes).

### 5. Connect a real server

In the app: **Add Server** (⌘N), then host, SSH port, username, and either a
password or an existing Ed25519/ECDSA key. Leave *"Let ServerOS create its own
key"* checked — it installs a dedicated key in `authorized_keys` that you can
revoke independently, so no password is stored.

The flow then tests the connection, shows the host key fingerprint for you to
confirm, installs the agent, enrols it, and verifies `/v1/health`.

**The server needs no internet access.** ServerOS carries the Linux agent inside
the app and pushes it down the SSH connection it already holds, in base64 chunks,
verifying the SHA-256 of what landed before the installer runs. Nothing is
downloaded on the server's side. `install-agent.sh --base-url` still exists for
organisations mirroring the agent themselves.

**Supported:** Ubuntu 22.04+, Debian 12+, on **x86-64**. Root or passwordless
`sudo` is required for the install.

arm64 servers are supported by the agent but no arm64 build is bundled yet, so
adding one fails with a message saying exactly that. To add it: on any arm64
Linux machine run `cd agent && cargo build --release`, copy the result to
`macos/ServerOS/Kit/SSH/Resources/serveros-agent-linux-aarch64`, and rebuild.

---

## Verification

`./scripts/check-all.sh` runs everything that does not need a Mac:

| Check | What it proves |
|---|---|
| `cargo test --workspace` | 1,081 agent tests, incl. live Docker, live PostgreSQL, live D-Bus |
| `control-plane` logic tests | 517 tests over auth, health, redaction, pagination, enrolment |
| `scripts/check-swift.py` | no duplicate declarations, balanced delimiters, all 20 screen contracts satisfied |
| `scripts/check-members.py` | every design-system and model member reference resolves |
| `scripts/check-wire-contract.py` | every field the agent emits is decoded by a Swift model |
| `scripts/check-safety.py` | no secret reaches a log; demo data cannot reach real mode |
| `scripts/mvp-workflow.py` | the whole MVP path against a **live agent** — 32 checks |

`mvp-workflow.py` is the one to run when you want to know whether the product
works. It mints the same short-lived HMAC tokens the macOS app mints and walks
the path a user walks — health, auth (a forged token and a replayed token are
both refused), system, metrics sampled twice and confirmed to move, processes,
users, a container through inspect → restart → logs → stop, images, volumes,
networks, file browse and two refusals, PostgreSQL, and the audit trail. Point
it at any running agent:

```bash
python3 scripts/mvp-workflow.py --url http://127.0.0.1:8723 \
                                --key /etc/serveros/agent.key
```

The Swift checks exist because the app cannot be compiled on a Linux CI box; they
catch the drift a compiler would, not the types it would. They are a
supplement to `xcodebuild`, never a substitute — see
`docs/BUILD-VERIFICATION.md` for exactly what has and has not been run.

---

## Security posture

* **Credentials live in the macOS Keychain**, per server, and never reach
  SwiftData, `UserDefaults`, a log, or the control plane. `Server` has no
  credential column by design.
* **The agent has no `/execute` endpoint.** Every capability is a named route
  with its own scope and its own audit record.
* **Request tokens are short-lived and single-use**: the shared secret never
  crosses the wire after enrolment, tokens expire in ≤5 minutes, and a replayed
  `jti` is refused.
* **The agent listens on loopback only.** Reachability comes from the SSH
  channel the app already holds — no exposed port, no TLS certificate to expire.
* **Secrets are masked before they are shown or logged** — container
  environment variables, PostgreSQL query text, new-user passwords.
* **The app is sandboxed** with the minimum entitlements: outgoing network,
  user-selected files, and its own Keychain group.

---

## Licence

Copyright © 2026 Orion Systems & Design.
