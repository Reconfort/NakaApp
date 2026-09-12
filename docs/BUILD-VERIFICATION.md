# Build verification — what has actually been run

The project rule is that nothing is called complete until it builds. This file
is the honest ledger: what has been executed, on what, with what result, and —
more importantly — what has **not**.

Last updated: 12 September 2026.

**The macOS app builds and its tests pass.** `** BUILD SUCCEEDED **`, then
`** TEST SUCCEEDED **` — 193 tests, 0 failures, 10 skipped. Built on macOS with
Xcode, arm64, Debug. `ServerOS.app` is produced at
`.derived/Build/Products/Debug/ServerOS.app`.

The ten skips are all `KeychainTests`, and they skip themselves rather than
falsely passing: `build.command` passes `CODE_SIGNING_ALLOWED=NO` so it works on
a machine with no signing identity, and an unsigned test host gets
`errSecMissingEntitlement` (-34018) from the Keychain. Open the project in
Xcode, pick a team under Signing & Capabilities, and ⌘U runs them for real.

---

## Verified by execution

| What | Where | Result |
|---|---|---|
| **`xcodebuild build`** | **macOS, Xcode, arm64** | **BUILD SUCCEEDED** |
| **`xcodebuild test`** | **macOS, Xcode, arm64** | **193 tests, 0 failures, 10 skipped** |
| `cargo test --workspace` (Rust agent) | Linux x86-64, real kernel | **1,081 passed, 0 failed** |
| — against a live Docker daemon | Docker 29.4.3, API 1.43 | list / inspect / restart / stop / logs / images / volumes / networks |
| — against a live PostgreSQL | PostgreSQL 16.13 | SCRAM-SHA-256, MD5 and trust auth all exercised |
| — against a live D-Bus | systemd unavailable in this container; D-Bus client covered by its own suite | service routes report `services: false` rather than pretending |
| Control-plane logic tests | Node | **517 passed, 0 failed** |
| Agent release build | `cargo build --release` | binary produced, enrolled, served 59 routes |
| **Full MVP workflow** (`scripts/mvp-workflow.py`) | live agent over HTTP | **32 passed, 0 failed** |
| `scripts/check-swift.py` | static | no duplicate declarations, balanced delimiters, all 20 screen contracts present |
| `scripts/check-members.py` | static | every design-system and model member reference resolves (62 files, 20 types) |
| `scripts/check-wire-contract.py` | static | every field the agent emits is named by a Swift model |
| `scripts/check-safety.py` | static, 202 files | no secret in any log call; no `print`/`dump` in the app at all; demo data unreachable from the real path; no credential on a SwiftData model |
| `scripts/embed-install-script.py --check` | static | embedded installer byte-identical to `install-agent.sh` |
| `scripts/build-macos.sh` | stubbed `xcodebuild` | success path, failure path, test phase and rebuild trigger all exercised |

The MVP workflow is the one that matters most. It mints the same short-lived
HMAC tokens the macOS app mints and walks the exact path a user walks:
health → auth (including a forged token and a replayed token, both refused) →
system → metrics sampled twice and confirmed to move → processes → users
(confirming no password hash escapes) → containers list, inspect, env masking,
restart, settle, logs, stop → images, volumes, networks → file browse, read,
and two refusals (`/etc/shadow`, and a traversal to it) → PostgreSQL overview
and databases with query text withheld → the audit trail, confirmed to contain
the restart and no secret material → 404 envelope shape.

Every check in `check-safety.py` was itself tested against deliberately broken
code — a `print` of a credential, a secret passed to `logging::info_with`, an
`api_key` in a NestJS `logger.error`, a `DemoAgentClient` built inside a real
screen, and a `password` field on a SwiftData `@Model`. All five were caught. A
checker that has only ever passed proves nothing about what it would catch.

---

## What the first real compile found

Five defects, none of which the static checks could have caught, and one that
shows exactly where those checks were thin:

1. `NSURLErrorConnectionLost` does not exist — the constant is
   `NSURLErrorNetworkConnectionLost`, already in the same `case` list.
2. `.onHover { withAnimation(…) { isHovered = $0 } }` in three places. `$0`
   binds to the *innermost* closure, which is `withAnimation`'s and takes no
   arguments. Named the parameter.
3. `private struct ChipFlowLayout: Layout` resolved to the design system's own
   `Layout` enum rather than `SwiftUI.Layout`. Qualified both it and
   `LayoutSubviews`.
4. `deinit` cancelling three `Task` properties on a `@MainActor` class —
   `deinit` is not actor-isolated. Marked them `nonisolated(unsafe)`, which is
   sound here: `Task.cancel()` is callable from any thread and nothing else
   holds a reference by then.
5. `query_start` and `state_change` declared `String?` while the agent sends
   epoch seconds as a number.

The fifth one is the instructive one. `check-wire-contract.py` proved both
fields were *named* by a Swift model and passed — it had no opinion about
types. Five of the six rows in the fixture were null, so even the fixture did
not give it away until the suite ran. `scripts/check-wire-types.py` now closes
that gap: it matches each fixture to the model whose `CodingKeys` cover it and
compares every row's JSON value type against the declared Swift type. It found
`state_change` too, which the test run had not yet reached.

## Still unverified

* **Demo mode as an interactive experience** — the app launches, but nobody has
  clicked through restarting a container and watching it settle.
* **The Mac ↔ agent path against a real Linux server.** The agent side of that
  path is covered by `mvp-workflow.py` (32 checks, live agent); what is untested
  is the SSH port-forward and enrolment from the app itself.
* **`KeychainTests` under real signing** — see the note above.

`build.command` builds, runs the tests, then waits; while it waits, creating a
`.build-request` file next to it starts another build, so a compile-and-fix loop
needs no further action. It writes:

```
build-errors.txt   just the diagnostics — read this first
build-status.txt   one line, machine-readable
build.log          full xcodebuild output
test.log           full test output
```

---

## Dependency posture, and why the Rust agent has none

The instruction is to prefer mature, proven libraries over reinventing
infrastructure, and not to invent constraints such as "no external crates".

Where that instruction has teeth, it is followed: the macOS app takes
`swift-nio`, `swift-nio-ssh` and `swift-crypto` as package dependencies rather
than hand-rolling an SSH transport or a cipher — exactly the code that should
never be written from scratch.

The Rust agent is the exception, and not by preference. `crates.io` is
unreachable from both build environments available here (verified: connection
refused from the cloud container and from the local VM; `index.crates.io`
answers 403 through the proxy). Adding dependencies now would make the agent
impossible to build or test in either place — trading 1,081 executed tests for
a tree that cannot compile until it reaches a machine with open network access.

So the agent stays dependency-free **for now**, and this is recorded as a
decision to revisit rather than a rule. On any machine with normal network
access, the crates worth adopting first are `serde`/`serde_json` (replacing
`crates/json`), `hyper` or `axum` (replacing `crates/http`), `zbus` (replacing
the hand-written D-Bus client in `crates/systemd`), and `tokio-postgres`
(replacing the wire protocol in `crates/pg`). Each is a self-contained swap
behind an existing module boundary; none of them changes the agent's API.
