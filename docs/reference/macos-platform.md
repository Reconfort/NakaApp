# macOS Platform Reference — ServerOS

Verified September 12, 2026 against official Apple documentation.
Deployment target assumption throughout: **macOS 14.0**.

---

## 1. Current releases, Xcode, and the `.xcodeproj` format

### 1.1 Shipping versions (Sept 2026)

| Item | Current shipping | In RC (released 2026-09-09) |
|---|---|---|
| macOS | **macOS Tahoe 26.6** | macOS 27 "Golden Gate" RC (build 26A428) |
| Xcode | **Xcode 26.6** | Xcode 27 RC (build 27A266a) |
| Swift | 6.3 (6.3.3 latest patch) | Swift 6.4 (ships in Xcode 27) |

- Xcode 26 shipped with **Swift 6.2** and SDKs for macOS Tahoe 26. It **requires a Mac running macOS Sequoia 15.6 or later**.
- Xcode 27 RC includes **Swift 6.4** and SDKs for macOS 27. It **requires a Mac running macOS Tahoe 26.6 or later**.

Docs:
- https://developer.apple.com/documentation/xcode-release-notes
- https://developer.apple.com/documentation/xcode-release-notes/xcode-26-release-notes
- https://developer.apple.com/documentation/xcode-release-notes/xcode-27-release-notes
- https://developer.apple.com/documentation/macos-release-notes
- https://developer.apple.com/news/releases/
- https://www.swift.org/blog/swift-6.3-released/

### 1.2 `objectVersion` — what current Xcode writes and reads

Apple does **not** document `objectVersion` publicly. The authoritative community mapping is `CocoaPods/Xcodeproj` `lib/xcodeproj/constants.rb`, `COMPATIBILITY_VERSION_BY_OBJECT_VERSION` (verified at commit `f427b24`, v1.28.1, 2026-07-06):

```ruby
COMPATIBILITY_VERSION_BY_OBJECT_VERSION = {
  100 => 'Xcode 26.3',
  77  => 'Xcode 16.0', # with project compatibility set to Xcode 16.0
  71  => 'Xcode 16.2',
  70  => 'Xcode 16.0',
  63  => 'Xcode 15.3',
  60  => 'Xcode 15.0',
  56  => 'Xcode 14.0',
  55  => 'Xcode 13.0',
  54  => 'Xcode 12.0',
  53  => 'Xcode 11.4',
  52  => 'Xcode 11.0',
  51  => 'Xcode 10.0',
  50  => 'Xcode 9.3',
  48  => 'Xcode 8.0',
  47  => 'Xcode 6.3',
  46  => 'Xcode 3.2',
  45  => 'Xcode 3.1',
}.freeze

LAST_KNOWN_OBJECT_VERSION = 100
```

Source: https://github.com/CocoaPods/Xcodeproj/blob/master/lib/xcodeproj/constants.rb
PR adding 100: https://github.com/CocoaPods/Xcodeproj/pull/1041

**Highest format current Xcode writes:** `objectVersion = 100`, `compatibilityVersion = "Xcode 26.3"`. Xcode 26.3+ upgrades projects to this when you accept its "Update to recommended settings" prompt.

**What current Xcode still opens without complaint:** every value in the table above, down to `46` (Xcode 3.2). Xcode is backward-compatible on read; it does not refuse or warn on an older `objectVersion`. It may *offer* an upgrade via the project-issues warning, but that is dismissible and does not block building. Forward compatibility is the hard direction: an older Xcode cannot open a newer `objectVersion`.

**Recommendation for a hand-generated `project.pbxproj`: use `objectVersion = 77`.**

Rationale: 77 is the first version supporting `PBXFileSystemSynchronizedRootGroup` (Xcode 16's synchronized folder groups). This is the single biggest simplification available for hand-generation — you reference a *folder* instead of enumerating every source file as a `PBXFileReference` + `PBXBuildFile` + `PBXGroup` child. Adding a Swift file to the repo then requires no `.pbxproj` edit at all.

Minimum shape:

```
archiveVersion = 1;
classes = { };
objectVersion = 77;
objects = { ... };
rootObject = <24-hex-uppercase-ID>;
```

and in the `PBXProject`:

```
compatibilityVersion = "Xcode 16.0";
```

Synchronized root group object:

```
XXXXXXXXXXXXXXXXXXXXXXXX /* ServerOS */ = {
    isa = PBXFileSystemSynchronizedRootGroup;
    path = ServerOS;
    sourceTree = "<group>";
};
```

referenced from the target via the `fileSystemSynchronizedGroups` key on `PBXNativeTarget`:

```
fileSystemSynchronizedGroups = (
    XXXXXXXXXXXXXXXXXXXXXXXX /* ServerOS */,
);
```

Optional `exceptions` on the root group take `PBXFileSystemSynchronizedBuildFileExceptionSet` objects (to exclude files, override detected file types, or change target membership). `PBXFileSystemSynchronizedBuildFileExceptionSet` also supports `assetTagsByRelativePath` as of Xcodeproj 1.28.0.

Note: with a synchronized group, the target's `PBXSourcesBuildPhase` has an **empty** `files = ( );` — the folder supplies the sources.

Reference: https://pepicrft.me/blog/how-synchronized-groups-work-at-the-pbxproj-level/

If you need maximum third-party tooling compatibility instead (some CI/codegen tools still choke on `PBXFileSystemSynchronizedRootGroup`), fall back to `objectVersion = 56` / `compatibilityVersion = "Xcode 14.0"` and enumerate files explicitly.

### 1.3 Does Xcode accept an XML-plist `project.pbxproj`?

**Yes.** `project.pbxproj` is a property list; Xcode's parser accepts all plist serializations, including XML (`<?xml version="1.0" ...><!DOCTYPE plist ...>`). Xcode reads an XML-formatted project file and builds from it normally. On the first save, Xcode **rewrites it in the canonical OpenStep/ASCII (NeXTSTEP) format** with its usual `/* comment */` annotations.

Practical consequences:
- Generating XML is legitimate and is much easier to emit correctly (no OpenStep quoting rules to get wrong) — it is a fine strategy for a generator script.
- It will not survive round-tripping: the first Xcode write normalizes it, producing one enormous diff.
- Some third-party tools that regex the file rather than parse it (older fastlane/CocoaPods paths) assume OpenStep and will fail on XML.

Evidence of Xcode accepting XML and rewriting it: https://github.com/CocoaPods/CocoaPods/issues/613 and https://github.com/CocoaPods/CocoaPods/issues/2530 (both are complaints that the file *became* XML and that Xcode kept working, with the objection being diff noise).

If you emit OpenStep directly, the canonical conventions are: 24-character uppercase hex object IDs, two-space indent, `isa` first in each object, and quoting only for strings containing characters outside `[A-Za-z0-9_.\/]`.

---

## 2. API availability at deployment target macOS 14.0

Taken from the `availability` metadata on each symbol's Apple documentation page.

| API | Introduced (macOS) | Introduced (iOS) | OK at macOS 14.0? |
|---|---|---|---|
| `@Observable` / Observation framework | **14.0** | 17.0 | Yes |
| `NavigationSplitView` | **13.0** | 16.0 | Yes |
| `.toolbar(removing:)` | **14.0** | 17.0 | Yes |
| `ContentUnavailableView` | **14.0** | 17.0 | Yes |
| `Table` | **12.0** | 16.0 | Yes |
| `.inspector(isPresented:content:)` | **14.0** | 17.0 | Yes |
| SwiftData `ModelContainer` / `@Model` | **14.0** | 17.0 | Yes (also `swift: 5.9.0 -`) |
| `.scrollBounceBehavior(_:axes:)` | **13.3** | 16.4 | Yes |
| `.symbolEffect(_:options:isActive:)` | **14.0** | 17.0 | Yes |
| `MeshGradient` | **15.0** | 18.0 | **NO — macOS 15+** |
| `TextRenderer` (protocol) | 14.0 | 17.0 | see note |
| `.textRenderer(_:)` (the modifier) | **15.0** | 18.0 | **NO — macOS 15+** |

### Flags

- **`MeshGradient` is macOS 15.0+.** Not usable at a macOS 14 deployment target without `if #available(macOS 15, *)`. Do not plan a visual identity around it.
- **`TextRenderer` is effectively macOS 15.0+.** The `TextRenderer` *protocol* page reports `macOS: 14.0.0 -`, but the only way to install one — `View.textRenderer(_:)` — reports `macOS: 15.0.0 -`. Conforming to the protocol at macOS 14 is pointless because you cannot apply it. Treat the whole feature as 15+.
- Nothing in the requested list is macOS 26+ only.
- `.toolbar(removing: .sidebarToggle)` is the documented way to drop the sidebar-toggle item `NavigationSplitView` adds by default — relevant for a custom sidebar chrome.

Doc URLs:
- https://developer.apple.com/documentation/observation/observable()
- https://developer.apple.com/documentation/swiftui/navigationsplitview
- https://developer.apple.com/documentation/swiftui/view/toolbar(removing:)
- https://developer.apple.com/documentation/swiftui/contentunavailableview
- https://developer.apple.com/documentation/swiftui/table
- https://developer.apple.com/documentation/swiftui/view/inspector(ispresented:content:)
- https://developer.apple.com/documentation/swiftdata/modelcontainer
- https://developer.apple.com/documentation/swiftui/view/scrollbouncebehavior(_:axes:)
- https://developer.apple.com/documentation/swiftui/meshgradient
- https://developer.apple.com/documentation/swiftui/view/symboleffect(_:options:isactive:)
- https://developer.apple.com/documentation/swiftui/textrenderer
- https://developer.apple.com/documentation/swiftui/view/textrenderer(_:)

---

## 3. App Sandbox entitlements

`ServerOS.entitlements`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.app-sandbox</key>
    <true/>
    <key>com.apple.security.network.client</key>
    <true/>
    <key>com.apple.security.files.user-selected.read-write</key>
    <true/>
</dict>
</plist>
```

| Need | Exact entitlement key | Type |
|---|---|---|
| Enable the sandbox at all | `com.apple.security.app-sandbox` | Boolean |
| Outgoing network connections | `com.apple.security.network.client` | Boolean |
| Read/write files chosen via Open/Save panel | `com.apple.security.files.user-selected.read-write` | Boolean |
| Keychain (own items) | **none required** — see §4 | — |
| Keychain sharing across apps | `keychain-access-groups` | Array of String |

`com.apple.security.network.client` (macOS 10.7+): "A Boolean value indicating whether your app may open outgoing network connections." Apple's note: for TCP sockets, the client/server entitlements "restrict only the initiation of a network connection, not the flow of data." **Connecting to a server on the same machine still requires this entitlement** — it explicitly covers "a server process running on another machine, or on the same machine."

`com.apple.security.files.user-selected.read-write` (macOS 10.7+): "A Boolean value that indicates whether the app may have read-write access to files the user has selected using an Open or Save dialog."

Docs:
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.network.client
- https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.files.user-selected.read-write
- https://developer.apple.com/documentation/bundleresources/entitlements/keychain-access-groups

### 3.1 Security-scoped bookmarks

User-selected file access is granted per-launch by Powerbox. To keep access to a folder (e.g. a locally cached SSH key directory or a chosen log-export destination) **across app launches**, persist a security-scoped bookmark.

Create — `URL.bookmarkData(options:includingResourceValuesForKeys:relativeTo:)` with **`.withSecurityScope`**:

```swift
let data = try url.bookmarkData(
    options: [.withSecurityScope],
    includingResourceValuesForKeys: nil,
    relativeTo: nil
)
```

Resolve — `URL(resolvingBookmarkData:options:relativeTo:bookmarkDataIsStale:)` with **`.withSecurityScope`**:

```swift
var isStale = false
let url = try URL(
    resolvingBookmarkData: data,
    options: [.withSecurityScope],
    relativeTo: nil,
    bookmarkDataIsStale: &isStale
)
```

Use — you **cannot touch the resource** until you call `startAccessingSecurityScopedResource()`:

```swift
guard url.startAccessingSecurityScopedResource() else { throw ... }
defer { url.stopAccessingSecurityScopedResource() }
// file I/O here
```

`func startAccessingSecurityScopedResource() -> Bool` (macOS 10.7+): "In an app that has adopted App Sandbox, makes the resource pointed to by a security-scoped URL available to the app." Apple's warning is load-bearing: "If you fail to relinquish your access to file-system resources when you no longer need them, your app leaks kernel resources. If sufficient kernel resources leak, your app loses its ability to add file-system locations to its sandbox ... until relaunched." Every `start` must be balanced by a `stop`.

Note `.withSecurityScope` is macOS-only. If a bookmark resolves with `isStale == true`, re-create it from the resolved URL.

Doc: https://developer.apple.com/documentation/foundation/nsurl/startaccessingsecurityscopedresource()

---

## 4. Keychain

### 4.1 Modern API

`SecItem*` from the Security framework. There is no Swift-native replacement as of macOS 26; `SecItemAdd` / `SecItemCopyMatching` / `SecItemUpdate` / `SecItemDelete` remain the API.

```swift
func SecItemAdd(_ attributes: CFDictionary, _ result: UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
```

Store a server credential:

```swift
let query: [String: Any] = [
    kSecClass as String:                    kSecClassGenericPassword,
    kSecAttrService as String:              "com.serveros.agent-token",
    kSecAttrAccount as String:              serverUUID.uuidString,
    kSecValueData as String:                token.data(using: .utf8)!,
    kSecAttrAccessible as String:           kSecAttrAccessibleAfterFirstUnlock,
    kSecUseDataProtectionKeychain as String: true,
]
let status = SecItemAdd(query as CFDictionary, nil)
```

Read it back:

```swift
let query: [String: Any] = [
    kSecClass as String:                    kSecClassGenericPassword,
    kSecAttrService as String:              "com.serveros.agent-token",
    kSecAttrAccount as String:              serverUUID.uuidString,
    kSecReturnData as String:               true,
    kSecMatchLimit as String:               kSecMatchLimitOne,
    kSecUseDataProtectionKeychain as String: true,
]
var item: CFTypeRef?
let status = SecItemCopyMatching(query as CFDictionary, &item)
```

### 4.2 Attribute keys

| Key | Purpose |
|---|---|
| `kSecClass` | Item class. Use `kSecClassGenericPassword` for app secrets. |
| `kSecAttrService` | Service identifier. Part of the primary key for generic passwords. |
| `kSecAttrAccount` | Account name. The other half of the primary key. |
| `kSecValueData` | The secret bytes (`Data`). Encrypted by the system. |
| `kSecAttrAccessible` | When the item is readable. See below. |
| `kSecAttrAccessGroup` | Keychain access group; requires `keychain-access-groups` entitlement. |
| `kSecUseDataProtectionKeychain` | **Set `true`.** See §4.4. |
| `kSecAttrLabel` | User-visible label in Keychain Access. |
| `kSecAttrSynchronizable` | iCloud Keychain sync. Leave unset/false for server credentials. |
| `kSecReturnData` / `kSecMatchLimit` | Query-side result control. |

`kSecAttrService` + `kSecAttrAccount` together form the uniqueness constraint for `kSecClassGenericPassword`. Adding a duplicate returns `errSecDuplicateItem` (-25299) — update instead of add, or delete-then-add.

`SecItemAdd` blocks the calling thread. Apple: "`SecItemAdd` blocks the calling thread, so it can cause your app's UI to hang if called from the main thread. Instead, call `SecItemAdd` from a background dispatch queue or `async` function." Keep the keychain wrapper off `@MainActor`.

### 4.3 `kSecAttrAccessibleAfterFirstUnlock` vs `kSecAttrAccessibleWhenUnlocked`

- **`kSecAttrAccessibleWhenUnlocked`** — readable only while the device/Mac is unlocked. Becomes unavailable the moment the screen locks. This is the default and the most restrictive of the two.
- **`kSecAttrAccessibleAfterFirstUnlock`** — "The data in the keychain item cannot be accessed after a restart until the device has been unlocked once by the user." After that first unlock, "the data remains accessible until the next restart," including while locked. Apple: "This is recommended for items that need to be accessed by background applications."

For ServerOS: use **`kSecAttrAccessibleAfterFirstUnlock`** for agent tokens/API credentials if any background refresh, WebSocket reconnection, or menu-bar polling must survive the screen locking. Use `kSecAttrAccessibleWhenUnlocked` for secrets only ever touched during direct user interaction.

Both have a `...ThisDeviceOnly` variant (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`) that blocks migration to a new device via backup. For per-server infrastructure credentials, `ThisDeviceOnly` is the defensible default.

Doc: https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlock

### 4.4 Does keychain access need an entitlement in a sandboxed app?

**No entitlement is required to read and write your own app's keychain items.** Xcode adds an `application-identifier` entitlement to the app bundle at build time, and "Keychain Services uses this entitlement to grant the application access to its own keychain items."

`keychain-access-groups` is required **only** to share items with other apps (or with an extension), via `kSecAttrAccessGroup`. ServerOS does not need it for the MVP.

One caveat that matters on macOS: **set `kSecUseDataProtectionKeychain: true` on every query.** Apple: "A key whose value indicates whether to treat macOS keychain items like iOS keychain items... It's highly recommended that you set the value of this key to `true` for all keychain operations." Without it, macOS uses the legacy file-based keychain, where `kSecAttrAccessible` and `kSecAttrAccessGroup` are **ignored** — so your carefully chosen accessibility class silently does nothing. It is macOS 10.15+ and is safely ignored on other platforms.

Doc: https://developer.apple.com/documentation/security/ksecusedataprotectionkeychain

---

## 5. LocalAuthentication — Touch ID gate for destructive actions

```swift
import LocalAuthentication

func confirmDestructive(_ reason: String) async throws -> Bool {
    let context = LAContext()
    context.localizedFallbackTitle = "Use Password…"

    var error: NSError?
    guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
        throw error ?? LAError(.biometryNotAvailable)
    }
    return try await context.evaluatePolicy(
        .deviceOwnerAuthentication,
        localizedReason: reason
    )
}
```

Call site: `try await confirmDestructive("delete the production-postgres container")`.

**Policy constant: `LAPolicy.deviceOwnerAuthentication`** — "User authentication with biometry, Apple Watch, or the device passcode." This is the right one for a destructive-action gate: it falls back to the login password when Touch ID is unavailable or fails, so it works on Macs without a Touch Bar/Touch ID sensor and on external keyboards.

Use `.deviceOwnerAuthenticationWithBiometrics` ("User authentication with biometry") **only** if you want to hard-require Touch ID with no password fallback — on a Mac Mini with no Touch ID this returns `LAError.biometryNotAvailable` and your destructive action becomes unreachable. Not recommended.

Other cases: `.deviceOwnerAuthenticationWithWatch`, `.deviceOwnerAuthenticationWithBiometricsOrWatch`, `.deviceOwnerAuthenticationWithCompanion`, `.deviceOwnerAuthenticationWithBiometricsOrCompanion`.

API:

```swift
func evaluatePolicy(_ policy: LAPolicy, localizedReason: String, reply: @escaping @Sendable (Bool, (any Error)?) -> Void)
func evaluatePolicy(_ policy: LAPolicy, localizedReason: String) async throws -> Bool
```

`LAContext` is macOS 10.10+; `LAPolicy` is macOS 10.10+.

Copy guidance from Apple, directly applicable to the confirmation-dialog microcopy: "provide a clear reason for the authentication request, and describe the resulting action. Make the message short and clear... **Don't include the app name**, which already appears in the authentication dialog (in macOS, in the title of the dialog)."

Threading caveat: the completion-handler variant's reply "is evaluated on a private queue internal to the framework in an unspecified threading context. You must not call `canEvaluatePolicy(_:error:)` in this block, because doing so could lead to deadlock." Prefer the `async` form.

### Required Info.plist key

**On macOS: none.** `NSFaceIDUsageDescription` has availability `iOS: 11.0.0 -, iPadOS: 11.0.0 -` — it is **not a macOS key**. macOS Touch ID via `LAContext` requires no usage-description string; the `localizedReason` you pass to `evaluatePolicy` is the user-facing text.

(If a ServerOS iOS companion app later uses biometrics, that target *does* need `NSFaceIDUsageDescription`: "A message that tells people why the app is requesting the ability to authenticate with Face ID." It is required there.)

Also note: an `LAContext` should be created fresh per authentication. Reusing one lets `touchIDAuthenticationAllowableReuseDuration` silently skip the prompt — undesirable for a destructive-action gate.

Docs:
- https://developer.apple.com/documentation/localauthentication/lapolicy
- https://developer.apple.com/documentation/localauthentication/lacontext/evaluatepolicy(_:localizedreason:reply:)
- https://developer.apple.com/documentation/bundleresources/information-property-list/nsfaceidusagedescription

---

## 6. Swift 6 strict concurrency

### 6.1 Is it on by default?

**The Swift 6 language mode is opt-in at the language level, but Xcode 26+ project templates turn the new concurrency settings on for new projects.** Two separate things:

1. **Swift 6 language mode** (`SWIFT_VERSION = 6.0`) enables strict concurrency checking as *errors*. Apple: "The Swift 6 language mode is opt-in: Your projects continue to build with their current language mode."
2. **Approachable Concurrency** (Swift 6.2, Xcode 26) changes the *isolation defaults* so that opting into #1 is far less painful.

Since you are hand-writing the `.pbxproj`, none of the template defaults apply — you must set these explicitly.

### 6.2 Build settings

| Build setting | Values | Set to |
|---|---|---|
| `SWIFT_VERSION` | `5.0`, `6.0` | **`6.0`** |
| `SWIFT_APPROACHABLE_CONCURRENCY` | `YES` / `NO` | **`YES`** |
| `SWIFT_DEFAULT_ACTOR_ISOLATION` | `MainActor` / `nonisolated` | **`MainActor`** for the app target |
| `SWIFT_STRICT_CONCURRENCY` | `minimal` / `targeted` / `complete` | `complete` (implied by `SWIFT_VERSION = 6.0`) |

`SWIFT_APPROACHABLE_CONCURRENCY = YES` and `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor` are **both on by default in new Xcode 26 projects**; existing projects migrated forward get `nonisolated`.

`SWIFT_DEFAULT_ACTOR_ISOLATION` maps to the compiler flag **`-default-isolation`**. Per SE-0466: "The only valid arguments to `-default-isolation` are `MainActor` and `nonisolated`," and "If no `-default-isolation` flag is specified, the default isolation for the module is `nonisolated`." So the *compiler* default is `nonisolated` — the `MainActor` default is an Xcode template choice, and you must write it into your `.pbxproj` yourself.

`SWIFT_APPROACHABLE_CONCURRENCY` is an umbrella that enables the upcoming features `NonisolatedNonsendingByDefault` (SE-0461) and `InferIsolatedConformances` (SE-0470), among others.

In Xcode's build settings UI these appear as "Swift Compiler - Concurrency → Approachable Concurrency" and "Default Actor Isolation".

Swift Package equivalent:

```swift
swiftSettings: [
    .defaultIsolation(MainActor.self),
    .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
    .enableUpcomingFeature("InferIsolatedConformances"),
]
```

### 6.3 Practical guidance for `@MainActor` on views and models

With `SWIFT_DEFAULT_ACTOR_ISOLATION = MainActor`:

- **Do not annotate SwiftUI views with `@MainActor`.** They are already main-actor isolated — both because `View` itself is `@MainActor` and because the module default now covers everything. Adding it is noise.
- **Do not annotate `@Observable` model classes with `@MainActor`** either — they inherit it from the module default. This is the correct place for them: a UI-facing observable model that feeds SwiftUI should live on the main actor. `@Observable` + implicit `@MainActor` + `@State` is the idiomatic Xcode 26 shape.

```swift
@Observable
final class ServerListModel {       // implicitly @MainActor
    private(set) var servers: [Server] = []
    var isLoading = false

    func refresh() async {          // implicitly runs on the main actor
        isLoading = true
        defer { isLoading = false }
        servers = try? await api.fetchServers() ?? []
    }
}
```

- **Push work off the main actor deliberately, with `@concurrent`.** Under Approachable Concurrency (SE-0461), a `nonisolated async` function runs in the *caller's* execution context rather than hopping to the global pool. That means marking something `nonisolated` no longer gets it off the main thread. Use the `@concurrent` attribute for genuinely parallel work:

```swift
@concurrent
func parseLogBatch(_ raw: Data) async throws -> [LogLine] { ... }
```

This is the 2024-memory trap: `nonisolated async` used to imply "runs off the main actor." Under 6.2+ it does not.

- **Networking/agent layers:** make them `nonisolated` or `actor`-isolated explicitly, not main-actor. A `ServerAgentClient` doing `URLSession` work should be an `actor` or a `nonisolated` type with `@concurrent` methods, so the metric stream does not serialize behind UI work.
- **`Sendable`:** DTOs crossing the boundary (metrics samples, container descriptors, log lines) must be `Sendable`. Prefer `struct` + `let` — these are automatically `Sendable`. Under `InferIsolatedConformances`, protocol conformances on main-actor types are inferred `@MainActor`, which is usually what you want but will surprise you if a model is handed to a background actor.

Docs:
- https://developer.apple.com/documentation/swift/adoptingswift6
- https://www.swift.org/blog/swift-6.2-released/
- https://github.com/swiftlang/swift-evolution/blob/main/proposals/0466-control-default-actor-isolation.md
- https://swift.org/migration

---

## 7. URLSession to a local agent over plain HTTP

### 7.1 Can a sandboxed app reach `127.0.0.1:PORT`?

Yes — **with `com.apple.security.network.client`**. The entitlement explicitly covers "a server process running on another machine, **or on the same machine**." Loopback is not exempt from the sandbox; without the entitlement the connection fails.

There is no `URLSession` support for **Unix domain sockets**. `URLSession` speaks `http(s)://` over TCP only. If the ServerOS agent exposes a UDS, you must either (a) have the agent also bind a loopback TCP port, or (b) drop to `Network.framework` (`NWConnection` with `NWEndpoint.unix(path:)`) and implement HTTP framing yourself. For the MVP, bind a loopback TCP port.

### 7.2 Does ATS block `http://` to 127.0.0.1?

**Yes — for the literal IP `127.0.0.1`. No — for the hostname `localhost`.** This is the single most surprising item in this document.

Apple DTS (Quinn), testing exactly this: "I ... issued requests to `http://127.0.0.1:12345/` and `http://localhost:12345/`. The latter works but the former gets blocked by ATS."

This got *stricter*, not looser, at exactly your deployment target. From the `NSAllowsLocalNetworking` documentation:

> "In iOS 10 through iOS 16 ... and macOS 10.12 through macOS 13, ATS allows all three of these connections by default, so you no longer need an exception for any of them."
> **"In iOS 17, iPadOS 17, and macOS 14, ATS no longer allows connections to IP addresses by default. Add individual IP addresses and classless inter-domain routing (CIDR) ranges in the `NSExceptionDomains` dictionary."**

So on macOS 14+ — your deployment target — a raw-IP cleartext URL is blocked out of the box. You will see:

```
App Transport Security has blocked a cleartext HTTP (http://) resource
load since it is insecure. Temporary exceptions can be configured via
your app's Info.plist file.
```
(`NSURLErrorAppTransportSecurityRequiresSecureConnection`, -1022.)

### 7.3 What to do

**Preferred, no exception needed: use the hostname.**

```swift
URL(string: "http://localhost:8712/v1/metrics")!
```

`localhost` is an unqualified domain, not an IP literal, and is not blocked.

**If you must use the IP literal**, the narrowest correct Info.plist exception is:

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsLocalNetworking</key>
    <true/>
</dict>
```

`NSAllowsLocalNetworking` (macOS 10.12+): "controls whether App Transport Security (ATS) allows your app to connect to unqualified domains, `.local` domains, and IP addresses using IPv4 or IPv6." Apple even recommends setting it as a statement of intent: "consider setting `NSAllowsLocalNetworking` to `YES` as a declaration of intent, if appropriate, even if you don't support older OS versions."

Per-address alternative (also valid on macOS 14+, and narrower):

```xml
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>127.0.0.1</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>
        </dict>
    </dict>
</dict>
```

**Do not use `NSAllowsArbitraryLoads`.** It disables ATS globally and is one of the exceptions Apple lists as "requir[ing] you to provide justification, and might trigger additional App Store review."

### 7.4 Exception keys, for reference

Full ATS dictionary shape, verbatim from Apple:

```
NSAppTransportSecurity : Dictionary {
    NSAllowsArbitraryLoads : Boolean
    NSAllowsArbitraryLoadsForMedia : Boolean
    NSAllowsArbitraryLoadsInWebContent : Boolean
    NSAllowsLocalNetworking : Boolean
    NSRequiresNIAPTLSPackageVersion : String
    NSExceptionDomains : Dictionary {
        <domain-name-string> : Dictionary {
            NSIncludesSubdomains : Boolean
            NSExceptionAllowsInsecureHTTPLoads : Boolean
            NSExceptionMinimumTLSVersion : String
            NSExceptionRequiresForwardSecrecy : Boolean
            NSRequiresCertificateTransparency : Boolean
            NSExceptionRequiresNIAPTLSPackageVersion : String
        }
    }
}
```

Two further notes:
- **Global exceptions do not apply to domains listed in `NSExceptionDomains`.** Listing a domain there opts it *out* of the global settings entirely.
- **ATS does not apply to `Network.framework` or `CFNetwork`.** Apple: "ATS doesn't apply to calls your app makes to lower-level networking interfaces like the Network framework or CFNetwork. In these cases, you take responsibility for ensuring the security of the connection." A raw `NWConnection` to the agent bypasses ATS entirely — but then you own TLS correctness, which Apple warns against ("mistakes are both easy to make and costly").
- Debug with `nscurl --ats-diagnostics <url>` to see which exception combination a given endpoint needs.

Docs:
- https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity
- https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity/nsallowslocalnetworking
- https://developer.apple.com/documentation/security/preventing-insecure-network-connections
- https://developer.apple.com/forums/thread/6205
