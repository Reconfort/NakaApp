# swift-nio-ssh API Reference (verbatim, extracted from source)

**Purpose:** enable writing *correct* Swift against `swift-nio-ssh` without a compiler.

Every declaration below was copied verbatim from the cloned source at the exact release tag.
Anything not verifiable from source is explicitly marked **UNCONFIRMED**.

## Provenance

| Package | Latest release tag | Commit verified | Source of truth |
|---|---|---|---|
| `apple/swift-nio-ssh` | **0.15.0** | `3ec281496f28a3b6581afd946b759e2642f5cd8d` (clone HEAD == tag 0.15.0) | `Sources/NIOSSH/**`, `Sources/NIOSSHClient/**`, `Tests/NIOSSHTests/**`, `README.md` |
| `apple/swift-nio` | **2.102.0** | `a931f2c1de8dd49381ce3bf2e279d033f68d8865` (tag 2.102.0 checked out) | `Sources/NIOCore/**`, `Sources/NIOPosix/**` |
| `apple/swift-crypto` | **4.5.2** (latest tag) | clone HEAD `da9d28d69ebe3894b18376c8f2395c2f37b8448f` (main; see note) | `Sources/Crypto/**`, `Sources/CryptoExtras/**` |

> swift-crypto note: the `Crypto` declarations below were read from the cloned `main` branch,
> not the 4.5.2 tag. The key-type initializers quoted are long-stable API, but treat the
> *exact* `throws(CryptoKitMetaError)` typed-throws spellings as **UNCONFIRMED for 4.5.2** —
> write `try` / `do-catch` normally and it compiles either way.

### SwiftPM package lines (real, current versions)

```swift
// swift-tools-version:6.1        // swift-nio-ssh 0.15.0's own manifest is 6.1
dependencies: [
    .package(url: "https://github.com/apple/swift-nio-ssh.git", from: "0.15.0"),
    .package(url: "https://github.com/apple/swift-nio.git", from: "2.102.0"),
    // Only if you need to build NIOSSHPrivateKey from PEM/DER/raw bytes yourself:
    .package(url: "https://github.com/apple/swift-crypto.git", from: "4.5.2"),
],
targets: [
    .target(
        name: "YourTarget",
        dependencies: [
            .product(name: "NIOSSH", package: "swift-nio-ssh"),
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "Crypto", package: "swift-crypto"),        // optional
            .product(name: "_CryptoExtras", package: "swift-crypto"), // optional: Ed25519 PEM
        ]
    )
]
```

**Platform floor declared by swift-nio-ssh 0.15.0** (`Package.swift`, verbatim):

```swift
platforms: [
    .macOS(.v10_15),
    .iOS(.v13),
    .watchOS(.v6),
    .tvOS(.v13),
],
```

swift-nio-ssh's own dependency constraints (verbatim from its `Package.swift`):

```swift
.package(url: "https://github.com/apple/swift-nio.git", from: "2.81.0"),
.package(url: "https://github.com/apple/swift-crypto.git", "1.0.0"..<"5.0.0"),
.package(url: "https://github.com/apple/swift-atomics.git", from: "1.0.2"),
```

Minimum Swift version for `0.13.0 ..<` is **6.1** (README table).

### The single most important architectural fact

There is **one public entry point**: the `NIOSSHHandler` `ChannelHandler`. You put it in a
normal NIO TCP `Channel`'s pipeline; it drives version exchange, KEX, and user auth by itself
using the two delegates you pass in its `SSHClientConfiguration`. Everything else (exec, shell,
port forwarding) happens on **child channels** created via `NIOSSHHandler.createChannel`.

---

## a. TCP connect + SSH transport handshake as a CLIENT

### `NIOSSHHandler` (verbatim — `Sources/NIOSSH/NIOSSHHandler.swift`)

```swift
public final class NIOSSHHandler {
    /// Construct a new ``NIOSSHHandler``.
    ///
    /// - parameters:
    ///     - role: The role of this channel in the connection, client or server.
    ///     - allocator: An allocator for `ByteBuffer`s
    ///     - inboundChildChannelInitializer: A callback that will be invoked whenever the remote peer attempts to construct a new SSH channel in a connection.
    public init(
        role: SSHConnectionRole,
        allocator: ByteBufferAllocator,
        inboundChildChannelInitializer: ((Channel, SSHChannelType) -> EventLoopFuture<Void>)?
    )
}

@available(*, unavailable)
extension NIOSSHHandler: Sendable {}
```

```swift
extension NIOSSHHandler: ChannelDuplexHandler {
    public typealias InboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer
    public typealias InboundOut = Never  // Temporary
    public typealias OutboundIn = Never  // Temporary

    public func handlerAdded(context: ChannelHandlerContext)
    public func handlerRemoved(context: ChannelHandlerContext)
    public func channelActive(context: ChannelHandlerContext)
    public func channelInactive(context: ChannelHandlerContext)
    public func channelRead(context: ChannelHandlerContext, data: NIOAny)
    public func channelReadComplete(context: ChannelHandlerContext)
}
```

> `NIOSSHHandler` is **explicitly non-`Sendable`** (`@available(*, unavailable) extension NIOSSHHandler: Sendable {}`).
> See "Concurrency gotchas" — this breaks `pipeline.handler(type:).get()` under Swift 6.

### `SSHConnectionRole` (verbatim — `Sources/NIOSSH/Role.swift`)

```swift
/// The role of a given party in an SSH connection.
public enum SSHConnectionRole {
    /// This entity is an SSH client.
    case client(SSHClientConfiguration)

    /// This entity is an SSH server.
    case server(SSHServerConfiguration)
}

@available(*, unavailable)
extension SSHConnectionRole: Sendable {}
```

### `SSHClientConfiguration` (verbatim — `Sources/NIOSSH/SSHClientConfiguration.swift`)

```swift
/// Configuration for an SSH client.
public struct SSHClientConfiguration {
    /// The user authentication delegate to be used with this client.
    public var userAuthDelegate: NIOSSHClientUserAuthenticationDelegate

    /// The server authentication delegate to be used with this client.
    public var serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate

    /// The global request delegate to be used with this client.
    public var globalRequestDelegate: GlobalRequestDelegate

    /// Supported data encryption algorithms
    public var transportProtectionSchemes: [NIOSSHTransportProtection.Type]

    /// The maximum size, in bytes, of a channel data payload this peer is willing to receive ...
    /// Defaults to `1 << 17` (128 KiB).
    ///
    /// - Precondition: Must be at least 32768 bytes ...
    /// - Precondition: The packet size must leave 1024 bytes for headers and framing.
    public var maximumPacketSize: Int = Constants.defaultMaximumChannelPacketSize

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil
    )

    public init(
        userAuthDelegate: NIOSSHClientUserAuthenticationDelegate,
        serverAuthDelegate: NIOSSHClientServerAuthenticationDelegate,
        globalRequestDelegate: GlobalRequestDelegate? = nil,
        transportProtectionSchemes: [NIOSSHTransportProtection.Type]
    )
}

// The various delegates aren't required to be Sendable, so the config isn't sendable.
@available(*, unavailable)
extension SSHClientConfiguration: Sendable {}
```

`maximumPacketSize` is a stored property **with a `didSet` that `precondition`s** — assigning
an out-of-range value crashes at runtime (min `32768`, max `UInt32.max - 1024`).

### `Constants` (verbatim — `Sources/NIOSSH/Constants.swift`)

```swift
public enum Constants: Sendable {
    public static let bundledTransportProtectionSchemes: [(NIOSSHTransportProtection & _NIOSSHSendableMetatype).Type] =
        [
            AES256GCMOpenSSHTransportProtection.self, AES128GCMOpenSSHTransportProtection.self,
        ]
}
```

Everything else in `Constants` is `internal` (`version = "SSH-2.0-SwiftNIOSSH_1.0"`,
`defaultMaximumChannelPacketSize = 1 << 17`, `minimumChannelPacketSize = 32768`,
`maximumChannelPacketSize = UInt32.max - 1024`, `channelWindowSizePacketMultiple = 64`).
`AES256GCMOpenSSHTransportProtection` / `AES128GCMOpenSSHTransportProtection` are **internal types** —
you can pass `Constants.bundledTransportProtectionSchemes`, but you cannot name them.

### Handshake-completion / banner events

`NIOSSHHandler` fires these up the **parent** channel's pipeline as inbound user events
(verbatim — `Sources/NIOSSH/Connection State Machine/Operations/AcceptsUserAuthMessages.swift`):

```swift
public struct NIOUserAuthBannerEvent: Hashable, Sendable {
    public var message: String
    public var languageTag: String
    public init(message: String, languageTag: String)
}

public struct UserAuthSuccessEvent: Hashable, Sendable {
    public init() {}
}
```

`UserAuthSuccessEvent` is how you learn the connection is authenticated and usable.

### `ClientBootstrap` (verbatim — swift-nio 2.102.0, `Sources/NIOPosix/Bootstrap.swift`)

```swift
public final class ClientBootstrap: NIOClientTCPBootstrapProtocol {
    public convenience init(group: EventLoopGroup)
    public init?(validatingGroup group: EventLoopGroup)

    @preconcurrency
    public func channelInitializer(_ handler: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> Self

    @inlinable
    public func channelOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> Self

    public func connectTimeout(_ timeout: TimeAmount) -> Self

    public func connect(host: String, port: Int) -> EventLoopFuture<Channel>
    public func connect(to address: SocketAddress) -> EventLoopFuture<Channel>

    @available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
    public func connect<Output: Sendable>(
        host: String,
        port: Int,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output

    @available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
    public func connect<Output: Sendable>(
        to address: SocketAddress,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Output>
    ) async throws -> Output
}
```

Supporting NIO API used in the examples (verbatim):

```swift
// Sources/NIOPosix/MultiThreadedEventLoopGroup.swift
public convenience init(numberOfThreads: Int)
// Sources/NIOPosix/PosixSingletons.swift
public static var posixEventLoopGroup: MultiThreadedEventLoopGroup   // NIOSingletons.posixEventLoopGroup

// Sources/NIOCore/ChannelPipeline.swift
public var syncOperations: SynchronousOperations
public struct SynchronousOperations {
    public func addHandler(
        _ handler: ChannelHandler,
        name: String? = nil,
        position: ChannelPipeline.SynchronousOperations.Position = .last
    ) throws
    public func addHandlers(
        _ handlers: [ChannelHandler],
        position: ChannelPipeline.SynchronousOperations.Position = .last
    ) throws
    @inlinable
    public func handler<Handler: ChannelHandler>(type _: Handler.Type) throws -> Handler
    public func triggerUserOutboundEvent(_ event: Any, promise: EventLoopPromise<Void>?)
}

// async/future variant on ChannelPipeline itself:
@inlinable @preconcurrency
public func handler<Handler: ChannelHandler & _NIOCoreSendableMetatype>(
    type _: Handler.Type
) -> EventLoopFuture<Handler>

// Sources/NIOCore/EventLoop.swift
public func submit<T>(_ task: @escaping @Sendable () throws -> T) -> EventLoopFuture<T>
public func flatSubmit<T: Sendable>(_ task: @escaping @Sendable () -> EventLoopFuture<T>) -> EventLoopFuture<T>
public func makePromise<T>(of type: T.Type = T.self, file: StaticString = #fileID, line: UInt = #line) -> EventLoopPromise<T>
public func makeSucceededFuture<Success: Sendable>(_ value: Success) -> EventLoopFuture<Success>
@preconcurrency @inlinable
public func makeCompletedFuture<Success: Sendable>(withResultOf body: () throws -> Success) -> EventLoopFuture<Success>

// Sources/NIOCore/ChannelInvoker.swift
@preconcurrency
public func triggerUserOutboundEvent(
    _ event: Any & Sendable,
    file: StaticString = #fileID,
    line: UInt = #line
) -> EventLoopFuture<Void>
public enum CloseMode: Sendable { case output; case input; case all }

// Sources/NIOCore/Channel.swift
public enum ChannelEvent: Equatable, Sendable { case inputClosed; case outputClosed }
public func close(mode: CloseMode = .all, promise: EventLoopPromise<Void>?)

// Sources/NIOCore/IOData.swift
public enum IOData: Sendable {
    case byteBuffer(ByteBuffer)
    case fileRegion(FileRegion)
}

// Sources/NIOCore/ChannelOption.swift
public static let allowRemoteHalfClosure = Types.AllowRemoteHalfClosureOption()
public static func socketOption(_ name: NIOBSDSocket.Option) -> Self
public static func tcpOption(_ name: NIOBSDSocket.Option) -> Self
// Sources/NIOCore/BSDSocketAPI.swift
public static var tcp_nodelay: NIOBSDSocket.Option { get }
public static var so_reuseaddr: NIOBSDSocket.Option { get }

// Sources/NIOPosix/Bootstrap.swift — ServerBootstrap (local-forward listening socket)
public func childChannelInitializer(_ initializer: @escaping @Sendable (Channel) -> EventLoopFuture<Void>) -> Self
public func serverChannelOption<Option: ChannelOption>(_ option: Option, value: Option.Value) -> Self
public func bind(host: String, port: Int) -> EventLoopFuture<Channel>
```

Prefer `.tcpOption(.tcp_nodelay)` / `.socketOption(.so_reuseaddr)` over
`ChannelOptions.socket(SocketOptionLevel(IPPROTO_TCP), TCP_NODELAY)` (which the swift-nio-ssh
sample uses): the `socket(_:_:)` overload sits inside a platform `#if` block, the named ones do not.
Note `ClientBootstrap.init` already appends `.tcpOption(.tcp_nodelay) = 1` by default.

---

## b. User authentication

### The client delegate protocol (verbatim — `Sources/NIOSSH/User Authentication/ClientUserAuthenticationDelegate.swift`)

```swift
public protocol NIOSSHClientUserAuthenticationDelegate {
    /// Called when ``NIOSSH`` would like to attempt to offer a new authentication method.
    ///
    /// The callback is provided the authentication methods that the server is willing to accept in
    /// `availableMethods`. The delegate needs to provide an authentication offer by completing
    /// `nextChallengePromise`. If no further authentication offers are available (perhaps because the server
    /// has rejected them all) then this promise should be failed, which will terminate connection establishment.
    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    )
}
```

**How to answer `nextAuthenticationType`** — three outcomes, all via the promise:

| Intent | Call |
|---|---|
| Offer a credential | `nextChallengePromise.succeed(offer)` |
| "I have nothing left to try" (clean auth failure) | `nextChallengePromise.succeed(nil)` |
| Hard error (e.g. server doesn't offer a method you need) | `nextChallengePromise.fail(error)` — terminates connection establishment |

The delegate may complete the promise **asynchronously** (this is the documented reason it is a
promise and not a return value — it lets you show an interactive password prompt).
`nextAuthenticationType` is called repeatedly until you return `nil`/fail — a delegate that
always returns the same offer loops forever, so **always nil out your credential after offering it**.

### `NIOSSHAvailableUserAuthenticationMethods` (verbatim)

```swift
public struct NIOSSHAvailableUserAuthenticationMethods: OptionSet, Sendable {
    public var rawValue: UInt8
    public init(rawValue: UInt8)

    /// Public key authentication is acceptable.
    public static let publicKey: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 0)
    /// Password-based authentication is acceptable.
    public static let password: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 1)
    /// Host-based authentication is acceptable.
    public static let hostBased: NIOSSHAvailableUserAuthenticationMethods = .init(rawValue: 1 << 2)
    /// A short-hand for all supported authentication types.
    public static let all: NIOSSHAvailableUserAuthenticationMethods = [.publicKey, .password, .hostBased]
}

extension NIOSSHAvailableUserAuthenticationMethods: Hashable {}
```

Only `"publickey"`, `"password"`, `"hostbased"` are mapped from the wire; unknown server methods
(e.g. `keyboard-interactive`) are **silently ignored**. There is no keyboard-interactive support.

### `NIOSSHUserAuthenticationOffer` and `.Offer` (verbatim)

```swift
/// A specific offer of user authentication. This type is the one used on the client side.
public struct NIOSSHUserAuthenticationOffer: Sendable {
    /// The username for which the client would like to authenticate.
    public var username: String

    /// The specific authentication offer.
    public var offer: Offer

    public init(username: String, serviceName: String, offer: Offer) {
        self.username = username
        self.offer = offer
    }
}

extension NIOSSHUserAuthenticationOffer {
    public enum Offer: Sendable {
        /// The client would like to perform private key authentication.
        case privateKey(PrivateKey)
        /// The client would like to perform password authentication.
        case password(Password)
        /// The client would like to perform host-based authentication.
        /// This method is currently unsupported by ``NIOSSH``.
        case hostBased(HostBased)
        /// The client believes it does not need authentication.
        case none
    }
}

extension NIOSSHUserAuthenticationOffer.Offer {
    public struct PrivateKey: Sendable {
        /// The client's private key. This is not sent to the server ...
        public var privateKey: NIOSSHPrivateKey
        /// The client's public key. This is sent to the server.
        public var publicKey: NIOSSHPublicKey

        public init(privateKey: NIOSSHPrivateKey)
        public init(privateKey: NIOSSHPrivateKey, certifiedKey: NIOSSHCertifiedPublicKey)
    }

    public struct Password: Sendable {
        /// The client's password.
        public var password: String
        public init(password: String)
    }

    public struct HostBased: Sendable {
        init() {
            fatalError("PublicKeyRequest is currently unimplemented")
        }
    }
}
```

**Gotchas, all confirmed in source:**

1. `init(username:serviceName:offer:)` takes `serviceName` and **throws it away** — the initializer
   body never stores it. The service is hard-coded to `"ssh-connection"` when the message is built
   (`self.service = "ssh-connection"`). Every sample in the repo passes `serviceName: ""`.
   You must still pass the argument; it is not defaulted.
2. `.hostBased` is a trap: `HostBased.init()` is `internal` **and** unconditionally `fatalError`s.
   Never construct it.
3. `NIOSSHUserAuthenticationOffer` is `Sendable` — safe to build off the event loop and succeed
   the promise from another thread/queue (the shipped `InteractivePasswordPromptDelegate` does
   exactly this from a `DispatchQueue`).

### Password auth — shipped implementation (verbatim — `SimplePasswordDelegate.swift`)

This is public API you can use directly, and is the canonical shape to copy:

```swift
public final class SimplePasswordDelegate {
    private var authRequest: NIOSSHUserAuthenticationOffer?

    public init(username: String, password: String) {
        self.authRequest = NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",
            offer: .password(.init(password: password))
        )
    }
}

@available(*, unavailable)
extension SimplePasswordDelegate: Sendable {}

extension SimplePasswordDelegate: NIOSSHClientUserAuthenticationDelegate {
    public func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        if let authRequest = self.authRequest, availableMethods.contains(.password) {
            // We need to nil out our copy because any future calls must return nil
            self.authRequest = nil
            nextChallengePromise.succeed(authRequest)
        } else {
            nextChallengePromise.succeed(nil)
        }
    }
}
```

> Note its doc comment says "`NIOSSHServerUserAuthenticationDelegate`" — that is a typo upstream;
> it conforms to the **client** protocol. Also note `SimplePasswordDelegate` is **not `Sendable`**.

### Private key auth — the offer shape (verbatim from `Tests/NIOSSHTests/UserAuthenticationStateMachineTests.swift`)

```swift
final class InfinitePrivateKeyDelegate: NIOSSHClientUserAuthenticationDelegate {
    let key = NIOSSHPrivateKey(p256Key: .init())

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        let request = NIOSSHUserAuthenticationOffer(
            username: "foo",
            serviceName: "",
            offer: .privateKey(.init(privateKey: self.key))
        )
        nextChallengePromise.succeed(request)
    }
}
```

With an OpenSSH **certificate** instead of a bare key:

```swift
self.privateKey = try NIOSSHPrivateKey(
    p256Key: P256.Signing.PrivateKey(rawRepresentation: Fixtures.privateKeyRaw)
)
self.certifiedKey = try NIOSSHCertifiedPublicKey(NIOSSHPublicKey(openSSHPublicKey: Fixtures.certificateKey))!
// ...
offer: .privateKey(.init(privateKey: self.privateKey, certifiedKey: self.certifiedKey))
```

### `NIOSSHPrivateKey` — the COMPLETE public surface (verbatim — `NIOSSHPrivateKey.swift`)

```swift
@preconcurrency import Crypto
import NIOCore

public struct NIOSSHPrivateKey: Sendable {
    public init(ed25519Key key: Curve25519.Signing.PrivateKey)
    public init(p256Key key: P256.Signing.PrivateKey)
    public init(p384Key key: P384.Signing.PrivateKey)
    public init(p521Key key: P521.Signing.PrivateKey)

    #if canImport(Darwin)
    public init(secureEnclaveP256Key key: SecureEnclave.P256.Signing.PrivateKey)
    #endif

    /// Obtains the public key for a corresponding private key.
    public var publicKey: NIOSSHPublicKey { get }
}
```

That is **all of it**. Consequences you must design around:

- **There is no PEM / OpenSSH / DER initializer on `NIOSSHPrivateKey`.** You must produce a
  `Crypto` key first and wrap it. (`sign(...)` and `hostKeyAlgorithms` are `internal`.)
- **There is no RSA support anywhere in the library.** Grepping the whole of `Sources/` for
  "rsa" (case-insensitive) returns **zero** matches. The README confirms:
  *"Modern cryptographic primitives only: Ed25519 and ECDSA over the major NIST curves
  (P256, P384, P521) for asymmetric cryptography, AES-GCM for symmetric cryptography,
  x25519 for key exchange"*. An `ssh-rsa` user key or host key **cannot** be used. Plan for
  Ed25519 (and P256/384/521) only; a server offering only `ssh-rsa` host keys will fail KEX
  with `NIOSSHError.keyExchangeNegotiationFailure` / `.invalidHostKeyForKeyExchange`.
- The wrapped Crypto key types map to these SSH algorithm names (`internal var hostKeyAlgorithms`,
  quoted for reference): `ed25519 -> "ssh-ed25519"`, `ecdsaP256 -> "ecdsa-sha2-nistp256"`,
  `ecdsaP384 -> "ecdsa-sha2-nistp384"`, `ecdsaP521 -> "ecdsa-sha2-nistp521"`,
  `secureEnclaveP256 -> "ecdsa-sha2-nistp256"`.
- `SecureEnclave.P256.Signing.PrivateKey` is supported on Darwin — relevant if ServerOS wants
  hardware-backed client identities on macOS.

### Building the `Crypto` key to hand to `NIOSSHPrivateKey`

From swift-crypto (`Sources/Crypto/Key Agreement/ECDH.swift` — yes, `P256.Signing.PrivateKey`
lives in that file; verbatim):

```swift
extension P256 {
    public enum Signing: Sendable {
        public struct PrivateKey: NISTECPrivateKey, Sendable {
            /// Creates a random P-256 private key for signing.
            public init(compactRepresentable: Bool = true)

            /// Creates a P-256 private key for signing from an ANSI x9.63 representation.
            public init<Bytes: ContiguousBytes>(x963Representation: Bytes) throws(CryptoKitMetaError)

            /// Creates a P-256 private key for signing from a collection of bytes.
            public init<Bytes: ContiguousBytes>(rawRepresentation: Bytes) throws(CryptoKitMetaError)

            #if !hasFeature(Embedded)
            /// Creates a P-256 private key for signing from a Privacy-Enhanced Mail (PEM) representation.
            /// Accepts PEM types "EC PRIVATE KEY" (SEC1) and "PRIVATE KEY" (PKCS#8).
            public init(pemRepresentation: String) throws(CryptoKitMetaError)
            #endif

            /// Creates a P-256 private key for signing from a DER encoded representation.
            /// Tries PKCS#8 first, then falls back to SEC.1.
            public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws(CryptoKitMetaError)
                where Bytes.Element == UInt8

            public var publicKey: P256.Signing.PublicKey { get }
            public var rawRepresentation: Data { get }
            public var x963Representation: Data { get }
            public var derRepresentation: Data { get }
            // pemRepresentation: String  (guarded by #if !hasFeature(Embedded))
        }
    }
}
```

`P384.Signing.PrivateKey` and `P521.Signing.PrivateKey` are generated from the same gyb template
and have the identical initializer set.

Ed25519 (verbatim — `Sources/Crypto/Keys/EC/Ed25519Keys.swift`):

```swift
extension Curve25519.Signing {
    public struct PrivateKey: ECPrivateKey, Sendable {
        public init()
        public init<D: ContiguousBytes>(rawRepresentation data: D) throws(CryptoKitMetaError)
        public var publicKey: PublicKey { get }
        public var rawRepresentation: Data { get }
    }
    public struct PublicKey: Sendable {
        public init<D: ContiguousBytes>(rawRepresentation: D) throws(CryptoKitMetaError)
        public var rawRepresentation: Data { get }
    }
}
```

Note there is **no PEM initializer for Ed25519 in the `Crypto` module**. PEM for Ed25519 lives in
the separate `CryptoExtras` product (verbatim — `Sources/CryptoExtras/EC/Curve25519+PEM.swift`):

```swift
@available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
extension Curve25519.Signing.PrivateKey {
    public var derRepresentation: Data { get }
    public var pemRepresentation: String { get }
    public init(pemRepresentation: String) throws
    public init<Bytes: RandomAccessCollection>(derRepresentation: Bytes) throws where Bytes.Element == UInt8
}
```

> **Critical practical gotcha:** these PEM parsers accept **PKCS#8 / SEC1 PEM**
> (`-----BEGIN PRIVATE KEY-----`, `-----BEGIN EC PRIVATE KEY-----`). They do **not** parse the
> modern OpenSSH private-key container (`-----BEGIN OPENSSH PRIVATE KEY-----`), which is what
> `ssh-keygen` writes by default and what is in almost every user's `~/.ssh/id_ed25519`.
> Neither swift-nio-ssh nor swift-crypto contains an OpenSSH-private-key parser — confirmed by
> grepping `openSSH` across `Sources/NIOSSH/`, which matches only the **public** key APIs.
> To support real `~/.ssh` keys, ServerOS must either (1) ship its own OpenSSH private key
> (bcrypt-KDF + openssh-key-v1) parser, (2) require `ssh-keygen -p -m PKCS8`-converted keys, or
> (3) use `SecureEnclave.P256` / app-generated keys. Mark this as a real work item.

### `UserAuthSignableRequest` / signable payload — **does not exist as public API**

There is no type named `UserAuthSignableRequest` anywhere in the repository. The closest thing is:

```swift
// Sources/NIOSSH/User Authentication/UserAuthSignablePayload.swift  —  INTERNAL
internal struct UserAuthSignablePayload {
    private(set) var bytes: ByteBuffer

    init(sessionIdentifier: ByteBuffer, userName: String, serviceName: String, publicKey: NIOSSHPublicKey)
}
```

It is `internal`, as is `NIOSSHPrivateKey.sign(_:)`. **You cannot implement a custom signer
(e.g. an SSH-agent bridge or a Keychain-backed signer) with the public 0.15.0 API** — you must
hand the library a real `NIOSSHPrivateKey` and it does the signing itself, in
`SSHMessage.UserAuthRequestMessage.init(request:sessionID:)`:

```swift
case .privateKey(let privateKeyRequest):
    let dataToSign = UserAuthSignablePayload(
        sessionIdentifier: sessionID,
        userName: self.username,
        serviceName: self.service,
        publicKey: privateKeyRequest.publicKey
    )
    let signature = try privateKeyRequest.privateKey.sign(dataToSign)
    self.method = .publicKey(.known(key: privateKeyRequest.publicKey, signature: signature))
```

(The RFC 4252 §7 byte layout it signs is documented verbatim in the file's header comment.)

### Server-side types (for completeness / symmetry)

```swift
public struct NIOSSHUserAuthenticationRequest: Sendable {
    public var username: String
    public var request: Request
    public init(username: String, serviceName: String, request: Request)   // serviceName also discarded
}
extension NIOSSHUserAuthenticationRequest {
    public enum Request: Sendable {
        case publicKey(PublicKey)
        case password(Password)
        case hostBased(HostBased)
        case none
    }
}
public enum NIOSSHUserAuthenticationOutcome: Sendable {
    case success
    case partialSuccess(remainingMethods: NIOSSHAvailableUserAuthenticationMethods)
    case failure
}
```

---

## c. Host key verification

### The delegate (verbatim — `Sources/NIOSSH/Keys And Signatures/ClientServerAuthenticationDelegate.swift`)

```swift
/// A ``NIOSSHClientServerAuthenticationDelegate`` is an object that can validate whether
/// a server host key is trusted.
public protocol NIOSSHClientServerAuthenticationDelegate {
    /// Invoked to validate a specific host key. Implementations should succeed the `validationCompletePromise`
    /// if they trust the host key, or fail it if they do not.
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>)
}
```

The shipped example (verbatim — `Sources/NIOSSHClient/main.swift`) — note the warning:

```swift
final class AcceptAllHostKeysDelegate: NIOSSHClientServerAuthenticationDelegate {
    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        // Do not replicate this in your own code: validate host keys! This is a
        // choice made for expedience, not for any other reason.
        validationCompletePromise.succeed(())
    }
}
```

### `NIOSSHPublicKey` — the COMPLETE public surface (verbatim — `NIOSSHPublicKey.swift`)

```swift
public struct NIOSSHPublicKey: Sendable, Hashable {
    /// Create a ``NIOSSHPublicKey`` from the OpenSSH public key string.
    public init(openSSHPublicKey: String) throws

    /// Encapsulate a ``NIOSSHCertifiedPublicKey`` in a ``NIOSSHPublicKey``.
    public init(_ certifiedKey: NIOSSHCertifiedPublicKey)
}

extension String {
    /// Takes a NIOSSHPublicKey and turns it into OpenSSH public key string in the format of "algorithm-id base64-encoded-key"
    public init(openSSHPublicKey: NIOSSHPublicKey)
}
```

**What is available for pinning — precisely:**

| Thing you might want | Exists? |
|---|---|
| `hostKey.fingerprint` | **NO.** Grepping `fingerprint` across `Sources/`, `Tests/`, `README.md` yields **zero** matches. |
| `hostKey.rawRepresentation` | **NO** public member. `rawRepresentation` appears only inside `internal` `Equatable`/`Hashable` implementations on the *backing* Crypto keys. |
| `hostKey.keyPrefix` (algorithm name) | exists but is **`internal`**. |
| `hostKey == otherKey` | **YES** — `NIOSSHPublicKey: Hashable` (structural equality over the underlying key bytes). |
| `String(openSSHPublicKey: hostKey)` | **YES** — returns `"<algorithm-id> <base64>"` (no comment field). |
| `try NIOSSHPublicKey(openSSHPublicKey: "ssh-ed25519 AAAA...")` | **YES** — parses `"algorithm-id base64-key [comment]"` (splits on space, `maxSplits: 2`). |
| Hashable (usable as dictionary key / `Set` member) | **YES** |

**Therefore the correct pinning strategy** is one of:

1. **Exact key comparison (recommended, simplest, exact):** store the known-good key,
   re-parse it with `NIOSSHPublicKey(openSSHPublicKey:)`, and compare with `==`.
2. **Canonical-string comparison / storage:** persist `String(openSSHPublicKey: hostKey)` and
   compare strings. This is also how you build a `known_hosts`-style store.
3. **Your own fingerprint:** derive the OpenSSH `SHA256:` fingerprint yourself from
   `String(openSSHPublicKey:)` by base64-decoding the second field and SHA256-ing the raw
   blob, i.e. `SHA256(base64decode(components[1]))` base64-encoded without padding. This
   reproduces `ssh-keygen -lf`'s output format. **UNCONFIRMED** — no code in swift-nio-ssh does
   this; it follows from the wire format, and the base64 body is verifiably the same
   `writeSSHHostKey` blob OpenSSH hashes, but nothing in the library validates that claim.

Certificates (verbatim signatures — `NIOSSHCertifiedPublicKey.swift`) if you support CA-signed hosts:

```swift
public struct NIOSSHCertifiedPublicKey {
    public var nonce: ByteBuffer { get }
    public var serial: UInt64 { get }
    public var type: CertificateType { get }
    public var key: NIOSSHPublicKey { get }
    public var keyID: String { get }
    public var validPrincipals: [String] { get }
    public var validAfter: UInt64 { get }
    public var validBefore: UInt64 { get }
    public var criticalOptions: [String: String] { get }
    public var extensions: [String: String] { get }
    public var signatureKey: NIOSSHPublicKey { get }
    public var signature: NIOSSHSignature { get }

    public init(/* see source, long */)
    public init?(_ key: NIOSSHPublicKey)
    public func validate(/* see source */)

    public struct CertificateType: RawRepresentable, Sendable {
        public var rawValue: UInt32
        public init(rawValue: UInt32)
        public static let user = CertificateType(rawValue: 1)
        public static let host = CertificateType(rawValue: 2)
    }
}
```

`public init?(_ key: NIOSSHPublicKey)` is the downcast: `NIOSSHCertifiedPublicKey(hostKey)`
returns `nil` if the presented host key is not a certificate.

---

## d. `session` channel + `exec`, reading stdout/stderr

### `SSHChannelType` (verbatim — `Sources/NIOSSH/Child Channels/SSHChannelType.swift`)

```swift
public enum SSHChannelType: Equatable, Sendable {
    /// A "session" is remote execution of a program.
    case session
    /// "Direct TCP/IP" is a request from the client to the server to open an outbound connection.
    case directTCPIP(DirectTCPIP)
    /// "Forwarded TCP/IP" is a connection that was accepted from a listening socket and is being forwarded to the client.
    case forwardedTCPIP(ForwardedTCPIP)
}
```

### `NIOSSHHandler.createChannel` — EXACT signature (verbatim)

```swift
extension NIOSSHHandler {
    /// Creates an SSH channel.
    ///
    /// This function is **not** thread-safe: it may only be called from on the channel.
    ///
    /// - parameters:
    ///     - promise: An `EventLoopPromise` that will be fulfilled with the channel when it becomes active.
    ///     - channelType: The type of the channel to create. Defaults to ``SSHChannelType/session`` for running remote processes.
    ///     - channelInitializer: A callback that will be invoked to initialize the channel.
    public func createChannel(
        _ promise: EventLoopPromise<Channel>? = nil,
        channelType: SSHChannelType = .session,
        _ channelInitializer: ((Channel, SSHChannelType) -> EventLoopFuture<Void>)?
    )
}
```

Notes confirmed from the body:
- Returns `Void`; the result arrives on `promise`.
- The initializer closure is **unlabeled and trailing**, and is **not `@Sendable`**.
- It is safe to call **before** user auth completes: pending initializations are queued
  (`pendingChannelInitializations`) and flushed in `channelReadComplete` once
  `stateMachine.hasActivated`. If the connection is already disconnected, the promise fails with
  `NIOSSHError.creatingChannelAfterClosure`.
- **Must be called on the connection's event loop.**

### `SSHChannelData` and `DataType` (verbatim — `Sources/NIOSSH/Child Channels/SSHChannelData.swift`)

```swift
public struct SSHChannelData {
    /// The type of this data.
    public var type: DataType
    /// The data in this message.
    public var data: IOData

    public init(type: DataType, data: IOData)
}

extension SSHChannelData: Equatable {}
extension SSHChannelData: Sendable {}

extension SSHChannelData {
    public struct DataType {
        /// Regular channel data.
        public static let channel = DataType(_baseType: 0)
        /// Extended data associated with stderr.
        public static let stdErr = DataType(_baseType: 1)

        /// Construct an ``SSHChannelData`` for an unknown type of extended data.
        public init(extended: Int)   // preconditions extended != 0
    }
}

extension SSHChannelData.DataType: Hashable {}
extension SSHChannelData.DataType: Sendable {}
extension SSHChannelData.DataType: CustomStringConvertible {
    public var description: String
}
extension SSHChannelData.DataType: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: UInt32)   // preconditions value != 0
}
```

**Wrapping / unwrapping — there is NO `SSHChannelDataUnwrappingHandler`.** Grepping `Unwrapping`
across `Sources/` returns **zero** matches. You write the 20-line codec yourself. The library's
own client ships exactly that, twice; here is the verbatim reusable one
(`Sources/NIOSSHClient/PortForwardingServer.swift`):

```swift
/// A simple handler that wraps data into SSHChannelData for forwarding.
final class SSHWrapperHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let data = self.unwrapInboundIn(data)

        guard case .channel = data.type, case .byteBuffer(let buffer) = data.data else {
            context.fireErrorCaught(SSHClientError.invalidData)
            return
        }

        context.fireChannelRead(self.wrapInboundOut(buffer))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let data = self.unwrapOutboundIn(data)
        let wrapped = SSHChannelData(type: .channel, data: .byteBuffer(data))
        context.write(self.wrapOutboundOut(wrapped), promise: promise)
    }
}
```

**Hard constraints on the child channel's I/O (from `SSHChildChannel.write0`):**

```swift
public func write0(_ data: NIOAny, promise: EventLoopPromise<Void>?) {
    guard !self.state.isClosed else { promise?.fail(ChannelError.ioOnClosedChannel); return }
    guard !self.state.sentEOF else { promise?.fail(ChannelError.outputClosed); return }
    let bodyData = self.unwrapData(data, as: SSHChannelData.self)
    ...
}
```

- The child channel accepts **only `SSHChannelData`** on write — writing a bare `ByteBuffer`
  to the child channel traps. Reads deliver **only `SSHChannelData`**.
- Only `.channel` and `.stdErr` can be *written*: `SSHMessage.init(_ channelData:recipientChannel:)`
  does `preconditionFailure("Non-stderr extended data codes are not supported")` for other
  extended codes, and `preconditionFailure("FileRegion not supported at this time")` if the
  `IOData` is a `.fileRegion`. **Never write `.fileRegion` to an SSH child channel.**

### `SSHChannelRequestEvent.ExecRequest` and `ExitStatus` (verbatim — `ChildChannelUserEvents.swift`)

```swift
public enum SSHChannelRequestEvent: Sendable {
    /// A request for this session to exec a command.
    public struct ExecRequest: Hashable, Sendable {
        /// The command to exec.
        public var command: String
        /// Whether this request should be replied to.
        public var wantReply: Bool

        public init(command: String, wantReply: Bool)
    }

    /// The command has exited with the given exit status.
    public struct ExitStatus: Hashable, Sendable {
        /// Whether this request should be replied to.
        public var wantReply: Bool { false }        // read-only, always false
        /// The exit status code.
        public var exitStatus: Int { get set }

        public init(exitStatus: Int)
    }

    /// A command has terminated in response to a signal.
    public struct ExitSignal: Hashable, Sendable {
        public var wantReply: Bool { false }
        /// The name of the signal, without the "SIG" prefix, e.g. "USR1".
        public var signalName: String
        public var errorMessage: String
        public var language: String
        public var dumpedCore: Bool

        public init(signalName: String, errorMessage: String, language: String, dumpedCore: Bool)
    }

    /// An ``EnvironmentRequest`` communicates a single environment variable the peer wants set.
    public struct EnvironmentRequest: Hashable, Sendable {
        public var name: String
        public var value: String
        public var wantReply: Bool
        public init(wantReply: Bool, name: String, value: String)
    }

    /// A request for this session to invoke a specific subsystem.
    public struct SubsystemRequest: Hashable, Sendable {
        public var wantReply: Bool
        public var subsystem: String
        public init(subsystem: String, wantReply: Bool)
    }

    /// Delivers a signal to the remote process.
    public struct SignalRequest: Hashable, Sendable {
        public var wantReply: Bool { false }
        /// The name of the signal (without the "SIG" prefix), e.g. "USR1".
        public var signal: String
        public init(signal: String)
    }

    /// A request to allow flow control to be managed at the client.
    public struct LocalFlowControlRequest: Hashable, Sendable {
        public var wantReply: Bool { false }
        public var clientCanDo: Bool
        public init(clientCanDo: Bool)
    }
}

/// A channel success message was received in reply to a channel request.
public struct ChannelSuccessEvent: Hashable, Sendable {
    public init() {}
}

/// A channel failure message was received in reply to a channel request.
public struct ChannelFailureEvent: Hashable, Sendable {
    public init() {}
}
```

### The authoritative list of events you may `triggerUserOutboundEvent` on a child channel

From `SSHChildChannel._actuallyTriggerOutboundEvent0` — anything not in this list fails the
promise with `ChannelError.operationUnsupported`:

`ExecRequest`, `EnvironmentRequest`, `ExitStatus`, `PseudoTerminalRequest`, `ShellRequest`,
`ExitSignal`, `SubsystemRequest`, `WindowChangeRequest`, `LocalFlowControlRequest`,
`SignalRequest`, `ChannelSuccessEvent`, `ChannelFailureEvent`.

### Inbound events you will receive on a session child channel

- `SSHChannelRequestEvent.ExitStatus` — remote process exit code
- `SSHChannelRequestEvent.ExitSignal` — killed by signal
- `ChannelSuccessEvent` / `ChannelFailureEvent` — reply to a `wantReply: true` request
  (fired by `SSHChildChannel` at lines 875/880)
- `ChannelEvent.inputClosed` — peer sent EOF (fired at line 693)
- `ChannelEvent.outputClosed` — our output side closed (fired at line 979)

### Half closure — MANDATORY

README, verbatim:

> The SSH network protocol pervasively uses half-closure in the child channels. NIO `Channel`s
> typically have half-closure support disabled by default, and SwiftNIO SSH respects this default
> in its child channels as well. **However, if you leave this setting at its default value the SSH
> child channels will behave extremely unexpectedly.** For this reason, it is strongly recommended
> that all child channels have half closure support enabled

The README writes it as `channel.setOption(ChannelOptions.allowRemoteHalfClosure, true)` which
**does not compile** against NIO 2.102.0 (there is no such unlabeled overload). The correct,
compiling spelling — verbatim from the repo's own `Sources/NIOSSHClient/ExecHandler.swift`:

```swift
func handlerAdded(context: ChannelHandlerContext) {
    let setOption = context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
    setOption.assumeIsolated().whenFailure { error in
        context.fireErrorCaught(error)
    }
}
```

To send EOF yourself: `close(mode: .output)`.

### `SSHChildChannelOptions` (verbatim — `ChildChannelOptions.swift`)

```swift
public struct SSHChildChannelOptions: Sendable {
    public static let localChannelIdentifier: SSHChildChannelOptions.Types.LocalChannelIdentifierOption = .init()
    public static let remoteChannelIdentifier: SSHChildChannelOptions.Types.RemoteChannelIdentifierOption = .init()
    public static let sshChannelType: SSHChildChannelOptions.Types.SSHChannelTypeOption = .init()
    public static let peerMaximumMessageLength: SSHChildChannelOptions.Types.PeerMaximumMessageLengthOption = .init()
}

extension SSHChildChannelOptions {
    public enum Types: Sendable {}
}

extension SSHChildChannelOptions.Types {
    public struct LocalChannelIdentifierOption: ChannelOption, Sendable  { public typealias Value = UInt32;  public init() {} }
    public struct RemoteChannelIdentifierOption: ChannelOption, Sendable { public typealias Value = UInt32?; public init() {} }
    public struct SSHChannelTypeOption: ChannelOption, Sendable          { public typealias Value = SSHChannelType; public init() {} }
    public struct PeerMaximumMessageLengthOption: ChannelOption, Sendable { public typealias Value = UInt32; public init() {} }
}
```

> **Trap:** `SSHChildChannel.setOption0` supports **only** `AutoReadOption` and
> `AllowRemoteHalfClosureOption`; every other option hits
> `fatalError("setting option \(option) on SSHChildChannel not supported")`. `getOption0`
> supports the four `SSHChildChannelOptions` above plus autoRead/allowRemoteHalfClosure, and
> `fatalError`s otherwise. Do not probe options speculatively on a child channel.

---

## e. `directTCPIP` — local port forwarding

### `SSHChannelType.DirectTCPIP` (verbatim)

```swift
extension SSHChannelType {
    /// ``SSHChannelType/DirectTCPIP`` is a request from the client to the server to open an outbound connection.
    public struct DirectTCPIP: Equatable, Sendable {
        /// The target host for the forwarded TCP connection.
        public var targetHost: String

        /// The target port for the forwarded TCP connection.
        public var targetPort: Int { get set }        // stored internally as UInt16

        /// The address of the initiating peer.
        public var originatorAddress: SocketAddress

        public init(targetHost: String, targetPort: Int, originatorAddress: SocketAddress)
    }
}
```

Constructed as: `SSHChannelType.directTCPIP(SSHChannelType.DirectTCPIP(targetHost:targetPort:originatorAddress:))`.

> **Trap:** `targetPort`'s setter and the public `init` do `UInt16(targetPort)` — an
> **unchecked narrowing conversion that traps** on a value outside `0...65535`. Validate the port
> before constructing.

### `SSHChannelType.ForwardedTCPIP` (verbatim) — for remote forwarding (server→client)

```swift
extension SSHChannelType {
    public struct ForwardedTCPIP: Equatable, Sendable {
        /// The host the remote peer connected to. This should be identical to the one that was requested.
        public var listeningHost: String
        /// The port on which the proxy is listening, and to which the remote peer connected.
        public var listeningPort: Int { get set }     // stored internally as UInt16
        /// The address of the remote peer.
        public var originatorAddress: SocketAddress

        public init(listeningHost: String, listeningPort: Int, originatorAddress: SocketAddress)
    }
}
```

Forwarded channels arrive through the `inboundChildChannelInitializer` you passed to
`NIOSSHHandler.init`, with `channelType == .forwardedTCPIP(...)`.

### Remote forwarding global requests (verbatim — `GlobalRequestDelegate.swift`)

```swift
public protocol GlobalRequestDelegate {
    /// The client wants to manage TCP port forwarding.
    /// The eventLoop associated with the promise passed in must be the same as the one used to create the handler.
    /// The default implementation rejects all requests to establish TCP port forwarding.
    func tcpForwardingRequest(
        _: GlobalRequest.TCPForwardingRequest,
        handler: NIOSSHHandler,
        promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>
    )
}

extension GlobalRequestDelegate {
    public func tcpForwardingRequest(
        _ request: GlobalRequest.TCPForwardingRequest,
        handler: NIOSSHHandler,
        promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>
    ) {
        // The default implementation rejects all requests.
        promise.fail(NIOSSHError.unsupportedGlobalRequest)
    }
}

public enum GlobalRequest: Sendable {
    public enum TCPForwardingRequest: Equatable, Sendable {
        case listen(host: String, port: Int)
        case cancel(host: String, port: Int)
    }

    public struct TCPForwardingResponse: Hashable, Sendable {
        /// If requested to listen on a port, and the port the client requested was 0, this is set to the
        /// port that was actually bound. Otherwise is nil.
        public var boundPort: Int?
        public init(boundPort: Int?)
    }
}
```

```swift
extension NIOSSHHandler {
    /// Send a TCP forwarding request, either to initiate or cancel remote TCP forwarding.
    /// This function is **not** thread-safe: it may only be called from on the channel.
    public func sendTCPForwardingRequest(
        _ request: GlobalRequest.TCPForwardingRequest,
        promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse?>? = nil
    )
}
```

> The README calls this `NIOSSHHandler.sendGlobalRequest` — **that name does not exist.**
> The public method is `sendTCPForwardingRequest(_:promise:)`. (`sendGlobalRequestMessage(_:promise:)`
> exists but is `internal`.) Use the confirmed name.

---

## f. PTY + shell (interactive terminal) and resize

### `PseudoTerminalRequest` — exact field names (verbatim)

```swift
public struct PseudoTerminalRequest: Hashable, Sendable {
    /// Whether a reply to this PTY request is desired.
    public var wantReply: Bool

    /// The value of the TERM environment variable, e.g. "vt100"
    public var term: String

    /// The desired width of the terminal in characters. This overrides
    /// the pixel width when this value is non-zero.
    public var terminalCharacterWidth: Int { get }      // GET-ONLY

    /// The desired height of the terminal in rows. ...
    public var terminalRowHeight: Int { get }           // GET-ONLY

    /// The desired width of the terminal in pixels. ...
    public var terminalPixelWidth: Int { get }          // GET-ONLY

    /// The desired height of the terminal in pixels. ...
    public var terminalPixelHeight: Int { get }         // GET-ONLY

    /// The posix terminal modes.
    public var terminalModes: SSHTerminalModes

    public init(
        wantReply: Bool,
        term: String,
        terminalCharacterWidth: Int,
        terminalRowHeight: Int,
        terminalPixelWidth: Int,
        terminalPixelHeight: Int,
        terminalModes: SSHTerminalModes
    )
}
```

> The four dimension properties are **computed and get-only** (backing storage is `fileprivate`
> `UInt32`). To change a size you construct a **new** value, or send a `WindowChangeRequest`.
> `wantReply` and `terminalModes` are settable. The public `init` does `UInt32(...)` on each
> dimension — **negative values trap**.

### `ShellRequest` (verbatim)

```swift
/// A request for this session to invoke a shell.
public struct ShellRequest: Hashable, Sendable {
    /// Whether this request should be replied to.
    public var wantReply: Bool

    public init(wantReply: Bool)
}
```

### `WindowChangeRequest` (verbatim)

```swift
/// A notification that the user has changed the size of the window.
/// Only useful if a pseudo-terminal has been allocated.
public struct WindowChangeRequest: Hashable, Sendable {
    /// Whether a reply to this window change request is desired.
    public var wantReply: Bool { false }        // read-only, always false

    public var terminalCharacterWidth: Int { get }   // GET-ONLY
    public var terminalRowHeight: Int { get }        // GET-ONLY
    public var terminalPixelWidth: Int { get }       // GET-ONLY
    public var terminalPixelHeight: Int { get }      // GET-ONLY

    public init(
        terminalCharacterWidth: Int,
        terminalRowHeight: Int,
        terminalPixelWidth: Int,
        terminalPixelHeight: Int
    )
}
```

Note there is **no `wantReply:` parameter** on `WindowChangeRequest.init` — it is always `false`.

### `SSHTerminalModes` (verbatim — `Sources/NIOSSH/SSHTerminalModes.swift`)

```swift
public struct SSHTerminalModes {
    /// The set ``Opcode``s and their ``OpcodeValue``s.
    public var modeMapping: [Opcode: OpcodeValue]

    public init(_ modeMapping: [Opcode: OpcodeValue])
}

extension SSHTerminalModes: Hashable {}
extension SSHTerminalModes: Sendable {}

extension SSHTerminalModes {
    public struct Opcode {
        public var rawValue: UInt8 { get }
        public init(rawValue: UInt8)

        public static let VINTR    = Opcode(rawValue: 1)
        public static let VQUIT    = Opcode(rawValue: 2)
        public static let VERASE   = Opcode(rawValue: 3)
        public static let VKILL    = Opcode(rawValue: 4)
        public static let VEOF     = Opcode(rawValue: 5)
        public static let VEOL     = Opcode(rawValue: 6)
        public static let VEOL2    = Opcode(rawValue: 7)
        public static let VSTART   = Opcode(rawValue: 8)
        public static let VSTOP    = Opcode(rawValue: 9)
        public static let VSUSP    = Opcode(rawValue: 10)
        public static let VDSUSP   = Opcode(rawValue: 11)
        public static let VREPRINT = Opcode(rawValue: 12)
        public static let VWERASE  = Opcode(rawValue: 13)
        public static let VLNEXT   = Opcode(rawValue: 14)
        public static let VFLUSH   = Opcode(rawValue: 15)
        public static let VSWTCH   = Opcode(rawValue: 16)
        public static let VSTATUS  = Opcode(rawValue: 17)
        public static let VDISCARD = Opcode(rawValue: 18)
        public static let IGNPAR   = Opcode(rawValue: 30)
        public static let PARMRK   = Opcode(rawValue: 31)
        public static let INPCK    = Opcode(rawValue: 32)
        public static let ISTRIP   = Opcode(rawValue: 33)
        public static let INLCR    = Opcode(rawValue: 34)
        public static let IGNCR    = Opcode(rawValue: 35)
        public static let ICRNL    = Opcode(rawValue: 36)
        public static let IUCLC    = Opcode(rawValue: 37)
        public static let IXON     = Opcode(rawValue: 38)
        public static let IXANY    = Opcode(rawValue: 39)
        public static let IXOFF    = Opcode(rawValue: 40)
        public static let IMAXBEL  = Opcode(rawValue: 41)
        public static let ISIG     = Opcode(rawValue: 50)
        public static let ICANON   = Opcode(rawValue: 51)
        public static let XCASE    = Opcode(rawValue: 52)
        public static let ECHO     = Opcode(rawValue: 53)
        public static let ECHOE    = Opcode(rawValue: 54)
        public static let ECHOK    = Opcode(rawValue: 55)
        public static let ECHONL   = Opcode(rawValue: 56)
        public static let NOFLSH   = Opcode(rawValue: 57)
        public static let TOSTOP   = Opcode(rawValue: 58)
        public static let IEXTEN   = Opcode(rawValue: 59)
        public static let ECHOCTL  = Opcode(rawValue: 60)
        public static let ECHOKE   = Opcode(rawValue: 61)
        public static let PENDIN   = Opcode(rawValue: 62)
        public static let OPOST    = Opcode(rawValue: 70)
        public static let OLCUC    = Opcode(rawValue: 71)
        public static let ONLCR    = Opcode(rawValue: 72)
        public static let OCRNL    = Opcode(rawValue: 73)
        public static let ONOCR    = Opcode(rawValue: 74)
        public static let ONLRET   = Opcode(rawValue: 75)
        public static let CS7      = Opcode(rawValue: 90)
        public static let CS8      = Opcode(rawValue: 91)
        public static let PARENB   = Opcode(rawValue: 92)
        public static let PARODD   = Opcode(rawValue: 93)
        public static let TTY_OP_ISPEED = Opcode(rawValue: 128)
        public static let TTY_OP_OSPEED = Opcode(rawValue: 129)
    }

    public struct OpcodeValue {
        public var rawValue: UInt32
        public init(rawValue: UInt32)
    }
}

extension SSHTerminalModes.Opcode: ExpressibleByIntegerLiteral { public init(integerLiteral value: UInt8) }
extension SSHTerminalModes.OpcodeValue: ExpressibleByIntegerLiteral { public init(integerLiteral value: UInt32) }
// both are Hashable, Sendable, Comparable, CustomStringConvertible/RawRepresentable
```

Both `Opcode` and `OpcodeValue` are `ExpressibleByIntegerLiteral`, so the repo's own test writes:

```swift
terminalModes: .init([.ECHO: 5])
```

### Verbatim interactive-shell request sequence (from `Tests/NIOSSHTests/EndToEndTests.swift`)

```swift
SSHChannelRequestEvent.PseudoTerminalRequest(
    wantReply: true,
    term: "vt100",
    terminalCharacterWidth: 80,
    terminalRowHeight: 24,
    terminalPixelWidth: 0,
    terminalPixelHeight: 0,
    terminalModes: .init([.ECHO: 5])
)
SSHChannelRequestEvent.ShellRequest(wantReply: true)
SSHChannelRequestEvent.WindowChangeRequest(
    terminalCharacterWidth: 0,
    terminalRowHeight: 0,
    terminalPixelWidth: 720,
    terminalPixelHeight: 480
)
```

---

## g. Exit status

```swift
public struct ExitStatus: Hashable, Sendable {
    public var wantReply: Bool { false }
    public var exitStatus: Int { get set }
    public init(exitStatus: Int)
}
```

Delivered as an **inbound user event** on the session child channel. Verbatim handling from
`Sources/NIOSSHClient/ExecHandler.swift`:

```swift
func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
    switch event {
    case let event as SSHChannelRequestEvent.ExitStatus:
        if let promise = self.completePromise {
            self.completePromise = nil
            promise.succeed(event.exitStatus)
        }

    default:
        context.fireUserInboundEventTriggered(event)
    }
}
```

`ExitStatus.init(exitStatus:)` does `UInt32(exitStatus)` internally — **negative values trap**.
Pair it with `ExitSignal` (§d) since a signal-terminated command sends `ExitSignal`, not `ExitStatus`.

---

## Errors

```swift
public struct NIOSSHError: Error {
    /// The type of this error, used to identify the kind of error that has been thrown.
    public var type: ErrorType
    // private var diagnostics: String?
}

extension NIOSSHError: CustomStringConvertible {
    public var description: String
}

extension NIOSSHError {
    public struct ErrorType {
        public static let invalidSSHMessage: ErrorType
        public static let weakSharedSecret: ErrorType
        public static let invalidNonceLength: ErrorType
        public static let invalidEncryptedPacketLength: ErrorType
        public static let invalidDecryptedPlaintextLength: ErrorType
        public static let invalidKeySize: ErrorType
        public static let insufficientPadding: ErrorType
        public static let excessPadding: ErrorType
        public static let unknownPublicKey: ErrorType
        public static let unknownSignature: ErrorType
        public static let invalidDomainParametersForKey: ErrorType
        public static let invalidExchangeHashSignature: ErrorType
        public static let invalidPacketFormat: ErrorType
        public static let protocolViolation: ErrorType
        public static let keyExchangeNegotiationFailure: ErrorType
        public static let unsupportedVersion: ErrorType
        public static let channelSetupRejected: ErrorType
        public static let flowControlViolation: ErrorType
        public static let creatingChannelAfterClosure: ErrorType
        public static let tcpShutdown: ErrorType
        public static let invalidUserAuthSignature: ErrorType
        public static let unknownPacketType: ErrorType
        public static let unsupportedGlobalRequest: ErrorType
        public static let unexpectedGlobalRequestResponse: ErrorType
        public static let missingGlobalRequestResponse: ErrorType
        public static let globalRequestRefused: ErrorType
        public static let remotePeerDoesNotSupportMessage: ErrorType
        public static let invalidHostKeyForKeyExchange: ErrorType
        public static let invalidOpenSSHPublicKey: ErrorType
        public static let invalidCertificate: ErrorType
    }
}

extension NIOSSHError.ErrorType: Hashable {}
extension NIOSSHError.ErrorType: Sendable {}
extension NIOSSHError.ErrorType: CustomStringConvertible { public var description: String }
```

> **`NIOSSHError` is NOT `Equatable` and NOT `Sendable`.** Its doc comment says so explicitly:
> compare `error.type`, never the error. The diagnostic string is `private` and reachable only
> through `description` — which is exactly what you want to put behind a "View technical details"
> disclosure, with a human message in front of it.
>
> Auth failure surfaces as the **failure of the promise you failed** (or, if you returned `nil`,
> as the connection failing to activate); there is no dedicated `authenticationFailed` error type.

---

## Concurrency notes: `Sendable` and Swift 6 strict concurrency

### Non-`Sendable` types (explicitly marked `@available(*, unavailable) extension X: Sendable {}`)

| Type | Consequence |
|---|---|
| `NIOSSHHandler` | cannot cross isolation boundaries; `EventLoopFuture<NIOSSHHandler>.get()` / `.wait()` **will not compile** (both require `Value: Sendable`) |
| `SSHClientConfiguration` | build it inside the `channelInitializer` closure, not outside and captured |
| `SSHConnectionRole` | same |
| `SimplePasswordDelegate` | same |

The two delegate protocols (`NIOSSHClientUserAuthenticationDelegate`,
`NIOSSHClientServerAuthenticationDelegate`, `GlobalRequestDelegate`) **do not require `Sendable`** —
that is precisely why `SSHClientConfiguration` cannot be `Sendable`. If you want to construct the
config outside the initializer you must make your own delegates `Sendable` **and** still rebuild
the config inside the closure (the config type itself is unavailable-Sendable regardless).

`@preconcurrency import Crypto` appears in both `NIOSSHPrivateKey.swift` and
`NIOSSHPublicKey.swift` — swift-nio-ssh itself suppresses Crypto's concurrency diagnostics.

### The `pipeline.handler(type: NIOSSHHandler.self)` trap

```swift
// ❌ Does NOT compile under Swift 6 / strict concurrency:
//    EventLoopFuture.get() is `where Value: Sendable`, and NIOSSHHandler is explicitly not Sendable.
let handler = try await channel.pipeline.handler(type: NIOSSHHandler.self).get()

// ✅ Do this instead: touch the handler only on its event loop, and return something Sendable.
let child: Channel = try await channel.eventLoop.flatSubmit { () -> EventLoopFuture<Channel> in
    do {
        let ssh = try channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
        let promise = channel.eventLoop.makePromise(of: Channel.self)
        ssh.createChannel(promise, channelType: .session) { childChannel, _ in /* ... */ }
        return promise.futureResult
    } catch {
        return channel.eventLoop.makeFailedFuture(error)
    }
}.get()
```

`Channel` **is** `Sendable` (`public protocol Channel: AnyObject, ChannelOutboundInvoker, _NIOPreconcurrencySendable`,
and `@preconcurrency public protocol _NIOPreconcurrencySendable: Sendable {}`), so
`EventLoopFuture<Channel>.get()` is fine. `EventLoopPromise: Sendable` unconditionally;
`EventLoopFuture: @unchecked Sendable`.

### Bridging NIO futures to async/await

```swift
// Sources/NIOCore/AsyncAwaitSupport.swift  — verbatim
extension EventLoopFuture {
    /// Get the value/error from an `EventLoopFuture` in an `async` context.
    ///
    /// - warning: This method currently violates Structured Concurrency because cancellation isn't respected.
    @available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
    @preconcurrency
    @inlinable
    public func get() async throws -> Value where Value: Sendable
}

extension EventLoopPromise {
    /// Complete a future with the result (or error) of the `async` function `body`.
    @available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
    @discardableResult @preconcurrency @inlinable
    public func completeWithTask(
        _ body: @escaping @Sendable () async throws -> Value
    ) -> Task<Void, Never> where Value: Sendable
}

extension EventLoopGroup {
    @available(macOS 10.15, iOS 13, tvOS 13, watchOS 6, *)
    @inlinable
    public func shutdownGracefully() async throws
}
```

- `.get()` **does not honour Swift task cancellation** (documented warning above). For a
  responsive UI you must additionally close the `Channel` yourself on cancellation.
- `.wait()` is `where Value: Sendable` too, and must never be called on an event loop thread.
- `completeWithTask` is the reverse bridge — ideal for an `async` user-auth delegate that
  fetches a password from the Keychain:
  `nextChallengePromise.completeWithTask { try await self.makeOffer(availableMethods) }`.

### Isolation helpers used by the library's own samples

```swift
// Sources/NIOCore/EventLoopFuture+AssumeIsolated.swift
public func assumeIsolated() -> NIOIsolatedEventLoop   // on EventLoop
public func assumeIsolated() -> Isolated               // on EventLoopFuture / EventLoopPromise
// Sources/NIOCore/NIOLoopBound.swift
public struct NIOLoopBound<Value>: @unchecked Sendable {
    public init(_ value: Value, eventLoop: EventLoop)
}
public final class NIOLoopBoundBox<Value>: @unchecked Sendable
```

Use `NIOLoopBound` to carry a non-`Sendable` handler/context into a `@Sendable` closure that you
know runs on the same loop — verbatim from `Sources/NIOSSHClient/ExecHandler.swift`:

```swift
let loopBoundGlueHandler = NIOLoopBound(theirs, eventLoop: context.eventLoop)
let loopBoundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
```

Internally `NIOSSHHandler` uses `assumeIsolatedUnsafeUnchecked()` for its own future callbacks —
that spelling is internal-flavoured; prefer `assumeIsolated()` in your code.

---

## Complete minimal-but-real example client: connect → password auth → `exec "uname -a"` → collect output

Built exclusively from the declarations above.

```swift
import NIOCore
import NIOPosix
import NIOSSH

// MARK: - Result & errors

struct CommandResult: Sendable {
    var exitStatus: Int
    var stdout: String
    var stderr: String
}

enum SSHClientError: Error {
    case invalidChannelType
    case invalidData
    case passwordAuthenticationNotSupported
    case hostKeyMismatch(presented: String)
    case commandDidNotComplete
}

// MARK: - Host key verification (pinning by exact key equality)

/// `NIOSSHPublicKey` is Hashable, so exact comparison is the supported pinning primitive.
/// There is no `fingerprint` and no public `rawRepresentation` in swift-nio-ssh 0.15.0.
final class PinnedHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate, Sendable {
    /// An OpenSSH public key line, e.g. "ssh-ed25519 AAAAC3Nza..." (a trailing comment is allowed).
    private let expectedOpenSSHPublicKey: String

    init(expectedOpenSSHPublicKey: String) {
        self.expectedOpenSSHPublicKey = expectedOpenSSHPublicKey
    }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        do {
            let expected = try NIOSSHPublicKey(openSSHPublicKey: self.expectedOpenSSHPublicKey)
            if expected == hostKey {
                validationCompletePromise.succeed(())
            } else {
                // Canonical "<algorithm-id> <base64>" form; safe to show to the user and to persist.
                let presented = String(openSSHPublicKey: hostKey)
                validationCompletePromise.fail(SSHClientError.hostKeyMismatch(presented: presented))
            }
        } catch {
            validationCompletePromise.fail(error)
        }
    }
}

/// Trust-on-first-use: hand the key out for storage, then accept.
/// Use this ONLY for the first connection, and persist `String(openSSHPublicKey:)`.
final class TOFUHostKeyDelegate: NIOSSHClientServerAuthenticationDelegate, Sendable {
    private let store: @Sendable (String) -> Void

    init(store: @escaping @Sendable (String) -> Void) { self.store = store }

    func validateHostKey(hostKey: NIOSSHPublicKey, validationCompletePromise: EventLoopPromise<Void>) {
        self.store(String(openSSHPublicKey: hostKey))
        validationCompletePromise.succeed(())
    }
}

// MARK: - Password user auth

/// Offers the password exactly once, then reports "nothing left to try".
final class PasswordAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    private var offer: NIOSSHUserAuthenticationOffer?

    init(username: String, password: String) {
        self.offer = NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",                       // ignored by the library; must still be passed
            offer: .password(.init(password: password))
        )
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.password) else {
            nextChallengePromise.fail(SSHClientError.passwordAuthenticationNotSupported)
            return
        }
        guard let offer = self.offer else {
            nextChallengePromise.succeed(nil)      // out of options -> clean auth failure
            return
        }
        self.offer = nil                           // MUST clear, or we loop forever
        nextChallengePromise.succeed(offer)
    }
}

/// Private-key variant, for reference. Build the Crypto key first; NIOSSHPrivateKey has no PEM init.
final class PrivateKeyAuthDelegate: NIOSSHClientUserAuthenticationDelegate {
    private var offer: NIOSSHUserAuthenticationOffer?

    init(username: String, privateKey: NIOSSHPrivateKey) {
        self.offer = NIOSSHUserAuthenticationOffer(
            username: username,
            serviceName: "",
            offer: .privateKey(.init(privateKey: privateKey))
        )
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        guard availableMethods.contains(.publicKey), let offer = self.offer else {
            nextChallengePromise.succeed(nil)
            return
        }
        self.offer = nil
        nextChallengePromise.succeed(offer)
    }
}

// MARK: - Exec handler: sends the command, accumulates stdout/stderr, reports exit status

final class CollectingExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private let command: String
    private var completePromise: EventLoopPromise<CommandResult>?
    private var stdout = ByteBuffer()
    private var stderr = ByteBuffer()
    private var exitStatus: Int?

    init(command: String, completePromise: EventLoopPromise<CommandResult>) {
        self.command = command
        self.completePromise = completePromise
    }

    func handlerAdded(context: ChannelHandlerContext) {
        // MANDATORY: SSH child channels rely on half-closure.
        let setOption = context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
        setOption.assumeIsolated().whenFailure { error in
            context.fireErrorCaught(error)
        }
    }

    func channelActive(context: ChannelHandlerContext) {
        let execRequest = SSHChannelRequestEvent.ExecRequest(command: self.command, wantReply: true)
        context.triggerUserOutboundEvent(execRequest).assumeIsolated().whenFailure { _ in
            context.close(promise: nil)
        }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = self.unwrapInboundIn(data)

        guard case .byteBuffer(var bytes) = channelData.data else {
            context.fireErrorCaught(SSHClientError.invalidData)   // never a fileRegion inbound
            return
        }

        switch channelData.type {
        case .channel:
            self.stdout.writeBuffer(&bytes)
        case .stdErr:
            self.stderr.writeBuffer(&bytes)
        default:
            break                                                  // unknown extended data: ignore
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.ExitStatus:
            self.exitStatus = event.exitStatus

        case let event as SSHChannelRequestEvent.ExitSignal:
            // Match shell convention: 128 + signal. Name has no "SIG" prefix.
            self.exitStatus = self.exitStatus ?? 128
            var buffer = context.channel.allocator.buffer(capacity: event.errorMessage.utf8.count)
            buffer.writeString(event.errorMessage)
            self.stderr.writeBuffer(&buffer)

        case ChannelEvent.inputClosed:
            // Peer sent EOF; we have nothing more to send either.
            context.close(mode: .output, promise: nil)

        case is ChannelSuccessEvent:
            break                                                  // exec accepted
        case is ChannelFailureEvent:
            self.fail(SSHClientError.commandDidNotComplete)

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    /// Writing plain ByteBuffers (stdin) through this handler wraps them for the SSH channel.
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))),
                      promise: promise)
    }

    func channelInactive(context: ChannelHandlerContext) {
        self.finish()
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.finish()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        self.fail(error)
        context.close(promise: nil)
    }

    private func finish() {
        guard let promise = self.completePromise else { return }
        self.completePromise = nil
        promise.succeed(
            CommandResult(
                exitStatus: self.exitStatus ?? -1,
                stdout: self.stdout.getString(at: self.stdout.readerIndex, length: self.stdout.readableBytes) ?? "",
                stderr: self.stderr.getString(at: self.stderr.readerIndex, length: self.stderr.readableBytes) ?? ""
            )
        )
    }

    private func fail(_ error: Error) {
        guard let promise = self.completePromise else { return }
        self.completePromise = nil
        promise.fail(error)
    }
}

// MARK: - Driving it

func runUnameDashA(
    host: String,
    port: Int = 22,
    username: String,
    password: String,
    pinnedHostKey: String,
    group: EventLoopGroup
) async throws -> CommandResult {

    // 1. TCP connect + SSH transport handshake + user auth.
    //    Build the (non-Sendable) config INSIDE the initializer closure.
    //    (ClientBootstrap already sets .tcpOption(.tcp_nodelay) = 1 in its own init.)
    let channel = try await ClientBootstrap(group: group)
        .channelOption(.tcpOption(.tcp_nodelay), value: 1)
        .connectTimeout(.seconds(10))
        .channelInitializer { channel in
            channel.eventLoop.makeCompletedFuture {
                let sshHandler = NIOSSHHandler(
                    role: .client(
                        SSHClientConfiguration(
                            userAuthDelegate: PasswordAuthDelegate(username: username, password: password),
                            serverAuthDelegate: PinnedHostKeyDelegate(expectedOpenSSHPublicKey: pinnedHostKey)
                        )
                    ),
                    allocator: channel.allocator,
                    inboundChildChannelInitializer: nil   // we never accept inbound SSH channels here
                )
                try channel.pipeline.syncOperations.addHandler(sshHandler)
            }
        }
        .connect(host: host, port: port)
        .get()

    // 2. Open a `session` child channel and run the command.
    //    NIOSSHHandler is NOT Sendable, so only touch it on the event loop.
    let resultPromise = channel.eventLoop.makePromise(of: CommandResult.self)

    let childChannel: Channel = try await channel.eventLoop.flatSubmit { () -> EventLoopFuture<Channel> in
        do {
            let sshHandler = try channel.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
            let promise = channel.eventLoop.makePromise(of: Channel.self)

            sshHandler.createChannel(promise, channelType: .session) { childChannel, channelType in
                guard channelType == .session else {
                    return childChannel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                }
                return childChannel.eventLoop.makeCompletedFuture {
                    try childChannel.pipeline.syncOperations.addHandler(
                        CollectingExecHandler(command: "uname -a", completePromise: resultPromise)
                    )
                }
            }

            return promise.futureResult
        } catch {
            return channel.eventLoop.makeFailedFuture(error)
        }
    }.get()

    // 3. Wait for the command, then tear down.
    let result = try await resultPromise.futureResult.get()
    try? await childChannel.closeFuture.get()
    try await channel.close().get()
    return result
}

// Usage:
// let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
// defer { try? group.syncShutdownGracefully() }
// let out = try await runUnameDashA(
//     host: "203.0.113.10", username: "root", password: "…",
//     pinnedHostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA…", group: group
// )
```

### PTY + shell variant (same connect flow, different child-channel setup)

```swift
final class InteractiveShellHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private let term: String
    private let columns: Int
    private let rows: Int

    init(term: String = "xterm-256color", columns: Int = 80, rows: Int = 24) {
        self.term = term
        self.columns = columns
        self.rows = rows
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .assumeIsolated().whenFailure { context.fireErrorCaught($0) }
    }

    func channelActive(context: ChannelHandlerContext) {
        let pty = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true,
            term: self.term,
            terminalCharacterWidth: self.columns,
            terminalRowHeight: self.rows,
            terminalPixelWidth: 0,
            terminalPixelHeight: 0,
            terminalModes: SSHTerminalModes([.ECHO: 1, .ICANON: 1, .ISIG: 1, .OPOST: 1, .ONLCR: 1])
        )
        context.triggerUserOutboundEvent(pty).assumeIsolated().whenFailure { _ in
            context.close(promise: nil)
        }
        let shell = SSHChannelRequestEvent.ShellRequest(wantReply: true)
        context.triggerUserOutboundEvent(shell).assumeIsolated().whenFailure { _ in
            context.close(promise: nil)
        }
        context.fireChannelActive()
    }

    /// Call from the UI when the terminal view resizes (must hop to the child channel's loop).
    static func resize(channel: Channel, columns: Int, rows: Int) -> EventLoopFuture<Void> {
        let event = SSHChannelRequestEvent.WindowChangeRequest(
            terminalCharacterWidth: columns,
            terminalRowHeight: rows,
            terminalPixelWidth: 0,
            terminalPixelHeight: 0
        )
        return channel.triggerUserOutboundEvent(event)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = self.unwrapInboundIn(data)
        guard case .byteBuffer(let bytes) = channelData.data else { return }
        // .channel == stdout, .stdErr == stderr; forward both to the terminal emulator.
        context.fireChannelRead(self.wrapInboundOut(bytes))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = self.unwrapOutboundIn(data)
        context.write(self.wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))),
                      promise: promise)
    }
}
```

---

## Example: opening a `directTCPIP` local-port-forwarding channel

Adapted directly from `Sources/NIOSSHClient/main.swift` (which is the upstream reference
implementation of `ssh -L`): bind a local `ServerBootstrap`, and for each accepted local
connection open a `directTCPIP` SSH child channel and glue the two channels together.

```swift
import NIOCore
import NIOPosix
import NIOSSH

/// Opens one SSH `directTCPIP` child channel for a locally-accepted connection.
/// `sshConnection` is the parent SSH Channel returned by `ClientBootstrap.connect`.
func openForwardingChannel(
    sshConnection: Channel,
    localChannel: Channel,
    targetHost: String,
    targetPort: Int
) -> EventLoopFuture<Channel> {
    precondition((0...65535).contains(targetPort))   // DirectTCPIP.init traps outside UInt16

    guard let originator = localChannel.remoteAddress else {
        return localChannel.eventLoop.makeFailedFuture(SSHClientError.invalidData)
    }

    let directTCPIP = SSHChannelType.DirectTCPIP(
        targetHost: targetHost,
        targetPort: targetPort,
        originatorAddress: originator
    )

    return sshConnection.eventLoop.flatSubmit { () -> EventLoopFuture<Channel> in
        do {
            let sshHandler = try sshConnection.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
            let promise = sshConnection.eventLoop.makePromise(of: Channel.self)

            sshHandler.createChannel(promise, channelType: .directTCPIP(directTCPIP)) { childChannel, channelType in
                guard case .directTCPIP = channelType else {
                    return childChannel.eventLoop.makeFailedFuture(SSHClientError.invalidChannelType)
                }
                return childChannel.eventLoop.makeCompletedFuture {
                    // Child channel speaks SSHChannelData; wrap/unwrap to plain ByteBuffer,
                    // then glue it to the local TCP channel.
                    let (ours, theirs) = GlueHandler.matchedPair()
                    let childSync = childChannel.pipeline.syncOperations
                    try childSync.addHandler(SSHWrapperHandler())
                    try childSync.addHandler(ours)

                    let localSync = localChannel.pipeline.syncOperations
                    try localSync.addHandler(theirs)
                }
            }
            return promise.futureResult
        } catch {
            return sshConnection.eventLoop.makeFailedFuture(error)
        }
    }
}

/// Bind the local listening socket (the `-L <bindPort>:<targetHost>:<targetPort>` side).
func startLocalForward(
    group: EventLoopGroup,
    sshConnection: Channel,
    bindHost: String,
    bindPort: Int,
    targetHost: String,
    targetPort: Int
) -> EventLoopFuture<Channel> {
    ServerBootstrap(group: group)
        .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
        .childChannelInitializer { localChannel in
            openForwardingChannel(
                sshConnection: sshConnection,
                localChannel: localChannel,
                targetHost: targetHost,
                targetPort: targetPort
            ).map { _ in }                       // erase: we only need success/failure
        }
        .bind(host: bindHost, port: bindPort)
}
```

`GlueHandler` is a ~100-line bidirectional pipe handler that swift-nio-ssh ships **only in its
sample executables** (`Sources/NIOSSHClient/GlueHandler.swift`) — it is **not** part of the
`NIOSSH` library product. You must copy it into your own target (Apache-2.0) or write an
equivalent. `SSHWrapperHandler` is quoted verbatim in §d above and is likewise sample code,
not library API.

---

## Quick index of every public symbol in `NIOSSH` 0.15.0

Handler / configuration: `NIOSSHHandler`, `SSHConnectionRole`, `SSHClientConfiguration`,
`SSHServerConfiguration` (+ `.UserAuthBanner`), `Constants`, `NIOSSHTransportProtection`,
`NIOSSHEncryptablePayload`, `NIOSSHSessionKeys`, `ExpectedKeySizes`, `_NIOSSHSendableMetatype`.

Channels: `SSHChannelType` (+ `.DirectTCPIP`, `.ForwardedTCPIP`), `SSHChannelData` (+ `.DataType`),
`SSHChildChannelOptions` (+ `.Types.*`), `SSHChannelRequestEvent` (+ `PseudoTerminalRequest`,
`EnvironmentRequest`, `ShellRequest`, `ExecRequest`, `ExitStatus`, `ExitSignal`,
`SubsystemRequest`, `WindowChangeRequest`, `LocalFlowControlRequest`, `SignalRequest`),
`ChannelSuccessEvent`, `ChannelFailureEvent`, `SSHTerminalModes` (+ `Opcode`, `OpcodeValue`).

Auth: `NIOSSHClientUserAuthenticationDelegate`, `NIOSSHServerUserAuthenticationDelegate`,
`NIOSSHClientServerAuthenticationDelegate`, `NIOSSHAvailableUserAuthenticationMethods`,
`NIOSSHUserAuthenticationOffer` (+ `.Offer`), `NIOSSHUserAuthenticationRequest` (+ `.Request`),
`NIOSSHUserAuthenticationOutcome`, `SimplePasswordDelegate`, `DenyAllServerAuthDelegate`,
`NIOUserAuthBannerEvent`, `UserAuthSuccessEvent`.

Keys: `NIOSSHPrivateKey`, `NIOSSHPublicKey`, `NIOSSHCertifiedPublicKey` (+ `.CertificateType`),
`NIOSSHSignature`, `String.init(openSSHPublicKey:)`.

Global requests: `GlobalRequestDelegate`, `GlobalRequest` (+ `.TCPForwardingRequest`,
`.TCPForwardingResponse`).

Errors: `NIOSSHError` (+ `.ErrorType`).

## Things that DO NOT exist (checked, so nobody writes them)

- `UserAuthSignableRequest` — no such type. (`UserAuthSignablePayload` is `internal`.)
- `NIOSSHPublicKey.fingerprint` — no such member (zero matches for "fingerprint" repo-wide).
- `NIOSSHPublicKey.rawRepresentation` / `.keyPrefix` — not public.
- `NIOSSHPrivateKey.init(pem:)` / `init(openSSHPrivateKey:)` / `.sign(...)` public — none exist.
- Any RSA (`ssh-rsa`, `rsa-sha2-256/512`) support — zero matches repo-wide.
- `SSHChannelDataUnwrappingHandler` — no such handler; write the ~20-line codec (§d).
- `NIOSSHHandler.sendGlobalRequest` — README-only name; the real one is `sendTCPForwardingRequest`.
- Keyboard-interactive auth — unmapped/ignored method string.
- An OpenSSH private-key (`-----BEGIN OPENSSH PRIVATE KEY-----`) parser, in either package.
- `NIOSSHError: Equatable` / `: Sendable` — neither.
- An `async`/`NIOAsyncChannel`-native SSH surface — 0.15.0 is futures-only; bridge with `.get()`.
