//  SSHClient.swift
//  ServerOS
//
//  One SSH connection to one server, and the three things ServerOS does with
//  it: run a command, forward a port, open a shell.
//
//  ──────────────────────────────────────────────────────────────────────────
//  WHAT THIS IS FOR
//
//  SSH is not the product. The product talks to the ServerOS agent over HTTP,
//  and this layer exists to (a) put the agent there in the first place and
//  (b) carry that HTTP through a tunnel so the agent never needs to listen on
//  a routable address. Running shell commands is confined to setup and to the
//  emergency terminal; everything the app does day to day is a typed request
//  to the agent, not a parsed `ps` output.
//  ──────────────────────────────────────────────────────────────────────────
//
//  Written against swift-nio-ssh 0.15.0, which is futures-only and pointedly
//  non-Sendable in places. Three rules follow from that and are obeyed
//  throughout:
//
//   1. `NIOSSHHandler` is not `Sendable`, so it is only ever touched inside
//      `eventLoop.flatSubmit { … syncOperations … }`, never via
//      `pipeline.handler(type:).get()`.
//   2. Child channels speak `SSHChannelData`, never bare `ByteBuffer`s, and
//      there is no unwrapping handler in the library — the codec below is it.
//   3. `allowRemoteHalfClosure` is set on every child channel. Without it the
//      channels behave, in the README's words, "extremely unexpectedly".

import Foundation
import NIOCore
import NIOPosix
import NIOSSH

// MARK: - Public surface

/// How ServerOS proves who it is to the server.
public enum SSHAuthentication: Sendable {
    /// A password. Supported because real servers still use them, not because
    /// it is a good idea; the setup flow offers to install a key instead.
    case password(String)
    /// A key. Ed25519 or ECDSA P-256/384/521 — swift-nio-ssh has no RSA.
    case privateKey(NIOSSHPrivateKey)
}

/// What one remote command produced.
public struct SSHCommandResult: Sendable {
    public let stdout: String
    public let stderr: String
    /// The remote exit status, or `-1` when the command died without one
    /// (killed by a signal, or the channel closed first).
    public let exitStatus: Int32

    public var succeeded: Bool { exitStatus == 0 }

    /// `stdout` without the trailing newline, which is what a caller reading a
    /// single value out of a command almost always wants.
    public var trimmedStdout: String {
        stdout.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    public init(stdout: String, stderr: String, exitStatus: Int32) {
        self.stdout = stdout
        self.stderr = stderr
        self.exitStatus = exitStatus
    }
}

// `SSHTunneling` — the protocol `ServerConnection` holds instead of holding an
// `SSHClient` — is declared in `Networking/ServerConnection.swift`:
//
//     public protocol SSHTunneling: Sendable {
//         func openTunnel(remotePort: Int) async throws -> Int
//         func close() async
//     }
//
// `SSHClient` conforms below. Both requirements are `async`, which is what lets
// an actor's isolated methods satisfy them.

// MARK: - The client

/// One SSH connection.
///
/// An actor because a connection is mutable shared state with a lifecycle, and
/// because everything above it is `async` anyway. It owns its own
/// single-threaded `EventLoopGroup`: one server, one thread, shut down on
/// `disconnect()`. That costs a thread per connected server and buys a very
/// simple threading story — in particular, the local listening socket and the
/// SSH child channels are guaranteed to share an event loop, which is what
/// makes the glue handlers below safe.
public actor SSHClient: SSHTunneling {

    public let host: String
    public let port: Int
    public let username: String

    private let authentication: SSHAuthentication
    private let pinnedHostKey: String?

    private var group: MultiThreadedEventLoopGroup?
    /// The parent SSH channel. `internal` so `TerminalSession` can open a child
    /// channel on it; nothing outside this module sees it.
    private(set) var connectionChannel: Channel?
    private var verifier: HostKeyVerifier?
    private var cachedHostKey: String?
    private var cachedFingerprint: String?
    private var tunnel: (listener: Channel, localPort: Int, remotePort: Int)?

    public init(
        host: String,
        port: Int,
        username: String,
        authentication: SSHAuthentication,
        pinnedHostKey: String?
    ) {
        self.host = host
        self.port = port
        self.username = username
        self.authentication = authentication
        self.pinnedHostKey = pinnedHostKey
    }

    /// The host key the server presented, in `"<algorithm> <base64>"` form.
    /// Survives `disconnect()` so the Add Server flow can store it after the
    /// connection it learned it on has been torn down.
    public var observedHostKey: String? {
        cachedHostKey ?? verifier?.observedHostKey
    }

    /// The same key as `"SHA256:…"`, for showing to a person.
    public var observedHostKeyFingerprint: String? {
        cachedFingerprint ?? verifier?.observedFingerprint
    }

    public var isConnected: Bool { connectionChannel != nil }

    /// The local port the tunnel is listening on, if one is open.
    public var tunnelLocalPort: Int? { tunnel?.localPort }

    // MARK: - Connect

    /// TCP connect, SSH handshake, host key check, user authentication.
    ///
    /// Returns only once authentication has actually succeeded. That matters:
    /// `ClientBootstrap.connect` completes as soon as the TCP channel is
    /// active, long before the server has accepted (or rejected) the
    /// credential, and reporting "connected" at that point would turn a wrong
    /// password into a confusing failure three screens later.
    public func connect() async throws {
        if connectionChannel != nil { return }

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let verifier = HostKeyVerifier(pinnedHostKey: pinnedHostKey)
        let authenticated = OneShot<Void>(group.next().makePromise(of: Void.self))

        let username = self.username
        let authentication = self.authentication
        let host = self.host
        let port = self.port

        do {
            // `SSHClientConfiguration` and `SSHConnectionRole` are both
            // unavailable-Sendable, so they are built inside the initialiser
            // rather than captured from out here.
            // (`ClientBootstrap.init` already sets TCP_NODELAY.)
            let channel = try await ClientBootstrap(group: group)
                .connectTimeout(.seconds(20))
                .channelInitializer { channel in
                    channel.eventLoop.makeCompletedFuture {
                        let configuration = SSHClientConfiguration(
                            userAuthDelegate: SingleOfferAuthDelegate(
                                username: username,
                                authentication: authentication
                            ),
                            serverAuthDelegate: verifier
                        )
                        let ssh = NIOSSHHandler(
                            role: .client(configuration),
                            allocator: channel.allocator,
                            inboundChildChannelInitializer: nil
                        )
                        try channel.pipeline.syncOperations.addHandlers([
                            ssh,
                            AuthenticationGateHandler(gate: authenticated),
                        ])
                    }
                }
                .connect(host: host, port: port)
                .get()

            do {
                // Bounded: `connectTimeout` covers the TCP connect and nothing
                // after it, so a server that accepts the socket and then says
                // nothing would otherwise hang the Add Server sheet forever.
                try await Self.waitForAuthentication(authenticated, seconds: 30)
            } catch {
                try? await channel.close().get()
                throw error
            }

            self.group = group
            self.connectionChannel = channel
            self.verifier = verifier
            self.cachedHostKey = verifier.observedHostKey
            self.cachedFingerprint = verifier.observedFingerprint
        } catch {
            // Whatever went wrong, the promise must not be left unfulfilled
            // (NIO asserts on that in debug builds) and the thread must not be
            // left running.
            authenticated.fail(error)
            self.cachedHostKey = verifier.observedHostKey
            self.cachedFingerprint = verifier.observedFingerprint
            try? await group.shutdownGracefully()
            throw Self.connectionError(error, verifier: verifier, host: host, port: port, username: username)
        }
    }

    /// Close the tunnel, the connection and the event loop group.
    public func disconnect() async {
        await closeTunnel()

        cachedHostKey = verifier?.observedHostKey ?? cachedHostKey
        cachedFingerprint = verifier?.observedFingerprint ?? cachedFingerprint
        verifier = nil

        if let channel = connectionChannel {
            connectionChannel = nil
            try? await channel.close().get()
        }
        if let group {
            self.group = nil
            try? await group.shutdownGracefully()
        }
    }

    /// `SSHTunneling` conformance. Same thing as `disconnect()`; the protocol
    /// is what `ServerConnection` holds, and "close" is its word for it.
    public func close() async {
        await disconnect()
    }

    // MARK: - Run a command

    /// Run one command and collect its output.
    ///
    /// stdout and stderr are kept apart, because a setup step that fails needs
    /// to put the stderr in the "Technical details" disclosure without it
    /// having been interleaved into the value it was trying to read.
    public func run(_ command: String, timeout: TimeInterval = 60) async throws -> SSHCommandResult {
        guard let connection = connectionChannel else { throw ServerOSError.sshNotConnected }

        let result = OneShot<SSHCommandResult>(connection.eventLoop.makePromise(of: SSHCommandResult.self))

        let child: Channel
        do {
            child = try await Self.createChildChannel(
                connection: connection,
                channelType: .session
            ) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        ExecCollectingHandler(command: command, result: result)
                    )
                }
            }.get()
        } catch {
            result.fail(error)
            throw ServerOSError.sshFailed(
                "The server refused to open a session for the command.",
                technical: "\(error)"
            )
        }

        // Closed on every path: success, failure, timeout and cancellation.
        defer { child.close(promise: nil) }

        let seconds = max(1.0, min(timeout, 86_400))
        let outcome = try await withThrowingTaskGroup(of: RunOutcome.self) { group -> RunOutcome in
            group.addTask {
                let value = try await result.value()
                return RunOutcome.finished(value)
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return RunOutcome.timedOut
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { return .timedOut }
            return first
        }

        switch outcome {
        case .finished(let value):
            return value
        case .timedOut:
            throw ServerOSError.sshTimedOut(command: command, seconds: seconds)
        }
    }

    /// Run a command and fail if it did not exit 0.
    @discardableResult
    public func runChecked(_ command: String, timeout: TimeInterval = 60) async throws -> SSHCommandResult {
        let result = try await run(command, timeout: timeout)
        guard result.succeeded else {
            throw ServerOSError.sshCommandFailed(
                command: command,
                exitStatus: result.exitStatus,
                stderr: result.stderr.isEmpty ? result.stdout : result.stderr
            )
        }
        return result
    }

    // MARK: - Local port forwarding

    /// Listen on a loopback port on this Mac and forward it to `remotePort` on
    /// the server, over this SSH connection. Returns the local port.
    ///
    /// Port 0 is used for the local socket so the OS picks a free one — the
    /// agent's own port is often already taken locally by something else, and
    /// guessing leads to the worst kind of bug report.
    public func openTunnel(remotePort: Int) async throws -> Int {
        guard let connection = connectionChannel, let group else { throw ServerOSError.sshNotConnected }
        guard (1...65535).contains(remotePort) else {
            throw ServerOSError.sshTunnelFailed(
                "\(remotePort) isn't a TCP port number.",
                technical: nil
            )
        }

        if let tunnel, tunnel.remotePort == remotePort {
            return tunnel.localPort
        }
        await closeTunnel()

        // `DirectTCPIP.init` narrows to UInt16 without checking, so clamp
        // before it can trap. The guard above already excludes the bad range;
        // this is belt and braces around a documented crash.
        let target = Int(UInt16(clamping: remotePort))

        let listener: Channel
        do {
            listener = try await ServerBootstrap(group: group)
                .serverChannelOption(.socketOption(.so_reuseaddr), value: 1)
                .childChannelInitializer { localChannel in
                    Self.openForwardingChannel(
                        sshConnection: connection,
                        localChannel: localChannel,
                        targetPort: target
                    ).map { _ in }
                }
                .bind(host: "127.0.0.1", port: 0)
                .get()
        } catch {
            throw ServerOSError.sshTunnelFailed(
                "ServerOS couldn't open a local port to forward through.",
                technical: "\(error)"
            )
        }

        guard let localPort = listener.localAddress?.port, localPort > 0 else {
            try? await listener.close().get()
            throw ServerOSError.sshTunnelFailed(
                "ServerOS couldn't tell which local port it bound.",
                technical: "localAddress was \(String(describing: listener.localAddress))"
            )
        }

        tunnel = (listener: listener, localPort: localPort, remotePort: remotePort)
        return localPort
    }

    /// Stop accepting new local connections through the tunnel.
    ///
    /// Connections already forwarded are left to finish; they die with the SSH
    /// connection when `disconnect()` closes it, which is the behaviour a
    /// caller tearing down a server wants and is harmless otherwise.
    public func closeTunnel() async {
        guard let tunnel else { return }
        self.tunnel = nil
        try? await tunnel.listener.close().get()
    }

    // MARK: - Child channels

    /// Open an SSH child channel of the given type.
    ///
    /// This is the `flatSubmit` dance the reference prescribes: `NIOSSHHandler`
    /// is explicitly not `Sendable`, so it cannot be pulled out of the pipeline
    /// into an `async` context — it can only be touched synchronously on its
    /// own event loop, handing back a `Channel`, which is `Sendable`.
    static func createChildChannel(
        connection: Channel,
        channelType: SSHChannelType,
        initializer: @escaping @Sendable (Channel) -> EventLoopFuture<Void>
    ) -> EventLoopFuture<Channel> {
        connection.eventLoop.flatSubmit { () -> EventLoopFuture<Channel> in
            do {
                let ssh = try connection.pipeline.syncOperations.handler(type: NIOSSHHandler.self)
                let promise = connection.eventLoop.makePromise(of: Channel.self)
                ssh.createChannel(promise, channelType: channelType) { childChannel, _ in
                    initializer(childChannel)
                }
                return promise.futureResult
            } catch {
                return connection.eventLoop.makeFailedFuture(error)
            }
        }
    }

    /// One accepted local connection becomes one `directTCPIP` SSH channel,
    /// glued together so bytes flow both ways.
    ///
    /// Both channels live on the same event loop — the group has exactly one
    /// thread — which is what makes it legal for the glue handlers to reach
    /// into each other's contexts.
    static func openForwardingChannel(
        sshConnection: Channel,
        localChannel: Channel,
        targetPort: Int
    ) -> EventLoopFuture<Channel> {
        guard let originator = localChannel.remoteAddress else {
            return localChannel.eventLoop.makeFailedFuture(
                ServerOSError.sshTunnelFailed("A local connection arrived with no address.", technical: nil)
            )
        }

        let directTCPIP = SSHChannelType.DirectTCPIP(
            targetHost: "127.0.0.1",
            targetPort: Int(UInt16(clamping: targetPort)),
            originatorAddress: originator
        )

        let future = createChildChannel(
            connection: sshConnection,
            channelType: .directTCPIP(directTCPIP)
        ) { childChannel in
            childChannel.eventLoop.makeCompletedFuture {
                let (ours, theirs) = TCPGlueHandler.matchedPair()
                let childPipeline = childChannel.pipeline.syncOperations
                try childPipeline.addHandler(SSHChannelDataCodec())
                try childPipeline.addHandler(ours)
                try localChannel.pipeline.syncOperations.addHandler(theirs)
            }
        }

        // If the server refuses the forward, the local connection has nowhere
        // to go; close it rather than leaving a socket that silently eats data.
        future.whenFailure { _ in
            localChannel.close(promise: nil)
        }
        return future
    }

    /// Wait for the handshake, with a ceiling on how long.
    static func waitForAuthentication(_ gate: OneShot<Void>, seconds: Double) async throws {
        let outcome = try await withThrowingTaskGroup(of: RaceOutcome.self) { group -> RaceOutcome in
            group.addTask {
                try await gate.value()
                return RaceOutcome.done
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
                return RaceOutcome.timedOut
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { return .timedOut }
            return first
        }

        if case .timedOut = outcome {
            throw ServerOSError.sshFailed(
                "The server accepted the connection but never finished the SSH handshake.",
                technical: "no authentication result after \(Int(seconds))s"
            )
        }
    }

    // MARK: - Errors

    /// Turn whatever NIO threw into something with a headline a person can read.
    static func connectionError(
        _ error: Error,
        verifier: HostKeyVerifier,
        host: String,
        port: Int,
        username: String
    ) -> ServerOSError {
        // A changed host key is the most important thing that can happen here,
        // and it is recorded on the verifier precisely so it cannot be lost to
        // a racing channel closure.
        if let mismatch = verifier.mismatch { return mismatch }
        if let alreadyOurs = error as? ServerOSError { return alreadyOurs }

        if let sshError = error as? NIOSSHError {
            switch sshError.type {
            case .keyExchangeNegotiationFailure, .invalidHostKeyForKeyExchange:
                return ServerOSError.sshFailed(
                    "This server only offers key types ServerOS can't use — it supports Ed25519 and ECDSA, not RSA.",
                    technical: sshError.description
                )
            case .unsupportedVersion:
                return ServerOSError.sshFailed(
                    "The SSH server on \(host) speaks a version of the protocol ServerOS doesn't.",
                    technical: sshError.description
                )
            case .tcpShutdown:
                return ServerOSError.sshFailed(
                    "The server closed the connection during setup.",
                    technical: sshError.description
                )
            default:
                return ServerOSError.sshFailed(
                    "The SSH handshake with \(host) failed.",
                    technical: sshError.description
                )
            }
        }

        if let channelError = error as? ChannelError {
            // Pattern-matched rather than compared: `ChannelError`'s
            // `Equatable` conformance is not something to bet a build on.
            if case .connectTimeout = channelError {
                return ServerOSError.sshFailed(
                    "\(host) didn't answer on port \(port) within 20 seconds.",
                    technical: "\(error)"
                )
            }
        }

        return ServerOSError.sshFailed(
            "ServerOS couldn't reach \(username)@\(host) on port \(port).",
            technical: "\(error)"
        )
    }
}

/// The two ways `run` can end. Declared outside the actor because task group
/// results have to be `Sendable`.
private enum RunOutcome: Sendable {
    case finished(SSHCommandResult)
    case timedOut
}

/// The same, for a wait with nothing to carry back.
private enum RaceOutcome: Sendable {
    case done
    case timedOut
}

// MARK: - Completing a promise exactly once

/// A promise that tolerates being completed more than once.
///
/// NIO's promises are meant to be completed exactly once — completing one
/// twice is a programming error and leaving one uncompleted trips a debug
/// assertion. Both are easy to do accidentally when a channel handler and the
/// `async` code that created it are racing to report the same failure, so the
/// rule is enforced here, in one place, instead of being hoped for at six call
/// sites.
final class OneShot<Value: Sendable>: @unchecked Sendable {
    private let promise: EventLoopPromise<Value>
    private let lock = NSLock()
    private var completed = false

    init(_ promise: EventLoopPromise<Value>) {
        self.promise = promise
    }

    func succeed(_ value: Value) {
        guard claim() else { return }
        promise.succeed(value)
    }

    func fail(_ error: Error) {
        guard claim() else { return }
        promise.fail(error)
    }

    func value() async throws -> Value {
        try await promise.futureResult.get()
    }

    private func claim() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if completed { return false }
        completed = true
        return true
    }
}

// MARK: - User authentication

/// Offers one credential, once.
///
/// swift-nio-ssh calls `nextAuthenticationType` repeatedly until the delegate
/// returns `nil`, so a delegate that keeps handing back the same offer loops
/// forever. Hence the "offer, then nil out" shape, copied from the library's
/// own `SimplePasswordDelegate`.
final class SingleOfferAuthDelegate: NIOSSHClientUserAuthenticationDelegate, @unchecked Sendable {

    private let lock = NSLock()
    private var offer: NIOSSHUserAuthenticationOffer?
    private let required: NIOSSHAvailableUserAuthenticationMethods
    private let username: String

    init(username: String, authentication: SSHAuthentication) {
        self.username = username
        switch authentication {
        case .password(let password):
            self.required = .password
            // `serviceName` is discarded by the initialiser — the library hard
            // codes "ssh-connection" — but the argument is not defaulted, so
            // every call site passes "".
            self.offer = NIOSSHUserAuthenticationOffer(
                username: username,
                serviceName: "",
                offer: .password(.init(password: password))
            )
        case .privateKey(let key):
            self.required = .publicKey
            self.offer = NIOSSHUserAuthenticationOffer(
                username: username,
                serviceName: "",
                offer: .privateKey(.init(privateKey: key))
            )
        }
    }

    func nextAuthenticationType(
        availableMethods: NIOSSHAvailableUserAuthenticationMethods,
        nextChallengePromise: EventLoopPromise<NIOSSHUserAuthenticationOffer?>
    ) {
        // An empty set means the server hasn't told us yet; treat that as
        // "anything goes" rather than refusing to try.
        let allowed = availableMethods.isEmpty ? NIOSSHAvailableUserAuthenticationMethods.all : availableMethods

        lock.lock()
        let pending = offer
        offer = nil
        lock.unlock()

        guard let pending else {
            // Nothing left to try: a clean authentication failure.
            nextChallengePromise.succeed(nil)
            return
        }

        guard allowed.contains(required) else {
            let what = required == .password ? "password" : "key"
            nextChallengePromise.fail(
                ServerOSError.sshFailed(
                    "This server doesn't accept \(what) authentication for \(username).",
                    technical: "server offered: \(allowed)"
                )
            )
            return
        }

        nextChallengePromise.succeed(pending)
    }
}

/// Completes once the connection is authenticated, so `connect()` can report
/// a bad password as a bad password rather than as a mystery later on.
final class AuthenticationGateHandler: ChannelInboundHandler {
    typealias InboundIn = Any

    private let gate: OneShot<Void>

    init(gate: OneShot<Void>) {
        self.gate = gate
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        if event is UserAuthSuccessEvent {
            gate.succeed(())
        }
        context.fireUserInboundEventTriggered(event)
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        gate.fail(error)
        context.close(promise: nil)
    }

    func channelInactive(context: ChannelHandlerContext) {
        gate.fail(
            ServerOSError.sshFailed(
                "The server closed the connection before accepting the credential.",
                technical: nil
            )
        )
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        gate.fail(
            ServerOSError.sshFailed(
                "The SSH connection ended before it was authenticated.",
                technical: nil
            )
        )
    }
}

// MARK: - Channel handlers

/// Runs one command, keeps stdout and stderr apart, reports the exit status.
///
/// Structurally the reference implementation from
/// `docs/reference/swift-nio-ssh-api.md`, which is in turn the library's own
/// `ExecHandler`. Deviating from it here would be inventing risk for nothing.
final class ExecCollectingHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private let command: String
    private let result: OneShot<SSHCommandResult>
    private var stdout = ByteBuffer()
    private var stderr = ByteBuffer()
    private var exitStatus: Int32?

    init(command: String, result: OneShot<SSHCommandResult>) {
        self.command = command
        self.result = result
    }

    func handlerAdded(context: ChannelHandlerContext) {
        // Mandatory. SSH child channels use half-closure pervasively and
        // misbehave badly without this.
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .assumeIsolated()
            .whenFailure { error in
                context.fireErrorCaught(error)
            }
    }

    func channelActive(context: ChannelHandlerContext) {
        let request = SSHChannelRequestEvent.ExecRequest(command: command, wantReply: true)
        context.triggerUserOutboundEvent(request)
            .assumeIsolated()
            .whenFailure { _ in
                context.close(promise: nil)
            }
        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = unwrapInboundIn(data)
        guard case .byteBuffer(var bytes) = channelData.data else { return }

        switch channelData.type {
        case .channel:
            stdout.writeBuffer(&bytes)
        case .stdErr:
            stderr.writeBuffer(&bytes)
        default:
            break
        }
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as SSHChannelRequestEvent.ExitStatus:
            exitStatus = Int32(clamping: event.exitStatus)

        case let event as SSHChannelRequestEvent.ExitSignal:
            // Shell convention: a process killed by a signal exits 128+n. The
            // signal number isn't on the wire, only its name, so 129 stands in
            // for "died on a signal" and the name goes in stderr where it can
            // actually be read.
            exitStatus = exitStatus ?? 129
            var message = context.channel.allocator.buffer(capacity: 64)
            message.writeString("\nKilled by SIG\(event.signalName). \(event.errorMessage)\n")
            stderr.writeBuffer(&message)

        // Spelled as a cast rather than as `case ChannelEvent.inputClosed:`,
        // which does not type-check against an `Any` subject.
        case let event as ChannelEvent where event == .inputClosed:
            context.close(mode: .output, promise: nil)

        case is ChannelFailureEvent:
            result.fail(
                ServerOSError.sshFailed(
                    "The server refused to run the command.",
                    technical: command
                )
            )
            context.close(promise: nil)

        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))), promise: promise)
    }

    func channelInactive(context: ChannelHandlerContext) {
        finish()
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        finish()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        result.fail(error)
        context.close(promise: nil)
    }

    private func finish() {
        result.succeed(
            SSHCommandResult(
                stdout: stdout.getString(at: stdout.readerIndex, length: stdout.readableBytes) ?? "",
                stderr: stderr.getString(at: stderr.readerIndex, length: stderr.readableBytes) ?? "",
                exitStatus: exitStatus ?? -1
            )
        )
    }
}

/// `SSHChannelData` ⇄ `ByteBuffer`.
///
/// swift-nio-ssh has no `SSHChannelDataUnwrappingHandler`; this twenty-line
/// codec is the whole of it, copied from the library's own sample client.
/// Child channels accept nothing but `SSHChannelData` on write — handing one a
/// bare `ByteBuffer` traps — so this sits at the bottom of every child
/// pipeline that wants to speak in plain bytes.
final class SSHChannelDataCodec: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .assumeIsolated()
            .whenFailure { error in
                context.fireErrorCaught(error)
            }
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = unwrapInboundIn(data)
        guard case .byteBuffer(let buffer) = channelData.data else { return }
        // A forwarded TCP connection has no stderr; anything that isn't
        // channel data is not ours to interpret.
        guard channelData.type == .channel else { return }
        context.fireChannelRead(wrapInboundOut(buffer))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))), promise: promise)
    }
}

/// Pipes two channels into each other.
///
/// swift-nio-ssh ships a `GlueHandler` in its sample executables but not in the
/// library, so here is one. It carries `NIOAny` through untouched rather than
/// unwrapping to a concrete type, which keeps it usable on both sides of the
/// forward, and it throttles reads on one side while the other side's buffer
/// is full so a slow consumer applies back pressure instead of quietly
/// growing memory.
///
/// Safe only because both channels share an event loop — see `SSHClient`'s
/// single-threaded group.
final class TCPGlueHandler {
    private var partner: TCPGlueHandler?
    private var context: ChannelHandlerContext?
    private var pendingRead = false

    private init() {}

    static func matchedPair() -> (TCPGlueHandler, TCPGlueHandler) {
        let first = TCPGlueHandler()
        let second = TCPGlueHandler()
        first.partner = second
        second.partner = first
        return (first, second)
    }

    private func partnerWrite(_ data: NIOAny) {
        context?.write(data, promise: nil)
    }

    private func partnerFlush() {
        context?.flush()
    }

    private func partnerWriteEOF() {
        context?.close(mode: .output, promise: nil)
    }

    private func partnerCloseFull() {
        context?.close(promise: nil)
    }

    private func partnerBecameWritable() {
        if pendingRead {
            pendingRead = false
            context?.read()
        }
    }

    private var partnerWritable: Bool {
        context?.channel.isWritable ?? false
    }
}

extension TCPGlueHandler: ChannelDuplexHandler {
    typealias InboundIn = NIOAny
    typealias InboundOut = NIOAny
    typealias OutboundIn = NIOAny
    typealias OutboundOut = NIOAny

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .assumeIsolated()
            .whenFailure { error in
                context.fireErrorCaught(error)
            }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        self.context = nil
        partner = nil
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        partner?.partnerWrite(data)
    }

    func channelReadComplete(context: ChannelHandlerContext) {
        partner?.partnerFlush()
    }

    func channelInactive(context: ChannelHandlerContext) {
        partner?.partnerCloseFull()
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as ChannelEvent where event == .inputClosed:
            // One side sent EOF: tell the other, but keep reading the reply.
            partner?.partnerWriteEOF()
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelWritabilityChanged(context: ChannelHandlerContext) {
        if context.channel.isWritable {
            partner?.partnerBecameWritable()
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(promise: nil)
    }

    func read(context: ChannelHandlerContext) {
        if let partner, partner.partnerWritable {
            context.read()
        } else {
            pendingRead = true
        }
    }
}
