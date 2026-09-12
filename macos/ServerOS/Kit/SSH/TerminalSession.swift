//  TerminalSession.swift
//  ServerOS
//
//  The escape hatch.
//
//  ──────────────────────────────────────────────────────────────────────────
//  This is NOT the product's primary surface, and the moment it starts being
//  used for ordinary work something has gone wrong with the rest of the app.
//  ServerOS exists so that restarting a container, adding a user or reading a
//  log does not require remembering a command. The terminal is here for the
//  10% ServerOS does not model yet, and for the reassurance of knowing it is
//  there — the same reason a good abstraction still lets you drop a level.
//
//  It follows that this file stays small. No command history, no completion,
//  no scrollback management: a PTY, a shell, bytes in, bytes out, and a resize.
//  The terminal emulator itself belongs in the view layer.
//  ──────────────────────────────────────────────────────────────────────────

import Foundation
import NIOCore
import NIOSSH

/// An interactive shell on the server, with a pseudo-terminal attached.
public actor TerminalSession {

    /// Everything the shell prints, stdout and stderr together — which is what
    /// a terminal is: one stream of bytes with escape sequences in it, not two
    /// channels to be reassembled.
    ///
    /// `nonisolated` so a view can `for await` on it without hopping through
    /// the actor for every chunk.
    public nonisolated let output: AsyncStream<Data>

    private let channel: Channel
    private let continuation: AsyncStream<Data>.Continuation
    private var isClosed = false

    init(channel: Channel, output: AsyncStream<Data>, continuation: AsyncStream<Data>.Continuation) {
        self.channel = channel
        self.output = output
        self.continuation = continuation
    }

    /// Send keystrokes (or a paste, or a Ctrl-C) to the shell.
    public func send(_ data: Data) async throws {
        guard !isClosed else { throw ServerOSError.sshNotConnected }
        guard !data.isEmpty else { return }

        var buffer = channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)

        let promise = channel.eventLoop.makePromise(of: Void.self)
        // `NIOAny(...)` rather than relying on a generic overload: the
        // `NIOAny`-taking method is the protocol requirement itself, so this
        // spelling resolves the same way whatever else is in scope.
        channel.writeAndFlush(NIOAny(buffer), promise: promise)
        do {
            try await promise.futureResult.get()
        } catch {
            throw ServerOSError.sshFailed("The terminal connection dropped.", technical: "\(error)")
        }
    }

    /// Tell the remote shell the window changed size, so `top` and friends
    /// redraw at the right width.
    public func resize(columns: Int, rows: Int) async {
        guard !isClosed else { return }
        let event = SSHChannelRequestEvent.WindowChangeRequest(
            terminalCharacterWidth: TerminalSession.clampDimension(columns),
            terminalRowHeight: TerminalSession.clampDimension(rows),
            terminalPixelWidth: 0,
            terminalPixelHeight: 0
        )
        // A resize that does not arrive is a cosmetic problem, not a failure
        // worth throwing at the UI.
        _ = try? await channel.triggerUserOutboundEvent(event).get()
    }

    /// End the session.
    public func close() async {
        guard !isClosed else { return }
        isClosed = true
        continuation.finish()
        try? await channel.close().get()
    }

    /// `PseudoTerminalRequest` and `WindowChangeRequest` narrow every dimension
    /// to `UInt32` in their initialisers without checking, so a negative window
    /// size — which SwiftUI will happily hand over mid-animation — would trap
    /// the whole app.
    static func clampDimension(_ value: Int) -> Int {
        min(max(value, 1), 10_000)
    }
}

// MARK: - Opening one

extension SSHClient {

    /// Open a shell with a PTY attached.
    ///
    /// The returned session is independent of `run(_:)` — it is its own SSH
    /// child channel — so an open terminal does not interfere with the app's
    /// ordinary traffic through the tunnel.
    public func openTerminal(
        term: String = "xterm-256color",
        columns: Int = 80,
        rows: Int = 24
    ) async throws -> TerminalSession {
        guard let connection = connectionChannel else { throw ServerOSError.sshNotConnected }

        let (stream, continuation) = AsyncStream<Data>.makeStream(bufferingPolicy: .bufferingNewest(512))

        let safeColumns = TerminalSession.clampDimension(columns)
        let safeRows = TerminalSession.clampDimension(rows)

        let child: Channel
        do {
            child = try await Self.createChildChannel(
                connection: connection,
                channelType: .session
            ) { channel in
                channel.eventLoop.makeCompletedFuture {
                    try channel.pipeline.syncOperations.addHandler(
                        TerminalChannelHandler(
                            term: term,
                            columns: safeColumns,
                            rows: safeRows,
                            continuation: continuation
                        )
                    )
                }
            }.get()
        } catch {
            continuation.finish()
            throw ServerOSError.sshFailed(
                "The server wouldn't open a terminal session.",
                technical: "\(error)"
            )
        }

        return TerminalSession(channel: child, output: stream, continuation: continuation)
    }
}

// MARK: - The channel handler

/// Requests a PTY and a shell, then pumps bytes into an `AsyncStream`.
final class TerminalChannelHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = ByteBuffer
    typealias OutboundIn = ByteBuffer
    typealias OutboundOut = SSHChannelData

    private let term: String
    private let columns: Int
    private let rows: Int
    private let continuation: AsyncStream<Data>.Continuation

    init(term: String, columns: Int, rows: Int, continuation: AsyncStream<Data>.Continuation) {
        self.term = term
        self.columns = columns
        self.rows = rows
        self.continuation = continuation
    }

    func handlerAdded(context: ChannelHandlerContext) {
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true)
            .assumeIsolated()
            .whenFailure { error in
                context.fireErrorCaught(error)
            }
    }

    func channelActive(context: ChannelHandlerContext) {
        let pty = SSHChannelRequestEvent.PseudoTerminalRequest(
            wantReply: true,
            term: term,
            terminalCharacterWidth: columns,
            terminalRowHeight: rows,
            terminalPixelWidth: 0,
            terminalPixelHeight: 0,
            // Sane defaults: echo on, canonical input, signals enabled, and
            // output post-processing so newlines land in the right column.
            terminalModes: SSHTerminalModes([
                .ECHO: 1,
                .ICANON: 1,
                .ISIG: 1,
                .IEXTEN: 1,
                .OPOST: 1,
                .ONLCR: 1,
            ])
        )
        context.triggerUserOutboundEvent(pty)
            .assumeIsolated()
            .whenFailure { _ in
                context.close(promise: nil)
            }

        let shell = SSHChannelRequestEvent.ShellRequest(wantReply: true)
        context.triggerUserOutboundEvent(shell)
            .assumeIsolated()
            .whenFailure { _ in
                context.close(promise: nil)
            }

        context.fireChannelActive()
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let channelData = unwrapInboundIn(data)
        guard case .byteBuffer(let buffer) = channelData.data else { return }
        // Both `.channel` and `.stdErr` go to the screen; a terminal shows
        // whatever the program wrote, wherever it wrote it.
        continuation.yield(Data(buffer.readableBytesView))
    }

    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        let buffer = unwrapOutboundIn(data)
        context.write(wrapOutboundOut(SSHChannelData(type: .channel, data: .byteBuffer(buffer))), promise: promise)
    }

    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        switch event {
        case let event as ChannelEvent where event == .inputClosed:
            context.close(promise: nil)
        case let status as SSHChannelRequestEvent.ExitStatus:
            var goodbye = context.channel.allocator.buffer(capacity: 32)
            goodbye.writeString("\r\n[exited \(status.exitStatus)]\r\n")
            continuation.yield(Data(goodbye.readableBytesView))
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        continuation.finish()
        context.fireChannelInactive()
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        continuation.finish()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        continuation.finish()
        context.close(promise: nil)
    }
}
