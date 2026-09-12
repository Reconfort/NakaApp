//  ServerConnection.swift
//  ServerOS
//
//  One server, end to end: tunnel, client, socket.
//
//  A feature screen should not know that reaching a server means finding a
//  credential in the Keychain, opening an SSH tunnel, waiting for an agent that
//  may still be starting, and only then making a request. It holds a
//  `ServerConnection`, watches `phase`, and uses `client` and `stream` once
//  they exist.
//
//  # The SSH boundary
//
//  There is no SSH code in this file, and there must not be. Tunnelling is
//  behind `SSHTunneling` so that the transport can be a real SSH
//  implementation, a stub in a preview, or — later — something else entirely,
//  without any of the three being able to reach into the others. `StubTunnel`
//  is what previews and tests use.
//
//  # Why the phase is a value rather than a set of booleans
//
//  `isConnecting`, `isConnected`, `hasFailed` can express states that cannot
//  happen, and a UI written against them eventually renders one. A single
//  `ConnectionPhase` cannot be both connecting and failed, and `describedStep`
//  gives every phase a sentence — so the connecting sheet is a `switch` with no
//  default rather than a pile of conditionals.

import Foundation

/// Where a connection has got to.
public enum ConnectionPhase: Equatable, Sendable {
    /// Never asked to connect.
    case idle
    /// Reading the saved credential.
    case resolving
    /// Opening the SSH tunnel.
    case connecting
    /// Tunnel is up; proving who we are to the agent.
    case authenticating
    /// The agent has not answered yet, which usually means it is still coming
    /// up after a reboot. Distinct from `authenticating` because the honest
    /// thing to show is "waiting", not "checking credentials".
    case startingAgent
    /// Connected. `client` and `stream` are usable.
    case ready
    /// Stopped, with a reason a person can read.
    case failed(ServerOSError)
    /// Deliberately disconnected.
    case disconnected

    /// One short sentence for the connecting sheet and the sidebar subtitle.
    public var describedStep: String {
        switch self {
        case .idle: return "Not connected"
        case .resolving: return "Finding this server's credential…"
        case .connecting: return "Opening a secure connection…"
        case .authenticating: return "Checking credentials…"
        case .startingAgent: return "Waiting for the agent to answer…"
        case .ready: return "Connected"
        case .failed(let error): return error.headline
        case .disconnected: return "Disconnected"
        }
    }

    /// The same sentence, naming the server: "Connecting to Production…".
    ///
    /// A distinct base name from `describedStep` on purpose — a property and a
    /// method that differ only in their arguments read as a typo at the call
    /// site.
    public func stepDescription(for serverName: String) -> String {
        switch self {
        case .idle: return "Not connected to \(serverName)"
        case .resolving: return "Finding \(serverName)'s credential…"
        case .connecting: return "Connecting to \(serverName)…"
        case .authenticating: return "Checking credentials for \(serverName)…"
        case .startingAgent: return "Waiting for \(serverName)'s agent…"
        case .ready: return "Connected to \(serverName)"
        case .failed(let error): return error.headline
        case .disconnected: return "Disconnected from \(serverName)"
        }
    }

    /// Whether work is in flight — what a progress indicator keys off.
    public var isWorking: Bool {
        switch self {
        case .resolving, .connecting, .authenticating, .startingAgent:
            return true
        case .idle, .ready, .failed, .disconnected:
            return false
        }
    }

    /// Whether `client` and `stream` can be used.
    public var isReady: Bool {
        if case .ready = self { return true }
        return false
    }
}

// MARK: - Tunnelling

/// Opens a local port that forwards to the agent's port on the server.
///
/// Implemented elsewhere. Nothing in this file knows what SSH is, and nothing
/// in the SSH implementation needs to know what an agent is.
public protocol SSHTunneling: Sendable {
    /// Forward a local port to `remotePort` on the server.
    /// - Returns: The local port to connect to, on this Mac.
    func openTunnel(remotePort: Int) async throws -> Int

    /// Tear the tunnel down. Safe to call when nothing is open.
    func close() async
}

/// A tunnel that opens nothing and reports a fixed local port.
///
/// For previews, for tests, and for pointing the app at an agent that is
/// already reachable on this Mac — a development agent running in a local VM,
/// say, where the port forward is somebody else's job.
public struct StubTunnel: SSHTunneling {
    /// The port `openTunnel(remotePort:)` will report.
    public let localPort: Int

    /// - Parameter localPort: Defaults to the agent's own default port, which
    ///   is what a locally-run development agent listens on.
    public init(localPort: Int = 8723) {
        self.localPort = localPort
    }

    public func openTunnel(remotePort: Int) async throws -> Int {
        localPort
    }

    public func close() async {}
}

// MARK: - The connection

/// Everything needed to talk to one server, assembled in order.
public actor ServerConnection {

    /// How many times to ask a freshly-tunnelled agent for its health before
    /// giving up. An agent that is starting alongside the server it manages can
    /// take a moment to bind its port.
    public static let healthAttempts: Int = 3

    /// Gap between those attempts.
    public static let healthRetryDelay: TimeInterval = 1.5

    /// The server this connection is for.
    public let serverID: String

    /// The server's display name, used in error copy and progress text.
    public let serverName: String

    /// Where the connection has got to.
    public private(set) var phase: ConnectionPhase = .idle

    /// The request client. Non-nil from `.ready` onwards.
    public private(set) var client: AgentClient?

    /// The live socket. Non-nil from `.ready` onwards, not yet connected — the
    /// screen decides which channels it wants and calls `connect(channels:)`.
    public private(set) var stream: LiveStream?

    private let tunnel: any SSHTunneling
    private let credentials: CredentialStore
    private let session: URLSession
    private var phaseContinuation: AsyncStream<ConnectionPhase>.Continuation?

    /// Assemble a connection. Nothing happens until `connect()`.
    public init(
        serverID: String,
        serverName: String,
        tunnel: any SSHTunneling,
        credentials: CredentialStore = CredentialStore(),
        session: URLSession = .shared
    ) {
        self.serverID = serverID
        self.serverName = serverName
        self.tunnel = tunnel
        self.credentials = credentials
        self.session = session
    }

    /// Every phase change from now on, starting with the current one.
    ///
    /// One observer at a time: calling this again finishes the previous stream.
    /// The UI layer wraps a connection in a single observable object, so one is
    /// what it needs.
    public func phaseUpdates() -> AsyncStream<ConnectionPhase> {
        phaseContinuation?.finish()
        let made = AsyncStream.makeStream(of: ConnectionPhase.self, bufferingPolicy: .bufferingNewest(16))
        phaseContinuation = made.continuation
        made.continuation.yield(phase)
        return made.stream
    }

    // MARK: - Connecting

    /// Open the tunnel, authenticate, and make `client` and `stream` available.
    ///
    /// Never throws: every failure lands in `phase` as a `.failed` carrying a
    /// `ServerOSError`, because a connection failure is something the screen
    /// draws rather than something a caller catches.
    public func connect() async {
        if phase.isReady || phase.isWorking { return }

        setPhase(.resolving)
        let credential: ServerCredential
        do {
            guard let stored = try await credentials.load(serverID: serverID) else {
                setPhase(.failed(.noCredential))
                return
            }
            credential = stored
        } catch let error as KeychainError {
            setPhase(.failed(ServerConnection.keychainFailure(error)))
            return
        } catch {
            setPhase(.failed(ServerOSError.decoding(error, endpoint: "keychain:\(serverID)")))
            return
        }

        setPhase(.connecting)
        let localPort: Int
        do {
            localPort = try await tunnel.openTunnel(remotePort: credential.agentPort)
        } catch let error as ServerOSError {
            setPhase(.failed(error))
            return
        } catch {
            setPhase(.failed(ServerOSError.sshFailed(
                "The SSH connection to \(serverName) couldn't be opened.",
                technical: "\(error)"
            )))
            return
        }

        let baseURL = AgentClient.loopbackURL(port: localPort)
        let minter = AgentTokenMinter(secret: credential.agentSecret)
        let agent = AgentClient(baseURL: baseURL, minter: minter, serverName: serverName, session: session)

        setPhase(.authenticating)
        guard let health = await waitForAgent(agent) else { return }

        guard health.isOK else {
            setPhase(.failed(ServerOSError(
                code: "agent_unhealthy",
                headline: "\(serverName)'s agent reported a problem.",
                causes: ["The agent is running but says it is not ready."],
                technical: "health.status = \(health.status)",
                isRetryable: true
            )))
            return
        }

        client = agent
        stream = LiveStream(baseURL: baseURL, minter: minter, session: session)
        setPhase(.ready)
    }

    /// Ask for health until the agent answers or the attempts run out.
    ///
    /// The retry exists for one specific moment: the tunnel is up because
    /// sshd is up, but the agent is still starting — after a reboot, or after
    /// the user restarted it from this app. Reporting "unreachable" a quarter of
    /// a second before it answers would be both wrong and the most annoying
    /// possible time to be wrong.
    ///
    /// Returns nil when it gave up, having already set the failure phase.
    private func waitForAgent(_ agent: AgentClient) async -> AgentHealth? {
        var lastFailure = ServerOSError(
            code: "agent_unreachable",
            headline: "ServerOS couldn't reach the agent on \(serverName).",
            causes: ["The agent may not be running on this server."],
            technical: nil,
            isRetryable: true
        )

        for attempt in 0..<ServerConnection.healthAttempts {
            if attempt > 0 {
                setPhase(.startingAgent)
                do {
                    try await Task.sleep(nanoseconds: UInt64(ServerConnection.healthRetryDelay * 1_000_000_000))
                } catch {
                    setPhase(.disconnected)
                    return nil
                }
            }

            do {
                return try await agent.health()
            } catch let error as ServerOSError {
                lastFailure = error
                // A credential that is wrong will still be wrong in a second and
                // a half. Only wait for things that time fixes.
                if !error.isRetryable { break }
            } catch {
                lastFailure = ServerOSError.transport(error, serverName: serverName)
            }
        }

        setPhase(.failed(lastFailure))
        return nil
    }

    // MARK: - Disconnecting

    /// Close the socket and the tunnel. Idempotent.
    public func disconnect() async {
        if let stream {
            await stream.disconnect()
        }
        stream = nil
        client = nil
        await tunnel.close()
        setPhase(.disconnected)
    }

    /// Tear everything down and connect again — what the "Reconnect" button in
    /// an error state does.
    public func reconnect() async {
        await disconnect()
        setPhase(.idle)
        await connect()
    }

    // MARK: - Plumbing

    private func setPhase(_ next: ConnectionPhase) {
        guard next != phase else { return }
        phase = next
        phaseContinuation?.yield(next)
    }

    private static func keychainFailure(_ error: KeychainError) -> ServerOSError {
        ServerOSError(
            code: "keychain_unavailable",
            headline: error.userMessage,
            causes: ["ServerOS keeps every server's credential in your Mac's keychain."],
            technical: error.technicalDetail,
            isRetryable: true
        )
    }
}
