//  LiveStream.swift
//  ServerOS
//
//  The socket that keeps a server view current.
//
//  # Why a socket rather than a timer
//
//  Polling four endpoints every two seconds means four TCP round trips through
//  an SSH tunnel, four token verifications, and — the part that actually breaks
//  correctness — a metrics sampler that never sees two consecutive samples from
//  the same caller, so every CPU percentage would be computed from a cold
//  baseline and read zero. One socket with a server-side sampler fixes all
//  three.
//
//  # Reconnection is silent on purpose
//
//  A tunnel drops when a laptop's Wi-Fi changes, when a VPN reconnects, when a
//  server reboots. None of those are worth a red banner if the socket comes
//  back in two seconds, and a UI that flashed "Disconnected" on every blip
//  would train people to ignore it — which is exactly what must not happen the
//  one time it is real.
//
//  So this reconnects with exponential backoff behind the screen's back, and
//  emits nothing while doing it: the agent greets every connection with a
//  `welcome` frame, and only the first one is delivered. The screen sees an
//  uninterrupted sequence of data frames with a gap in it. `isConnected` is
//  there for a view that genuinely wants to show connection state — a status
//  dot in the toolbar — rather than the whole screen reacting.

import Foundation

/// A live subscription to one server's `/v1/stream`.
public actor LiveStream {

    /// The channels the agent publishes. Anything else is rejected by the
    /// agent, so requests are filtered against this list before they are sent.
    public static let allChannels: [String] = ["metrics", "docker", "services", "activity"]

    /// Longest a reconnection ever waits. Beyond half a minute a person has
    /// already pressed Reconnect.
    public static let maximumBackoff: TimeInterval = 30

    private let baseURL: URL
    private let minter: AgentTokenMinter
    private let session: URLSession
    private let decoder: JSONDecoder

    private var channels: [String] = []
    private var socket: URLSessionWebSocketTask?
    private var runner: Task<Void, Never>?
    private var continuation: AsyncStream<StreamFrame>.Continuation?
    private var connected: Bool = false
    private var isStopped: Bool = false
    private var hasDeliveredWelcome: Bool = false
    private var suppressNextSubscribedEcho: Bool = false

    /// Create a stream for one server.
    ///
    /// - Parameters:
    ///   - baseURL: The same `http://localhost:<port>` the `AgentClient` uses.
    ///     The scheme is switched to `ws` internally.
    ///   - minter: Mints the token sent on the upgrade request.
    ///   - session: Injectable for tests.
    public init(baseURL: URL, minter: AgentTokenMinter, session: URLSession = .shared) {
        self.baseURL = baseURL
        self.minter = minter
        self.session = session
        self.decoder = JSONDecoder()
    }

    /// Whether a socket is currently open.
    ///
    /// Optimistic by a fraction of a second: it becomes true when the socket is
    /// resumed and false when a receive fails. That is the right granularity for
    /// a status dot and the wrong one for anything that must not act on a stale
    /// answer — those should watch the frames instead.
    public var isConnected: Bool { connected }

    // MARK: - Lifecycle

    /// Open the socket and start delivering frames.
    ///
    /// Calling this a second time replaces the first session: one `LiveStream`
    /// owns one socket and one stream, and handing out a second stream over the
    /// same socket would give two consumers half the frames each. The earlier
    /// stream is finished.
    public func connect(channels: [String]) -> AsyncStream<StreamFrame> {
        continuation?.finish()
        continuation = nil
        runner?.cancel()
        runner = nil
        socket?.cancel(with: .goingAway, reason: nil)
        socket = nil

        self.channels = channels.filter { LiveStream.allChannels.contains($0) }
        isStopped = false
        connected = false
        hasDeliveredWelcome = false
        suppressNextSubscribedEcho = false

        let made = AsyncStream.makeStream(
            of: StreamFrame.self,
            // Frames are state snapshots, not a transcript: if a consumer falls
            // behind, the newest metric is the only one worth keeping.
            bufferingPolicy: .bufferingNewest(256)
        )
        continuation = made.continuation
        runner = Task { [weak self] in
            await self?.run()
        }
        return made.stream
    }

    /// Add channels to the subscription. The resulting `subscribed` frame is
    /// delivered, because this one was asked for.
    public func subscribe(_ channels: [String]) async {
        let wanted = channels.filter { LiveStream.allChannels.contains($0) }
        for channel in wanted where !self.channels.contains(channel) {
            self.channels.append(channel)
        }
        guard let task = socket else { return }
        LiveStream.transmit(LiveStream.clientMessage(type: "subscribe", channels: wanted), on: task)
    }

    /// Drop channels from the subscription — what a screen does when the user
    /// navigates away, so a window sitting on Files is not paying for container
    /// polling.
    public func unsubscribe(_ channels: [String]) async {
        let unwanted = channels.filter { LiveStream.allChannels.contains($0) }
        self.channels.removeAll { unwanted.contains($0) }
        guard let task = socket else { return }
        LiveStream.transmit(LiveStream.clientMessage(type: "unsubscribe", channels: unwanted), on: task)
    }

    /// Close the socket and finish the stream. Reconnection stops for good;
    /// call `connect(channels:)` again to start over.
    public func disconnect() async {
        isStopped = true
        runner?.cancel()
        runner = nil
        socket?.cancel(with: .normalClosure, reason: nil)
        socket = nil
        connected = false
        continuation?.finish()
        continuation = nil
    }

    // MARK: - The connect / receive / back off loop

    private func run() async {
        var attempt = 0

        while !isStopped {
            var carriedTraffic = false
            if openSocket() {
                carriedTraffic = await pump()
            }
            if isStopped { break }

            // Only a connection that actually carried a frame resets the
            // backoff. Otherwise a server that accepts TCP and immediately
            // rejects the upgrade — a wrong port, a stale tunnel — would be
            // retried once a second forever.
            if carriedTraffic {
                attempt = 0
            }
            attempt += 1

            do {
                let delay = LiveStream.backoffDelay(attempt: attempt)
                try await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            } catch {
                break // cancelled by `disconnect()`
            }
        }

        connected = false
        continuation?.finish()
    }

    /// Build and resume a socket. Returns false only when the URL cannot be
    /// composed, which is a programming error rather than a network one.
    private func openSocket() -> Bool {
        guard !isStopped, let url = streamURL() else { return false }

        var request = URLRequest(url: url)
        request.timeoutInterval = 15
        // Fresh token per connection, exactly as with an HTTP request: the
        // agent's replay cache would refuse a reused one.
        request.setValue(
            "Bearer \(minter.mint(scopes: [.read]))",
            forHTTPHeaderField: "Authorization"
        )

        let task = session.webSocketTask(with: request)
        socket = task
        connected = true
        task.resume()

        // Re-state the subscription immediately. On a reconnect this restores
        // exactly the channels the screen last asked for, and its echo is
        // swallowed so the UI sees no event at all.
        if !channels.isEmpty {
            suppressNextSubscribedEcho = true
            LiveStream.transmit(LiveStream.clientMessage(type: "subscribe", channels: channels), on: task)
        }
        return true
    }

    /// Read until the socket fails. Returns whether anything arrived.
    private func pump() async -> Bool {
        guard let task = socket else { return false }
        var carriedTraffic = false

        while !isStopped {
            let message: URLSessionWebSocketTask.Message
            do {
                // Honours cancellation: `disconnect()` cancels the enclosing
                // Task and this throws rather than hanging on a dead socket.
                message = try await task.receive()
            } catch {
                break
            }
            carriedTraffic = true
            handle(message)
        }

        connected = false
        task.cancel(with: .goingAway, reason: nil)
        if socket === task {
            socket = nil
        }
        return carriedTraffic
    }

    private func handle(_ message: URLSessionWebSocketTask.Message) {
        switch message {
        case .string(let text):
            if let frame = decodeFrame(text) {
                emit(frame)
            }
        case .data(let data):
            // The agent only ever sends text, but a binary frame carrying JSON
            // is trivially recoverable and not worth dropping.
            if let text = String(data: data, encoding: .utf8), let frame = decodeFrame(text) {
                emit(frame)
            }
        @unknown default:
            break
        }
    }

    private func emit(_ frame: StreamFrame) {
        switch frame {
        case .welcome:
            // The agent greets every connection, including a silent reconnect.
            // The first greeting tells the UI what this server can do; a later
            // one carries no news, and re-applying capability flags mid-session
            // would make a settled sidebar flicker.
            if hasDeliveredWelcome { return }
            hasDeliveredWelcome = true
        case .subscribed:
            if suppressNextSubscribedEcho {
                suppressNextSubscribedEcho = false
                return
            }
        default:
            break
        }
        continuation?.yield(frame)
    }

    // MARK: - Frame decoding

    private func decodeFrame(_ text: String) -> StreamFrame? {
        let data = Data(text.utf8)
        guard let envelope = try? decoder.decode(StreamEnvelope.self, from: data) else {
            return nil
        }

        switch envelope.type {
        case "welcome":
            guard let welcome = try? decoder.decode(StreamWelcome.self, from: data) else { return nil }
            return .welcome(welcome)

        case "metrics":
            guard let payload = try? decoder.decode(StreamPayload<Metrics>.self, from: data) else { return nil }
            return .metrics(payload.data)

        case "docker":
            guard let payload = try? decoder.decode(StreamPayload<StreamDockerBody>.self, from: data) else {
                return nil
            }
            let body = payload.data
            // The stream spells the array `containers` where the REST endpoint
            // spells it `items`, and carries no stats counts. Rebuilding the
            // shared model here means every screen consumes one type whichever
            // source it came from.
            return .docker(DockerContainerList(
                total: body.total,
                items: body.containers,
                running: body.running,
                statsSampled: nil,
                statsTruncated: nil
            ))

        case "services":
            guard let payload = try? decoder.decode(StreamPayload<StreamServicesBody>.self, from: data) else {
                return nil
            }
            return .services(payload.data.units)

        case "activity":
            guard let payload = try? decoder.decode(StreamPayload<StreamActivityBody>.self, from: data) else {
                return nil
            }
            return .activity(payload.data.events)

        case "subscribed":
            guard let frame = try? decoder.decode(StreamSubscribed.self, from: data) else { return nil }
            return .subscribed(frame.channels)

        case "pong":
            return .pong

        case "error":
            guard let frame = try? decoder.decode(StreamErrorFrame.self, from: data) else { return nil }
            return .failure(code: frame.code, message: frame.message)

        default:
            // An agent newer than this app may publish a channel we do not
            // know. Ignoring it is correct; failing the socket would not be.
            return nil
        }
    }

    // MARK: - Plumbing

    private func streamURL() -> URL? {
        guard var components = URLComponents(url: baseURL, resolvingAgainstBaseURL: false) else {
            return nil
        }
        // `ws` over the tunnelled loopback port. As with the HTTP client the
        // host stays `localhost`: App Transport Security blocks cleartext to IP
        // literals from macOS 14, and that applies to `ws://` too.
        components.scheme = "ws"
        components.percentEncodedPath = "/v1/stream"
        components.percentEncodedQuery = nil
        return components.url
    }

    /// `{"type":"subscribe","channels":["metrics","docker"]}`
    ///
    /// Assembled as text rather than encoded: both fields come from constants in
    /// this file, so there is nothing to escape and nothing that can throw.
    static func clientMessage(type: String, channels: [String]) -> String {
        let safe = channels.filter { LiveStream.allChannels.contains($0) }
        let list = safe.map { "\"\($0)\"" }.joined(separator: ",")
        return "{\"type\":\"\(type)\",\"channels\":[\(list)]}"
    }

    /// Send without waiting.
    ///
    /// Static, so the completion handler captures nothing: a failed send means
    /// the socket has already gone, the receive loop is about to notice, and
    /// there is nothing useful to do in the completion.
    private static func transmit(_ text: String, on task: URLSessionWebSocketTask) {
        task.send(.string(text)) { _ in }
    }

    /// 1s, 2s, 4s, 8s, 16s, then 30s — each with up to 25% jitter.
    ///
    /// The jitter matters on a team: without it, every Mac watching the same
    /// server reconnects in lockstep after a network blip and arrives as a
    /// thundering herd on an agent that is already struggling.
    static func backoffDelay(attempt: Int) -> TimeInterval {
        let step = min(max(attempt, 1), 6)
        let base = min(pow(2.0, Double(step - 1)), LiveStream.maximumBackoff)
        let jitter = Double.random(in: 0...(base * 0.25))
        return min(base + jitter, LiveStream.maximumBackoff)
    }
}

// MARK: - Wire shapes local to the socket

/// Just enough of a frame to pick the right decoder.
private struct StreamEnvelope: Decodable {
    let type: String
}

/// A data channel's frame: `{"type":…,"at":…,"data":{…}}`.
private struct StreamPayload<Body: Decodable>: Decodable {
    let data: Body
}

/// The docker channel's payload. Note `containers`, not `items`.
private struct StreamDockerBody: Decodable {
    let total: Int
    let running: Int
    let containers: [DockerContainer]
}

private struct StreamServicesBody: Decodable {
    let total: Int
    let units: [ServiceUnit]
}

private struct StreamActivityBody: Decodable {
    let events: [ActivityEvent]
}

private struct StreamSubscribed: Decodable {
    let channels: [String]
}

private struct StreamErrorFrame: Decodable {
    let code: String
    let message: String
}
