//  ServerSession.swift
//  ServerOS
//
//  One server's live state, as the UI sees it.
//
//  Everything that arrives over the live channel lands here, and every screen
//  for that server reads from here. That gives three things the product needs:
//
//   * The health verdict is computed once, from one set of numbers, so the
//     dashboard card and the server header can never disagree.
//   * Switching between Docker and Files does not re-fetch anything; the data
//     was already streaming.
//   * When a server goes away, exactly one object knows, and every screen that
//     depends on it reacts at once.
//
//  This is a `@MainActor @Observable` class rather than an actor: it exists to
//  be read by SwiftUI, and SwiftUI reads on the main actor. The work behind it
//  is done by `AgentClient` and `LiveStream`, which are actors.

import Foundation
import Observation
import SwiftUI

@MainActor
@Observable
public final class ServerSession {

    // MARK: Identity

    public private(set) var summary: ServerSummary
    public var id: String { summary.id }
    public var name: String { summary.name }
    public var isDemo: Bool { summary.isDemo }

    // MARK: Connection

    public private(set) var phase: ConnectionPhase = .idle
    public private(set) var capabilities: AgentCapabilities = .none
    public private(set) var lastContact: Date?
    public private(set) var agentVersion: String?

    /// The API for this server. Nil until the connection is ready.
    public private(set) var api: AgentAPI?

    // MARK: Streamed state

    public private(set) var metrics: Metrics?
    public private(set) var system: SystemInfo?
    public private(set) var containers: [DockerContainer] = []
    public private(set) var services: [ServiceUnit] = []
    public private(set) var activity: [ActivityEvent] = []

    /// A short history for the sparklines. A ring buffer, because a window left
    /// open for a week must not accumulate a week of samples.
    public private(set) var cpuHistory: [Double] = []
    public private(set) var memoryHistory: [Double] = []
    private let historyLimit = 60

    // MARK: Derived

    /// The verdict. Recomputed whenever an input changes, in one place.
    public private(set) var health: ServerHealth = .unknown

    /// Everything currently wrong, most severe first — for the server Overview.
    public private(set) var findings: [HealthFinding] = []

    // MARK: Private

    private let connection: ServerConnection?
    private let demoClient: DemoAgentClient?
    // `nonisolated(unsafe)` so `deinit` can cancel them. `deinit` is not
    // main-actor isolated even on a `@MainActor` class, and leaving these
    // running past the session's death leaks a stream per closed window.
    // Safe in practice: `Task.cancel()` is documented as callable from any
    // thread, every other access is on the main actor, and by the time
    // `deinit` runs no other reference to this object exists.
    nonisolated(unsafe) private var streamTask: Task<Void, Never>?
    nonisolated(unsafe) private var phaseTask: Task<Void, Never>?
    nonisolated(unsafe) private var demoTask: Task<Void, Never>?
    private var stream: LiveStream?
    private var subscribedChannels: Set<String> = []

    // MARK: Init

    /// A real server, reached through SSH and the agent.
    public init(summary: ServerSummary, connection: ServerConnection) {
        self.summary = summary
        self.connection = connection
        self.demoClient = nil
    }

    /// A demo server. No network, no credentials, moving numbers.
    public init(demo summary: ServerSummary, client: DemoAgentClient) {
        self.summary = summary
        self.connection = nil
        self.demoClient = client
    }

    deinit {
        streamTask?.cancel()
        phaseTask?.cancel()
        demoTask?.cancel()
    }

    // MARK: Lifecycle

    public func connect() {
        guard phase == .idle || phase == .disconnected || phase.isFailure else { return }

        if let demoClient {
            startDemo(demoClient)
            return
        }
        guard let connection else { return }

        observePhases(of: connection)
        Task { await connection.connect() }
    }

    public func disconnect() {
        forgetLiveState()
        phase = .disconnected
        recomputeHealth()

        if let connection {
            Task { await connection.disconnect() }
        }
    }

    /// Tear down and connect again — every "Reconnect" button in the app.
    ///
    /// This used to be `disconnect(); phase = .idle; connect()`, which put
    /// `connection.disconnect()` and `connection.connect()` on two separate
    /// tasks against the same actor. Actors don't run tasks in the order they
    /// were made, and they are re-entrant at every `await`: `disconnect()`
    /// would suspend on closing the stream, `connect()` would enter, see the
    /// phase still `.ready`, and return having done nothing — then
    /// `disconnect()` would finish and leave the server at `.disconnected`.
    /// Permanently. Every Reconnect button in the app was this coin flip, and
    /// the coin was weighted: it came up "Offline" nearly every time, and the
    /// button meant to fix that ran the same race again.
    ///
    /// The connection has always had an ordered `reconnect()` of its own. This
    /// now uses it, in one task, so teardown completes before the connect
    /// begins.
    public func reconnect() {
        forgetLiveState()
        phase = .idle
        recomputeHealth()

        if let demoClient {
            startDemo(demoClient)
            return
        }
        guard let connection else { return }

        observePhases(of: connection)
        Task { await connection.reconnect() }
    }

    /// Drop everything this session holds about a live connection. The
    /// connection itself is torn down by the caller, in whichever order the
    /// caller needs.
    private func forgetLiveState() {
        streamTask?.cancel()
        streamTask = nil
        demoTask?.cancel()
        demoTask = nil
        api = nil
        stream = nil
        subscribedChannels = []
    }

    /// Follow the connection's phase from now on. Replaces any earlier
    /// observation: the connection finishes its previous stream when a new one
    /// is asked for, so a stale task cannot apply a stale phase on top of a
    /// fresh one.
    private func observePhases(of connection: ServerConnection) {
        phaseTask?.cancel()
        phaseTask = Task { [weak self] in
            guard let self else { return }
            for await newPhase in await connection.phaseUpdates() {
                await self.apply(phase: newPhase)
            }
        }
    }

    /// Ask the server for everything again, for ⌘R and pull-to-refresh.
    public func refreshAll() async {
        guard let api else { return }
        async let metricsResult = try? api.metrics()
        async let systemResult = try? api.system()
        async let activityResult = try? api.activity(limit: 50, since: nil)

        if let value = await metricsResult { apply(metrics: value) }
        if let value = await systemResult { system = value }
        if let value = await activityResult { activity = value }

        if capabilities.docker, let list = try? await api.containers(all: true) {
            containers = list.items
        }
        if capabilities.services, let units = try? await api.services() {
            services = units
        }
        lastContact = Date()
        recomputeHealth()
    }

    // MARK: Channel subscription
    //
    // Screens declare what they need to see; the session asks for exactly that
    // and nothing more. A window sitting on Files should not be paying for
    // container polling on the other end of an SSH tunnel.

    public func need(channels: Set<String>) {
        let toAdd = channels.subtracting(subscribedChannels)
        let toRemove = subscribedChannels.subtracting(channels)
        subscribedChannels = channels

        guard let stream else { return }
        if !toAdd.isEmpty { Task { await stream.subscribe(Array(toAdd)) } }
        if !toRemove.isEmpty { Task { await stream.unsubscribe(Array(toRemove)) } }
    }

    // MARK: Phase handling

    private func apply(phase newPhase: ConnectionPhase) async {
        phase = newPhase

        switch newPhase {
        case .ready:
            guard let connection else { break }
            api = await connection.client
            stream = await connection.stream
            lastContact = Date()

            if let api {
                if let health = try? await api.health() {
                    capabilities = health.capabilities
                    agentVersion = health.agentVersion
                }
                if let info = try? await api.system() { system = info }
            }
            startStream()
            await refreshAll()

        case .failed, .disconnected:
            api = nil
            stream = nil

        default:
            break
        }
        recomputeHealth()
    }

    private func startStream() {
        guard let stream else { return }
        let channels = subscribedChannels.isEmpty
            ? ["metrics", "activity"]
            : Array(subscribedChannels)

        streamTask?.cancel()
        streamTask = Task { [weak self] in
            let frames = await stream.connect(channels: channels)
            for await frame in frames {
                guard !Task.isCancelled else { return }
                await self?.apply(frame: frame)
            }
        }
    }

    private func apply(frame: StreamFrame) {
        lastContact = Date()

        switch frame {
        case .welcome(let welcome):
            capabilities = welcome.capabilities
            agentVersion = welcome.agentVersion

        case .metrics(let value):
            apply(metrics: value)

        case .docker(let list):
            containers = list.items

        case .services(let units):
            services = units

        case .activity(let events):
            // Newest first, de-duplicated by id, bounded.
            let existing = Set(activity.map(\.id))
            let fresh = events.filter { !existing.contains($0.id) }
            activity = (fresh + activity).sorted { $0.at > $1.at }
            if activity.count > 200 { activity = Array(activity.prefix(200)) }

        case .subscribed, .pong:
            break

        case .failure(let code, let message):
            // A channel-level failure is not a connection failure: Docker may
            // have been restarted underneath us while metrics keep flowing.
            if code.hasPrefix("docker") { containers = [] }
            if code.hasPrefix("services") { services = [] }
            _ = message
        }

        recomputeHealth()
    }

    private func apply(metrics value: Metrics) {
        metrics = value
        guard !value.isWarmingUp else { return }
        cpuHistory.append(value.cpu.usagePercent)
        memoryHistory.append(value.memory.usagePercent)
        if cpuHistory.count > historyLimit { cpuHistory.removeFirst(cpuHistory.count - historyLimit) }
        if memoryHistory.count > historyLimit { memoryHistory.removeFirst(memoryHistory.count - historyLimit) }
    }

    // MARK: Health

    private func recomputeHealth() {
        let reachable: Bool
        switch phase {
        case .ready: reachable = true
        case .failed, .disconnected: reachable = false
        default: reachable = lastContact != nil
        }

        let input = HealthInput(
            isReachable: reachable,
            secondsSinceLastContact: lastContact.map { Date().timeIntervalSince($0) },
            metrics: metrics,
            stoppedContainers: containers.filter(\.isStopped).map(\.displayName),
            unhealthyContainers: containers.filter(\.isUnhealthy).map(\.displayName),
            failedServices: services.filter(\.hasFailed).map(\.displayName)
        )

        health = HealthEvaluator.evaluate(input)
        findings = HealthEvaluator.findings(for: input)
    }

    // MARK: Demo

    private func startDemo(_ client: DemoAgentClient) {
        api = client
        phase = .ready
        lastContact = Date()

        demoTask?.cancel()
        demoTask = Task { [weak self] in
            guard let self else { return }
            if let health = try? await client.health() {
                await MainActor.run { self.capabilities = health.capabilities }
            }
            if let info = try? await client.system() {
                await MainActor.run { self.system = info }
            }
            // The demo environment walks its numbers, so ticking it on the same
            // cadence as a real metrics channel makes the UI's animations and
            // sparklines behave exactly as they will against a real server.
            while !Task.isCancelled {
                if let value = try? await client.metrics() {
                    await MainActor.run {
                        self.apply(metrics: value)
                        self.lastContact = Date()
                    }
                }
                if let list = try? await client.containers(all: true) {
                    await MainActor.run { self.containers = list.items }
                }
                if let units = try? await client.services() {
                    await MainActor.run { self.services = units }
                }
                if let events = try? await client.activity(limit: 30) {
                    await MainActor.run { self.activity = events }
                }
                await MainActor.run { self.recomputeHealth() }
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }

    // MARK: Updates from outside

    public func update(summary newSummary: ServerSummary) {
        summary = newSummary
    }
}

extension ConnectionPhase {
    var isFailure: Bool {
        if case .failed = self { return true }
        return false
    }
}
