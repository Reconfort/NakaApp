//  AppModel.swift
//  ServerOS
//
//  The application's root state: which servers exist, which are connected, and
//  what the estate looks like as a whole.
//
//  It owns exactly one `ServerSession` per server and hands them out. Nothing
//  else in the app is allowed to create a session, which is what keeps "one
//  connection per server" true no matter how many windows or screens are open.

import Foundation
import Observation
import SwiftData
import SwiftUI

@MainActor
@Observable
public final class AppModel {

    // MARK: State

    public private(set) var servers: [ServerSummary] = []
    public private(set) var sessions: [String: ServerSession] = [:]
    public private(set) var isLoading = true
    public private(set) var loadError: ServerOSError?

    /// Set when the user has no real servers and is trying the product out.
    /// Demo servers are always visibly labelled; see `DemoData.swift`.
    public var isShowingDemo: Bool {
        servers.contains(where: \.isDemo)
    }

    public var hasRealServers: Bool {
        servers.contains(where: { !$0.isDemo })
    }

    // MARK: Dependencies

    private let store: ServerStore
    private let credentials: CredentialStore
    private let deviceName: String
    /// One tunnel per server, kept so the Terminal can reuse the connection.
    private var tunnels: [String: ServerTunnel] = [:]

    // MARK: Init

    public init(store: ServerStore, credentials: CredentialStore = CredentialStore()) {
        self.store = store
        self.credentials = credentials
        self.deviceName = AgentTokenMinter.defaultSubject()
    }

    /// Build the standard production model, with an on-disk SwiftData store.
    public static func makeDefault() throws -> AppModel {
        let container = try ServerStore.makeContainer()
        return AppModel(store: ServerStore(container: container))
    }

    // MARK: Loading

    public func load() async {
        isLoading = true
        defer { isLoading = false }
        do {
            servers = try await store.all()
            loadError = nil
        } catch {
            loadError = ServerOSError(
                code: "store_unavailable",
                headline: "ServerOS couldn't open its server list.",
                causes: ["The app's local database may be damaged.",
                         "Quitting and reopening ServerOS usually fixes this."],
                technical: String(describing: error),
                isRetryable: true
            )
        }
    }

    // MARK: Sessions

    /// The session for a server, creating it on first use.
    public func session(for serverID: String) -> ServerSession? {
        if let existing = sessions[serverID] { return existing }
        guard let summary = servers.first(where: { $0.id == serverID }) else { return nil }

        let session: ServerSession
        if summary.isDemo {
            guard let client = DemoEnvironment.shared.client(for: serverID) else { return nil }
            session = ServerSession(demo: summary, client: client)
        } else {
            guard let connection = makeConnection(for: summary) else { return nil }
            session = ServerSession(summary: summary, connection: connection)
        }

        sessions[serverID] = session
        return session
    }

    private func makeConnection(for summary: ServerSummary) -> ServerConnection? {
        // The tunnel reads the credential itself, on first use, so a server
        // whose Keychain item has gone missing produces a clear error at
        // connect time rather than a silent absence at list time.
        let tunnel = ServerTunnel(summary: summary, credentials: credentials)
        tunnels[summary.id] = tunnel
        return ServerConnection(
            serverID: summary.id,
            serverName: summary.name,
            tunnel: tunnel,
            credentials: credentials
        )
    }

    /// The live SSH tunnel for a server, if one is open. The Terminal screen
    /// borrows it rather than opening a second SSH connection.
    public func tunnel(for serverID: String) -> ServerTunnel? {
        tunnels[serverID]
    }

    /// Connect every server that is not already connecting. Called at launch.
    public func connectAll() {
        for summary in servers {
            session(for: summary.id)?.connect()
        }
    }

    public func disconnectAll() {
        for session in sessions.values {
            session.disconnect()
        }
    }

    // MARK: Fleet rollup

    /// The health of every server, in sidebar order. Drives the Overview.
    public var fleetHealth: [(summary: ServerSummary, health: ServerHealth)] {
        servers.map { summary in
            (summary, sessions[summary.id]?.health ?? .unknown)
        }
    }

    public var fleetSummaryLine: String {
        HealthEvaluator.fleetSummary(fleetHealth.map(\.health))
    }

    public var serversNeedingAttention: [ServerSummary] {
        fleetHealth.filter { $0.health.state >= .warning }.map(\.summary)
    }

    /// Recent activity across every connected server, newest first.
    public func recentActivity(limit: Int = 30) -> [(server: ServerSummary, event: ActivityEvent)] {
        var combined: [(ServerSummary, ActivityEvent)] = []
        for summary in servers {
            guard let session = sessions[summary.id] else { continue }
            for event in session.activity.prefix(limit) {
                combined.append((summary, event))
            }
        }
        return combined.sorted { $0.1.at > $1.1.at }.prefix(limit).map { ($0.0, $0.1) }
    }

    // MARK: Mutating the server list

    public func add(_ summary: ServerSummary, credential: ServerCredential) async throws {
        try await credentials.save(credential)
        try await store.upsert(summary)
        servers = try await store.all()
        session(for: summary.id)?.connect()
    }

    public func rename(id: String, to newName: String) async throws {
        guard var summary = servers.first(where: { $0.id == id }) else { return }
        summary = ServerSummary(
            id: summary.id, name: newName, hostname: summary.hostname,
            sshPort: summary.sshPort, sshUsername: summary.sshUsername,
            agentPort: summary.agentPort, osPretty: summary.osPretty, arch: summary.arch,
            lastSeenAt: summary.lastSeenAt, addedAt: summary.addedAt, tags: summary.tags,
            sortIndex: summary.sortIndex, isDemo: summary.isDemo
        )
        try await store.upsert(summary)
        servers = try await store.all()
        sessions[id]?.update(summary: summary)
    }

    /// Remove a server from ServerOS.
    ///
    /// Deliberately does NOT uninstall the agent from the server: the user may
    /// be moving management to another Mac, and silently tearing down a running
    /// service on a production box because someone tidied a list would be
    /// indefensible. The UI says so in the confirmation.
    public func remove(id: String) async throws {
        sessions[id]?.disconnect()
        sessions.removeValue(forKey: id)
        if let tunnel = tunnels.removeValue(forKey: id) { await tunnel.close() }
        try await credentials.delete(serverID: id)
        try await store.delete(id: id)
        servers = try await store.all()
    }

    public func reorder(_ orderedIDs: [String]) async throws {
        try await store.reorder(orderedIDs: orderedIDs)
        servers = try await store.all()
    }

    // MARK: Demo

    /// Populate the demo servers, for someone evaluating ServerOS with no
    /// infrastructure to hand.
    public func enableDemoMode() async throws {
        for summary in DemoEnvironment.shared.servers {
            try await store.upsert(summary)
        }
        servers = try await store.all()
        connectAll()
    }

    public func disableDemoMode() async throws {
        for summary in servers where summary.isDemo {
            sessions[summary.id]?.disconnect()
            sessions.removeValue(forKey: summary.id)
            try await store.delete(id: summary.id)
        }
        servers = try await store.all()
    }

    // MARK: Command palette

    /// Everything ⌘K can reach right now.
    ///
    /// Built from live state rather than a static list, so "Restart estatify-api"
    /// is offered exactly when that container exists.
    public func paletteItems(currentServerID: String?) -> [PaletteItem] {
        var items: [PaletteItem] = []

        for section in FleetSection.allCases {
            items.append(PaletteItem(
                id: "nav:\(section.rawValue)",
                kind: .navigation,
                title: section.title,
                subtitle: nil,
                searchTerms: ["go to", "open"]
            ))
        }

        for summary in servers {
            items.append(PaletteItem(
                id: "server:\(summary.id)",
                kind: .server,
                title: summary.name,
                subtitle: summary.hostname,
                searchTerms: ["open", "server", summary.osPretty].compactMap { $0 }
            ))
        }

        // Sections and resources for the server the user is already inside get
        // offered without a prefix; other servers' resources are namespaced so
        // "restart nginx" does not silently act on the wrong machine.
        if let currentServerID, let session = sessions[currentServerID] {
            for section in ServerSection.allCases where section.isAvailable(given: session.capabilities) {
                items.append(PaletteItem(
                    id: "section:\(currentServerID):\(section.rawValue)",
                    kind: .navigation,
                    title: section.title,
                    subtitle: session.name,
                    searchTerms: ["go to", "open"]
                ))
            }

            for container in session.containers {
                items.append(PaletteItem(
                    id: "container:\(currentServerID):\(container.id)",
                    kind: .container,
                    title: container.displayName,
                    subtitle: container.image,
                    searchTerms: ["container", "docker", container.name, session.name]
                ))
                if container.isRunning {
                    items.append(PaletteItem(
                        id: "action:restart-container:\(currentServerID):\(container.id)",
                        kind: .action,
                        title: "Restart \(container.displayName)",
                        subtitle: "Container on \(session.name)",
                        searchTerms: ["restart", "container", "docker"]
                    ))
                }
            }

            for service in session.services {
                items.append(PaletteItem(
                    id: "service:\(currentServerID):\(service.name)",
                    kind: .service,
                    title: service.displayName,
                    subtitle: service.description,
                    searchTerms: ["service", "systemd", service.name, session.name]
                ))
                if service.canRestart {
                    items.append(PaletteItem(
                        id: "action:restart-service:\(currentServerID):\(service.name)",
                        kind: .action,
                        title: "Restart \(service.displayName)",
                        subtitle: "Service on \(session.name)",
                        searchTerms: ["restart", "service", "systemd"]
                    ))
                }
            }
        }

        items.append(PaletteItem(
            id: "action:add-server",
            kind: .action,
            title: "Add Server",
            subtitle: "Connect a new Linux server",
            searchTerms: ["new", "connect", "setup"]
        ))

        return items
    }
}
