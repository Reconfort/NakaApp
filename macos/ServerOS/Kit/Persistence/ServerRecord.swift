//  ServerRecord.swift
//  ServerOS
//
//  The list of servers, as the app remembers it between launches.
//
//  ──────────────────────────────────────────────────────────────────────────
//  NOTHING SECRET MAY BE ADDED TO THIS MODEL.
//
//  No agent secret, no SSH private key, no password, no bearer token, no
//  passphrase, no host key the user has not confirmed. Not as a `Data`, not
//  base64-encoded, not "temporarily".
//
//  SwiftData persists to an ordinary SQLite file inside the app's container. It
//  is not encrypted. Anything written here is readable by any process that can
//  read the file, survives in Time Machine snapshots, and lands in an iCloud or
//  Finder backup of the Mac. A `ServerRecord` is therefore deliberately
//  boring: a hostname, a port, a name, when it was last seen.
//
//  Secrets live in `ServerCredential`, which lives only in the Keychain. The
//  join between the two is `id`, which is also the Keychain account name — so
//  the encrypted half and the unencrypted half are linked by an identifier
//  rather than by copying anything across.
//  ──────────────────────────────────────────────────────────────────────────

import Foundation
import SwiftData

/// One server, as the app's local database knows it.
///
/// Everything here is either public-by-nature (a hostname, a port) or purely
/// cosmetic (a name, a sort position). See the file comment.
@Model
public final class ServerRecord {

    /// The agent's server id, e.g. `srv_563016eaa2ea5baa`. Also the Keychain
    /// account name for this server's credential, which is the only link
    /// between the two halves.
    @Attribute(.unique) public var id: String

    /// What the user calls this server. Theirs to change; never sent anywhere.
    public var name: String

    /// Hostname or address used for SSH.
    public var hostname: String

    public var sshPort: Int

    /// The account ServerOS logs in as.
    public var sshUsername: String

    /// The port the agent listens on, on the server side of the tunnel. A copy
    /// of the value in the credential, kept here so the server list can show
    /// "agent on :8723" without unlocking the Keychain.
    public var agentPort: Int

    /// `Ubuntu 24.04.4 LTS`, cached from the last `/v1/system`. Optional
    /// because it is unknown until the first successful connection.
    public var osPretty: String?

    /// `x86_64`, `aarch64`. Cached the same way.
    public var arch: String?

    /// When the agent last answered. Drives the "Last seen 4 minutes ago"
    /// subtitle and the offline threshold in `HealthEvaluator`.
    public var lastSeenAt: Date?

    /// When this server was added to ServerOS.
    public var addedAt: Date

    /// Free-form labels: `production`, `client-work`, `eu-west`.
    public var tags: [String]

    /// Position in the sidebar. Explicit rather than derived, because the order
    /// a person arranges their servers into is information.
    public var sortIndex: Int

    /// True for the built-in demo servers.
    ///
    /// The UI is required to badge these permanently. Demo data must never be
    /// mistakable for real infrastructure — see `DemoData.swift`.
    public var isDemo: Bool

    public init(
        id: String,
        name: String,
        hostname: String,
        sshPort: Int = 22,
        sshUsername: String,
        agentPort: Int = 8723,
        osPretty: String? = nil,
        arch: String? = nil,
        lastSeenAt: Date? = nil,
        addedAt: Date = Date(),
        tags: [String] = [],
        sortIndex: Int = 0,
        isDemo: Bool = false
    ) {
        self.id = id
        self.name = name
        self.hostname = hostname
        self.sshPort = sshPort
        self.sshUsername = sshUsername
        self.agentPort = agentPort
        self.osPretty = osPretty
        self.arch = arch
        self.lastSeenAt = lastSeenAt
        self.addedAt = addedAt
        self.tags = tags
        self.sortIndex = sortIndex
        self.isDemo = isDemo
    }
}

// MARK: - A value that can leave the store

/// A snapshot of a `ServerRecord`, safe to hand to another actor.
///
/// SwiftData models are reference types bound to the context that fetched them
/// and are not `Sendable`; passing one across an actor boundary is a data race
/// waiting to be observed. Everything outside `ServerStore` therefore works
/// with this instead — which also means a view holding a summary cannot
/// accidentally mutate the database by assigning to a property.
public struct ServerSummary: Sendable, Identifiable, Equatable, Hashable {
    public let id: String
    public let name: String
    public let hostname: String
    public let sshPort: Int
    public let sshUsername: String
    public let agentPort: Int
    public let osPretty: String?
    public let arch: String?
    public let lastSeenAt: Date?
    public let addedAt: Date
    public let tags: [String]
    public let sortIndex: Int
    public let isDemo: Bool

    public init(
        id: String,
        name: String,
        hostname: String,
        sshPort: Int = 22,
        sshUsername: String,
        agentPort: Int = 8723,
        osPretty: String? = nil,
        arch: String? = nil,
        lastSeenAt: Date? = nil,
        addedAt: Date = Date(),
        tags: [String] = [],
        sortIndex: Int = 0,
        isDemo: Bool = false
    ) {
        self.id = id
        self.name = name
        self.hostname = hostname
        self.sshPort = sshPort
        self.sshUsername = sshUsername
        self.agentPort = agentPort
        self.osPretty = osPretty
        self.arch = arch
        self.lastSeenAt = lastSeenAt
        self.addedAt = addedAt
        self.tags = tags
        self.sortIndex = sortIndex
        self.isDemo = isDemo
    }

    /// `user@host` or `user@host:port` — the subtitle under a server's name.
    public var describedEndpoint: String {
        sshPort == 22 ? "\(sshUsername)@\(hostname)" : "\(sshUsername)@\(hostname):\(sshPort)"
    }
}

extension ServerSummary {
    /// Snapshot a stored record.
    init(record: ServerRecord) {
        self.init(
            id: record.id,
            name: record.name,
            hostname: record.hostname,
            sshPort: record.sshPort,
            sshUsername: record.sshUsername,
            agentPort: record.agentPort,
            osPretty: record.osPretty,
            arch: record.arch,
            lastSeenAt: record.lastSeenAt,
            addedAt: record.addedAt,
            tags: record.tags,
            sortIndex: record.sortIndex,
            isDemo: record.isDemo
        )
    }
}

// MARK: - Store

/// Reads and writes the server list.
///
/// An actor so SwiftData work stays off the main thread and so the `ModelContext`
/// it uses is never touched from two places at once. Every method returns
/// `ServerSummary` values rather than models, so nothing non-`Sendable` escapes.
public actor ServerStore {

    private let container: ModelContainer

    /// - Parameter container: Usually the app's one container. Tests pass an
    ///   in-memory one from ``makeContainer(inMemory:)``.
    public init(container: ModelContainer) {
        self.container = container
    }

    /// Build a container for the server list.
    ///
    /// - Parameter inMemory: True for tests and previews — nothing touches disk.
    public static func makeContainer(inMemory: Bool = false) throws -> ModelContainer {
        let schema = Schema([ServerRecord.self])
        let configuration = ModelConfiguration(schema: schema, isStoredInMemoryOnly: inMemory)
        return try ModelContainer(for: schema, configurations: [configuration])
    }

    /// Every server, in sidebar order.
    public func all() throws -> [ServerSummary] {
        try snapshots()
    }

    /// One server, or nil.
    public func server(id: String) throws -> ServerSummary? {
        try snapshots().first { $0.id == id }
    }

    /// Insert a server, or overwrite the one with the same id.
    ///
    /// Upsert rather than insert because the only two ways a record appears are
    /// "the user added this server" and "setup ran again for a server that was
    /// already here" — and the second must not produce a duplicate row.
    public func upsert(_ summary: ServerSummary) throws {
        let context = ModelContext(container)
        let existing = try context.fetch(FetchDescriptor<ServerRecord>())
        if let record = existing.first(where: { $0.id == summary.id }) {
            record.name = summary.name
            record.hostname = summary.hostname
            record.sshPort = summary.sshPort
            record.sshUsername = summary.sshUsername
            record.agentPort = summary.agentPort
            record.osPretty = summary.osPretty
            record.arch = summary.arch
            record.lastSeenAt = summary.lastSeenAt
            record.tags = summary.tags
            record.sortIndex = summary.sortIndex
            record.isDemo = summary.isDemo
        } else {
            context.insert(ServerRecord(
                id: summary.id,
                name: summary.name,
                hostname: summary.hostname,
                sshPort: summary.sshPort,
                sshUsername: summary.sshUsername,
                agentPort: summary.agentPort,
                osPretty: summary.osPretty,
                arch: summary.arch,
                lastSeenAt: summary.lastSeenAt,
                addedAt: summary.addedAt,
                tags: summary.tags,
                sortIndex: summary.sortIndex,
                isDemo: summary.isDemo
            ))
        }
        try context.save()
    }

    /// Remove a server from the list.
    ///
    /// Deliberately does *not* touch the Keychain: forgetting a server and
    /// destroying its credential are two decisions, and the caller makes both
    /// explicitly.
    public func delete(id: String) throws {
        let context = ModelContext(container)
        let records = try context.fetch(FetchDescriptor<ServerRecord>())
        for record in records where record.id == id {
            context.delete(record)
        }
        try context.save()
    }

    /// Apply a new sidebar order.
    ///
    /// - Parameter orderedIDs: Server ids, front to back. Any server not named
    ///   keeps its position after the ones that are, so a reorder of a filtered
    ///   list cannot silently shuffle the servers that were not on screen.
    public func reorder(orderedIDs: [String]) throws {
        let context = ModelContext(container)
        let records = try context.fetch(FetchDescriptor<ServerRecord>())

        var position: [String: Int] = [:]
        for (index, id) in orderedIDs.enumerated() {
            position[id] = index
        }
        let tail = orderedIDs.count
        for record in records {
            if let index = position[record.id] {
                record.sortIndex = index
            } else {
                record.sortIndex = tail + record.sortIndex
            }
        }
        try context.save()
    }

    /// Record that the agent answered, for the "Last seen" subtitle.
    public func markSeen(id: String, at date: Date = Date()) throws {
        let context = ModelContext(container)
        let records = try context.fetch(FetchDescriptor<ServerRecord>())
        guard let record = records.first(where: { $0.id == id }) else { return }
        record.lastSeenAt = date
        try context.save()
    }

    /// Cache the facts the server reported about itself.
    public func updateSystemFacts(id: String, osPretty: String?, arch: String?) throws {
        let context = ModelContext(container)
        let records = try context.fetch(FetchDescriptor<ServerRecord>())
        guard let record = records.first(where: { $0.id == id }) else { return }
        record.osPretty = osPretty
        record.arch = arch
        try context.save()
    }

    /// Sorting happens in Swift rather than in the fetch descriptor.
    ///
    /// The list is a handful of rows — an in-memory sort is free, and it keeps
    /// the ordering rule (position, then name) in one readable place instead of
    /// split between a descriptor and the view.
    private func snapshots() throws -> [ServerSummary] {
        let context = ModelContext(container)
        let records = try context.fetch(FetchDescriptor<ServerRecord>())
        let summaries = records.map { ServerSummary(record: $0) }
        return summaries.sorted { left, right in
            if left.sortIndex != right.sortIndex {
                return left.sortIndex < right.sortIndex
            }
            return left.name.localizedStandardCompare(right.name) == .orderedAscending
        }
    }
}
