//  AgentAPI.swift
//  ServerOS
//
//  The surface a screen is allowed to depend on.
//
//  Every feature view talks to an `AgentAPI`, never to `AgentClient` directly.
//  Two things fall out of that:
//
//  * The demo environment is a real implementation rather than a pile of `if
//    isDemo` branches scattered through the UI. `DemoAgentClient` conforms to
//    this protocol and the screens cannot tell the difference — which is the
//    only way a demo mode stays honest as the app grows.
//  * Previews and tests get a seam that needs no server, no tunnel and no
//    keychain.
//
//  The method list mirrors the agent's route table
//  (`agent/crates/agent/src/api/mod.rs`) one-for-one. Adding a capability means
//  adding a route *and* a method here, which is the coupling that keeps the two
//  sides from drifting.
//
//  Everything is `async throws` because an actor can only satisfy asynchronous
//  requirements, and both implementations are actors.

import Foundation

// MARK: - Query vocabulary

/// How the process table is ordered. Matches `?sort=` on `/v1/processes`.
public enum ProcessSort: String, Sendable, CaseIterable {
    /// The default, because "what is eating my server" is the question the
    /// screen exists to answer.
    case cpu
    case memory
    case pid
    case name
}

/// The signals the agent is willing to send. Anything else is refused, so the
/// UI offers exactly these.
public enum ProcessSignal: String, Sendable, CaseIterable {
    /// Ask politely. What "Quit" sends.
    case term = "TERM"
    /// Reload configuration, for daemons that use it that way.
    case hup = "HUP"
    /// As if someone pressed ⌃C.
    case int = "INT"
    /// Non-negotiable. What "Force Quit" sends.
    case kill = "KILL"
}

/// A state change on a systemd unit.
public enum ServiceAction: String, Sendable, CaseIterable {
    case start
    case stop
    case restart
    case reload
    case enable
    case disable

    /// The path segment appended to `/v1/services/{unit}/`.
    public var pathComponent: String { rawValue }

    /// Enabling and disabling change what happens at every future boot, which
    /// outlives the person who clicked it — the agent guards both with `admin`.
    public var requiredScopes: [AgentScope] {
        switch self {
        case .start, .stop, .restart, .reload:
            return [.read, .write]
        case .enable, .disable:
            return [.read, .write, .admin]
        }
    }

    /// Present progressive, for the button's in-flight label: "Restarting…".
    public var inProgressLabel: String {
        switch self {
        case .start: return "Starting…"
        case .stop: return "Stopping…"
        case .restart: return "Restarting…"
        case .reload: return "Reloading…"
        case .enable: return "Enabling…"
        case .disable: return "Disabling…"
        }
    }

    /// Past tense, for the confirmation and the activity line: "Restarted nginx".
    public var completedLabel: String {
        switch self {
        case .start: return "Started"
        case .stop: return "Stopped"
        case .restart: return "Restarted"
        case .reload: return "Reloaded"
        case .enable: return "Enabled at boot"
        case .disable: return "Disabled at boot"
        }
    }
}

/// A lifecycle change on a container. Removal is deliberately not here: it is
/// the one container operation with nothing to undo, so it has its own method
/// and its own confirmation.
public enum ContainerAction: String, Sendable, CaseIterable {
    case start
    case stop
    case restart
    case pause
    case unpause

    /// The path segment appended to `/v1/docker/containers/{id}/`.
    public var pathComponent: String { rawValue }

    /// Present progressive, for the button's in-flight label.
    public var inProgressLabel: String {
        switch self {
        case .start: return "Starting…"
        case .stop: return "Stopping…"
        case .restart: return "Restarting…"
        case .pause: return "Pausing…"
        case .unpause: return "Resuming…"
        }
    }

    /// Past tense, for the confirmation and the activity line.
    public var completedLabel: String {
        switch self {
        case .start: return "Started"
        case .stop: return "Stopped"
        case .restart: return "Restarted"
        case .pause: return "Paused"
        case .unpause: return "Resumed"
        }
    }
}

/// Directory ordering. Matches `?sort=` on `/v1/files`; anything the agent does
/// not recognise falls back to `name`, so this list is the whole vocabulary.
public enum FileSort: String, Sendable, CaseIterable {
    case name
    case nameDescending = "name_desc"
    case size
    case sizeDescending = "size_desc"
    case modified
    case modifiedDescending = "modified_desc"
}

// MARK: - Request bodies

/// A new local account. Absent fields let the server's own defaults apply.
public struct NewUser: Encodable, Sendable {
    /// The login name. The only required field.
    public let username: String
    /// The GECOS name, shown instead of the login name wherever there is room.
    public let fullName: String?
    /// Absolute path, e.g. `/bin/bash`.
    public let shell: String?
    /// Supplementary groups. `sudo` here is what makes an administrator.
    public let groups: [String]?
    /// Whether to create a home directory. The agent defaults this to true.
    public let createHome: Bool?
    /// Set at creation through `chpasswd`'s stdin. Never echoed back, never
    /// recorded in the audit feed.
    public let password: String?

    public init(
        username: String,
        fullName: String? = nil,
        shell: String? = nil,
        groups: [String]? = nil,
        createHome: Bool? = nil,
        password: String? = nil
    ) {
        self.username = username
        self.fullName = fullName
        self.shell = shell
        self.groups = groups
        self.createHome = createHome
        self.password = password
    }

    private enum CodingKeys: String, CodingKey {
        case username, shell, groups, password
        case fullName = "full_name"
        case createHome = "create_home"
    }
}

/// Changes to an existing account. Every field is optional and `nil` means
/// "leave it alone" — the synthesised encoder omits nil rather than sending
/// `null`, which the agent would read as a value.
public struct UserChanges: Encodable, Sendable {
    public let fullName: String?
    public let shell: String?
    /// The complete supplementary group list, not a delta.
    public let groups: [String]?
    /// Locking prevents password login without deleting anything.
    public let locked: Bool?
    public let password: String?

    public init(
        fullName: String? = nil,
        shell: String? = nil,
        groups: [String]? = nil,
        locked: Bool? = nil,
        password: String? = nil
    ) {
        self.fullName = fullName
        self.shell = shell
        self.groups = groups
        self.locked = locked
        self.password = password
    }

    private enum CodingKeys: String, CodingKey {
        case shell, groups, locked, password
        case fullName = "full_name"
    }

    /// Whether this would change anything at all. The UI uses it to keep a
    /// "Save" button disabled rather than sending an empty PATCH.
    public var isEmpty: Bool {
        fullName == nil && shell == nil && groups == nil && locked == nil && password == nil
    }
}

// MARK: - Response shapes not covered by AgentModels

/// What came of a delete.
///
/// The agent moves things to a trash directory by default, and says so, which
/// is what lets the app show "Moved to Trash · Undo" honestly rather than
/// claiming a deletion it did not perform.
public struct FileDeletion: Decodable, Sendable {
    /// The path the caller asked about.
    public let path: String
    /// True when the target was moved to trash rather than unlinked.
    public let trashed: Bool
    /// Where it went, when it was trashed. This is the "Undo" target.
    public let restorePath: String?
    public let filesDeleted: Int64?
    public let directoriesDeleted: Int64?
    public let bytesFreed: Int64?

    private enum CodingKeys: String, CodingKey {
        case path, trashed
        case restorePath = "restore_path"
        case filesDeleted = "files_deleted"
        case directoriesDeleted = "directories_deleted"
        case bytesFreed = "bytes_freed"
    }
}

// MARK: - The protocol

/// Everything a ServerOS screen can ask of one server.
///
/// One method per agent route. Collection endpoints return the items rather
/// than the envelope wherever the envelope's extra counts are not needed, so a
/// view model does not have to reach through `.items` on every line.
public protocol AgentAPI: Sendable {

    /// What this server can do, as last reported. `.none` until the first
    /// `health()` or `fetchCapabilities()` answers.
    ///
    /// The server's display name is deliberately not here: error copy is
    /// written where the failure happens, and a screen already knows which
    /// server it is showing.
    var capabilities: AgentCapabilities { get async }

    // MARK: Meta

    /// `GET /v1/health` — liveness, version and capability flags.
    func health() async throws -> AgentHealth

    /// `GET /v1/capabilities` — the capability flags on their own.
    func fetchCapabilities() async throws -> AgentCapabilities

    /// `GET /v1/system` — the facts that do not change while the server is up.
    func system() async throws -> SystemInfo

    /// `GET /v1/metrics` — one sample. The live stream is the better source
    /// when a screen is watching; this is for one-off reads.
    func metrics() async throws -> Metrics

    /// `GET /v1/activity` — the agent's audit feed, newest first.
    /// - Parameter since: The highest event id already held, for incremental polling.
    func activity(limit: Int, since: Int64?) async throws -> [ActivityEvent]

    // MARK: Processes

    /// `GET /v1/processes`
    func processes(sort: ProcessSort, limit: Int, search: String?) async throws -> ProcessList

    /// `POST /v1/processes/{pid}/signal`
    func signalProcess(pid: Int32, signal: ProcessSignal) async throws

    // MARK: Users

    /// `GET /v1/users`
    func users(includeSystem: Bool) async throws -> UserList

    /// `GET /v1/groups`
    func groups() async throws -> [LinuxGroup]

    /// `GET /v1/users/{name}`
    func user(named name: String) async throws -> LinuxUser

    /// `POST /v1/users`
    func createUser(_ request: NewUser) async throws -> LinuxUser

    /// `PATCH /v1/users/{name}`
    func updateUser(named name: String, changes: UserChanges) async throws -> LinuxUser

    /// `DELETE /v1/users/{name}` — admin scope.
    func deleteUser(named name: String, removeHome: Bool) async throws

    /// `GET /v1/users/{name}/keys`
    func sshKeys(forUser name: String) async throws -> [SSHKeyEntry]

    /// `POST /v1/users/{name}/keys`
    func addSSHKey(forUser name: String, publicKey: String) async throws

    /// `DELETE /v1/users/{name}/keys/{fingerprint}`
    func removeSSHKey(forUser name: String, fingerprint: String) async throws

    // MARK: Services

    /// `GET /v1/services` — `type` narrows to one unit suffix, e.g. `.timer`.
    func services(type: String?) async throws -> [ServiceUnit]

    /// `GET /v1/services/{unit}`
    func service(unit: String) async throws -> ServiceUnitDetail

    /// `POST /v1/services/{unit}/{action}`
    func performServiceAction(_ action: ServiceAction, unit: String) async throws

    // MARK: Docker

    /// `GET /v1/docker`
    func dockerInfo() async throws -> DockerInfo

    /// `GET /v1/docker/containers`
    /// - Parameters:
    ///   - all: Include stopped containers.
    ///   - stats: Sample live CPU and memory. Costs a round trip per container.
    func containers(all: Bool, stats: Bool) async throws -> DockerContainerList

    /// `GET /v1/docker/containers/{id}`
    /// - Parameter revealEnvironment: Unmask secret-looking environment values.
    ///   Requires admin scope, is audited on the server, and is ignored rather
    ///   than refused for a caller without it.
    func container(id: String, revealEnvironment: Bool) async throws -> DockerContainerDetail

    /// `GET /v1/docker/containers/{id}/stats`
    func containerStats(id: String) async throws -> DockerStats

    /// `GET /v1/docker/containers/{id}/logs`
    func containerLogs(id: String, tail: Int, since: Int64?, timestamps: Bool) async throws -> [LogLine]

    /// `POST /v1/docker/containers/{id}/{action}`
    /// - Parameter graceSeconds: Seconds before SIGKILL, for stop and restart.
    func performContainerAction(_ action: ContainerAction, id: String, graceSeconds: Int?) async throws

    /// `DELETE /v1/docker/containers/{id}` — admin scope.
    func removeContainer(id: String, force: Bool, removeVolumes: Bool) async throws

    /// `GET /v1/docker/images`
    func images() async throws -> [DockerImage]

    /// `GET /v1/docker/volumes`
    func volumes() async throws -> [DockerVolume]

    /// `GET /v1/docker/networks`
    func networks() async throws -> [DockerNetwork]

    // MARK: Projects

    /// `GET /v1/projects`
    func projects() async throws -> ProjectList

    /// `GET /v1/projects/{name}`
    func project(named name: String) async throws -> Project

    // MARK: Databases

    /// `GET /v1/databases`
    func databaseInstances() async throws -> [DatabaseInstance]

    /// `GET /v1/databases/postgres`
    func postgresOverview() async throws -> PostgresOverview

    /// `GET /v1/databases/postgres/databases`
    func postgresDatabases() async throws -> [PostgresDatabase]

    /// `GET /v1/databases/postgres/tables`
    func postgresTables(database: String?) async throws -> [PostgresTable]

    /// `GET /v1/databases/postgres/connections`
    /// - Parameter includeQueryText: Include running statement text. Admin
    ///   scope; the agent omits it for anyone else rather than failing.
    func postgresConnections(includeQueryText: Bool) async throws -> [PostgresConnection]

    /// `GET /v1/databases/postgres/roles`
    func postgresRoles() async throws -> [PostgresRole]

    // MARK: Logs

    /// `GET /v1/logs/file`
    func fileLog(path: String, lines: Int, since: Int64?, filter: String?, isRegex: Bool) async throws -> LogBatch

    /// `GET /v1/logs/journal`
    func journal(unit: String?, lines: Int, since: Int64?, filter: String?, isRegex: Bool) async throws -> LogBatch

    // MARK: Files

    /// `GET /v1/files`
    func listDirectory(path: String, showHidden: Bool, sort: FileSort, limit: Int, offset: Int) async throws -> DirectoryListing

    /// `GET /v1/files/stat`
    func stat(path: String) async throws -> FileEntry

    /// `GET /v1/files/read` — text only; a binary file is refused with a
    /// sentence saying so, and the app offers a download instead.
    func readTextFile(path: String) async throws -> TextFileContents

    /// `GET /v1/files/download` — the raw bytes.
    func downloadFile(path: String) async throws -> Data

    /// `PUT /v1/files/write`
    func writeTextFile(path: String, contents: String) async throws -> FileEntry

    /// `POST /v1/files/directory`
    func createDirectory(path: String) async throws -> FileEntry

    /// `POST /v1/files/rename` — rename or move.
    func move(from: String, to: String) async throws -> FileEntry

    /// `POST /v1/files/chmod` — admin scope.
    /// - Parameter mode: Octal, as text: `"0640"`.
    func changeMode(path: String, mode: String) async throws -> FileEntry

    /// `DELETE /v1/files`
    func deleteFile(path: String, recursive: Bool) async throws -> FileDeletion

    /// `POST /v1/files/upload`
    func uploadFile(path: String, contents: Data, overwrite: Bool) async throws -> FileEntry
}

// MARK: - Shorthands

/// Defaults for the calls a screen makes constantly.
///
/// A protocol requirement cannot carry a default argument, so the shorthands
/// live here instead. The concrete types still declare their own defaults, so
/// this only matters when calling through the protocol.
extension AgentAPI {

    /// The most recent activity, for the dashboard feed.
    public func activity(limit: Int = 50) async throws -> [ActivityEvent] {
        try await activity(limit: limit, since: nil)
    }

    /// The process table as the Processes screen opens it.
    public func processes() async throws -> ProcessList {
        try await processes(sort: .cpu, limit: 100, search: nil)
    }

    /// The process table, sorted and capped, with no search term.
    public func processes(sort: ProcessSort, limit: Int) async throws -> ProcessList {
        try await processes(sort: sort, limit: limit, search: nil)
    }

    /// Every account, system ones included — the agent's own default.
    public func users() async throws -> UserList {
        try await users(includeSystem: true)
    }

    /// Every service worth showing a person.
    public func services() async throws -> [ServiceUnit] {
        try await services(type: nil)
    }

    /// Every container, running or not, without the cost of live stats.
    public func containers() async throws -> DockerContainerList {
        try await containers(all: true, stats: false)
    }

    /// Containers without the per-container stats round trips.
    public func containers(all: Bool) async throws -> DockerContainerList {
        try await containers(all: all, stats: false)
    }

    /// One container, with secret-looking environment values left masked.
    public func container(id: String) async throws -> DockerContainerDetail {
        try await container(id: id, revealEnvironment: false)
    }

    /// A container's recent output.
    public func containerLogs(id: String, tail: Int = 200) async throws -> [LogLine] {
        try await containerLogs(id: id, tail: tail, since: nil, timestamps: false)
    }

    /// A directory as the Files screen opens it.
    public func listDirectory(path: String) async throws -> DirectoryListing {
        try await listDirectory(path: path, showHidden: false, sort: .name, limit: 0, offset: 0)
    }

    /// A directory, name-sorted, with the whole listing.
    public func listDirectory(path: String, showHidden: Bool) async throws -> DirectoryListing {
        try await listDirectory(path: path, showHidden: showHidden, sort: .name, limit: 0, offset: 0)
    }
}
