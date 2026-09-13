//  AgentModels.swift
//  ServerOS
//
//  The wire contract with the ServerOS agent.
//
//  Every type here is decoded from a real agent response. The JSON shapes in
//  `macos/fixtures/` were captured from a running agent and are decoded by the
//  test suite, so a change on either side fails a test rather than a user's
//  screen.
//
//  Two conventions, both deliberate:
//
//  * Every type spells out its `CodingKeys` rather than relying on
//    `.convertFromSnakeCase`. The automatic strategy also rewrites the keys of
//    dictionaries, which would quietly mangle Docker labels like
//    `com.docker.compose.project`. Explicit keys cost a few lines and remove a
//    whole class of silent bug.
//  * Optionality mirrors the agent exactly. The agent omits a field when it
//    genuinely cannot know the answer — disk usage without `statvfs`, a
//    container's CPU before stats are sampled, `last_login` — and the UI is
//    expected to say "unknown" rather than "0". A non-optional here would turn
//    missing data into a lie.

import Foundation

// MARK: - Envelope

/// Collections always arrive wrapped so they can grow a cursor later without
/// breaking every client.
public struct AgentCollection<Item: Decodable & Sendable>: Decodable, Sendable {
    public let total: Int
    public let items: [Item]

    private enum CodingKeys: String, CodingKey {
        case total, items
    }
}

// MARK: - Health & capabilities

public struct AgentHealth: Decodable, Sendable {
    public let status: String
    public let agentVersion: String
    public let apiVersion: String
    public let serverID: String
    public let uptimeSeconds: Int
    public let capabilities: AgentCapabilities

    private enum CodingKeys: String, CodingKey {
        case status
        case agentVersion = "agent_version"
        case apiVersion = "api_version"
        case serverID = "server_id"
        case uptimeSeconds = "uptime_seconds"
        case capabilities
    }

    public var isOK: Bool { status == "ok" }
}

/// What this particular server can do.
///
/// The sidebar reads this directly: a server without Docker does not show a
/// Docker section at all, rather than showing one that fails when opened.
public struct AgentCapabilities: Decodable, Sendable, Equatable {
    public let metrics: Bool
    public let processes: Bool
    public let users: Bool
    public let files: Bool
    public let logs: Bool
    public let docker: Bool
    public let dockerAPIVersion: String?
    public let services: Bool
    public let serviceBackend: String?
    public let journal: Bool
    public let postgres: Bool

    private enum CodingKeys: String, CodingKey {
        case metrics, processes, users, files, logs, docker, services, journal, postgres
        case dockerAPIVersion = "docker_api_version"
        case serviceBackend = "service_backend"
    }

    /// Everything off — what the app assumes before it has heard from a server.
    public static let none = AgentCapabilities(
        metrics: false, processes: false, users: false, files: false, logs: false,
        docker: false, dockerAPIVersion: nil, services: false, serviceBackend: nil,
        journal: false, postgres: false
    )

    public init(
        metrics: Bool, processes: Bool, users: Bool, files: Bool, logs: Bool,
        docker: Bool, dockerAPIVersion: String?, services: Bool, serviceBackend: String?,
        journal: Bool, postgres: Bool
    ) {
        self.metrics = metrics
        self.processes = processes
        self.users = users
        self.files = files
        self.logs = logs
        self.docker = docker
        self.dockerAPIVersion = dockerAPIVersion
        self.services = services
        self.serviceBackend = serviceBackend
        self.journal = journal
        self.postgres = postgres
    }
}

// MARK: - System

public struct SystemInfo: Decodable, Sendable {
    public let hostname: String
    public let os: OSInfo
    public let kernel: String
    public let architecture: String
    public let cpu: CPUInfo
    public let memoryTotalBytes: Int64
    public let swapTotalBytes: Int64
    public let bootTime: Int64
    public let uptimeSeconds: Int64
    public let virtualization: String?
    public let loadAverage: LoadAverage
    public let agent: AgentInfo

    private enum CodingKeys: String, CodingKey {
        case hostname, os, kernel, architecture, cpu, virtualization, agent
        case memoryTotalBytes = "memory_total_bytes"
        case swapTotalBytes = "swap_total_bytes"
        case bootTime = "boot_time"
        case uptimeSeconds = "uptime_seconds"
        case loadAverage = "load_average"
    }

    public struct OSInfo: Decodable, Sendable {
        public let name: String
        public let version: String
        public let id: String
        public let pretty: String
    }

    public struct CPUInfo: Decodable, Sendable {
        public let model: String
        public let cores: Int
        public let threads: Int
        public let mhz: Double?
    }

    public struct AgentInfo: Decodable, Sendable {
        public let version: String
        public let uptimeSeconds: Int64
        public let startedAt: Int64
        public let enrolled: Bool

        private enum CodingKeys: String, CodingKey {
            case version, enrolled
            case uptimeSeconds = "uptime_seconds"
            case startedAt = "started_at"
        }
    }
}

public struct LoadAverage: Decodable, Sendable, Equatable {
    public let one: Double
    public let five: Double
    public let fifteen: Double
}

// MARK: - Metrics

public struct Metrics: Decodable, Sendable {
    public let sampledAt: Int64
    public let cpu: CPUMetrics
    public let memory: MemoryMetrics
    public let disk: DiskMetrics
    public let network: NetworkMetrics
    /// True until the sampler has two consecutive samples. Rates read zero
    /// until then, and the UI shows a placeholder instead of a confident 0%.
    public let warmingUp: Bool?

    private enum CodingKeys: String, CodingKey {
        case cpu, memory, disk, network
        case sampledAt = "sampled_at"
        case warmingUp = "warming_up"
    }

    public var isWarmingUp: Bool { warmingUp ?? false }
    public var sampledDate: Date { Date(timeIntervalSince1970: TimeInterval(sampledAt)) }
}

public struct CPUMetrics: Decodable, Sendable {
    public let usagePercent: Double
    public let userPercent: Double
    public let systemPercent: Double
    public let iowaitPercent: Double
    public let perCore: [Double]
    public let loadAverage: LoadAverage
    public let coreCount: Int

    private enum CodingKeys: String, CodingKey {
        case usagePercent = "usage_percent"
        case userPercent = "user_percent"
        case systemPercent = "system_percent"
        case iowaitPercent = "iowait_percent"
        case perCore = "per_core"
        case loadAverage = "load_average"
        case coreCount = "core_count"
    }
}

public struct MemoryMetrics: Decodable, Sendable {
    public let totalBytes: Int64
    public let usedBytes: Int64
    public let availableBytes: Int64
    public let cachedBytes: Int64
    public let buffersBytes: Int64
    public let usagePercent: Double
    public let swapTotalBytes: Int64
    public let swapUsedBytes: Int64
    public let swapUsagePercent: Double

    private enum CodingKeys: String, CodingKey {
        case totalBytes = "total_bytes"
        case usedBytes = "used_bytes"
        case availableBytes = "available_bytes"
        case cachedBytes = "cached_bytes"
        case buffersBytes = "buffers_bytes"
        case usagePercent = "usage_percent"
        case swapTotalBytes = "swap_total_bytes"
        case swapUsedBytes = "swap_used_bytes"
        case swapUsagePercent = "swap_usage_percent"
    }

    public var hasSwap: Bool { swapTotalBytes > 0 }
}

public struct DiskMetrics: Decodable, Sendable {
    public let totalBytes: Int64?
    public let usedBytes: Int64?
    public let availableBytes: Int64?
    public let usagePercent: Double?
    public let filesystems: [Filesystem]

    private enum CodingKeys: String, CodingKey {
        case filesystems
        case totalBytes = "total_bytes"
        case usedBytes = "used_bytes"
        case availableBytes = "available_bytes"
        case usagePercent = "usage_percent"
    }

    public struct Filesystem: Decodable, Sendable, Identifiable {
        public let device: String
        public let mountPoint: String
        public let fstype: String
        public let totalBytes: Int64?
        public let usedBytes: Int64?
        public let availableBytes: Int64?
        public let usagePercent: Double?
        public let inodesTotal: Int64?
        public let inodesUsed: Int64?

        public var id: String { mountPoint }

        private enum CodingKeys: String, CodingKey {
            case device, fstype
            case mountPoint = "mount_point"
            case totalBytes = "total_bytes"
            case usedBytes = "used_bytes"
            case availableBytes = "available_bytes"
            case usagePercent = "usage_percent"
            case inodesTotal = "inodes_total"
            case inodesUsed = "inodes_used"
        }
    }
}

public struct NetworkMetrics: Decodable, Sendable {
    public let rxBytesTotal: Int64
    public let txBytesTotal: Int64
    public let rxBytesPerSec: Double
    public let txBytesPerSec: Double
    public let interfaces: [Interface]

    private enum CodingKeys: String, CodingKey {
        case interfaces
        case rxBytesTotal = "rx_bytes_total"
        case txBytesTotal = "tx_bytes_total"
        case rxBytesPerSec = "rx_bytes_per_sec"
        case txBytesPerSec = "tx_bytes_per_sec"
    }

    public struct Interface: Decodable, Sendable, Identifiable {
        public let name: String
        public let rxBytes: Int64
        public let txBytes: Int64
        public let rxBytesPerSec: Double
        public let txBytesPerSec: Double
        public let rxErrors: Int64
        public let txErrors: Int64
        public let up: Bool

        public var id: String { name }

        private enum CodingKeys: String, CodingKey {
            case name, up
            case rxBytes = "rx_bytes"
            case txBytes = "tx_bytes"
            case rxBytesPerSec = "rx_bytes_per_sec"
            case txBytesPerSec = "tx_bytes_per_sec"
            case rxErrors = "rx_errors"
            case txErrors = "tx_errors"
        }
    }
}

// MARK: - Processes

/// The process list echoes the query it answered, so a stale response arriving
/// after the user changed the sort can be recognised and dropped.
public struct ProcessList: Decodable, Sendable {
    public let total: Int
    public let items: [ProcessInfo]
    public let sort: String?
    public let limit: Int?
}

public struct ProcessInfo: Decodable, Sendable, Identifiable {
    public let pid: Int32
    public let ppid: Int32
    public let name: String
    public let command: String
    public let user: String?
    public let uid: UInt32
    public let state: String
    public let cpuPercent: Double
    public let memoryBytes: Int64
    public let memoryPercent: Double
    public let threads: Int
    public let startedAt: Int64?

    public var id: Int32 { pid }

    private enum CodingKeys: String, CodingKey {
        case pid, ppid, name, command, user, uid, state, threads
        case cpuPercent = "cpu_percent"
        case memoryBytes = "memory_bytes"
        case memoryPercent = "memory_percent"
        case startedAt = "started_at"
    }
}

// MARK: - Users & groups

/// Users, split the way the screen groups them: people who can log in, and
/// system accounts. The counts come from the agent so the section headers do
/// not have to re-derive them from a truncated list.
public struct UserList: Decodable, Sendable {
    public let total: Int
    public let items: [LinuxUser]
    public let people: Int?
    public let system: Int?
}

public struct LinuxUser: Decodable, Sendable, Identifiable {
    public let username: String
    public let uid: UInt32
    public let gid: UInt32
    public let fullName: String?
    public let home: String
    public let shell: String
    public let groups: [String]
    public let isSystem: Bool
    public let canSudo: Bool
    /// Nil when `/etc/shadow` is unreadable, which is normal for a non-root
    /// agent. The UI shows "unknown", never "unlocked".
    public let locked: Bool?
    public let hasPassword: Bool?
    public let sshKeyCount: Int?
    public let lastLogin: Int64?

    public var id: String { username }

    private enum CodingKeys: String, CodingKey {
        case username, uid, gid, home, shell, groups, locked
        case fullName = "full_name"
        case isSystem = "is_system"
        case canSudo = "can_sudo"
        case hasPassword = "has_password"
        case sshKeyCount = "ssh_key_count"
        case lastLogin = "last_login"
    }

    /// A user can log in interactively — the distinction the Users screen groups by.
    public var isLoginUser: Bool {
        !isSystem && !shell.hasSuffix("nologin") && !shell.hasSuffix("false")
    }
}

public struct LinuxGroup: Decodable, Sendable, Identifiable {
    public let name: String
    public let gid: UInt32
    public let members: [String]

    public var id: String { name }
}

public struct SSHKeyEntry: Decodable, Sendable, Identifiable {
    public let fingerprint: String
    public let type: String
    public let comment: String?

    public var id: String { fingerprint }
}

// MARK: - Services

public struct ServiceUnit: Decodable, Sendable, Identifiable {
    public let name: String
    public let displayName: String
    public let description: String
    public let loadState: String
    public let activeState: String
    public let subState: String
    /// The product-level rollup the UI shows: running / stopped / failed /
    /// starting / stopping / unknown. Derived by the agent so the app never
    /// has to reason about systemd's three-axis state model.
    public let state: String
    public let enabled: String?
    public let canStart: Bool
    public let canStop: Bool
    public let canRestart: Bool

    public var id: String { name }

    private enum CodingKeys: String, CodingKey {
        case name, description, state, enabled
        case displayName = "display_name"
        case loadState = "load_state"
        case activeState = "active_state"
        case subState = "sub_state"
        case canStart = "can_start"
        case canStop = "can_stop"
        case canRestart = "can_restart"
    }

    public var isRunning: Bool { state == "running" }
    public var hasFailed: Bool { state == "failed" }
    public var isEnabledAtBoot: Bool { enabled == "enabled" || enabled == "enabled-runtime" }
}

public struct ServiceUnitDetail: Decodable, Sendable {
    public let name: String
    public let displayName: String
    public let description: String
    public let state: String
    public let activeState: String
    public let subState: String
    public let enabled: String?
    public let mainPID: Int32?
    public let memoryBytes: Int64?
    public let cpuUsageNsec: Int64?
    public let tasksCurrent: Int64?
    public let tasksMax: Int64?
    public let restartCount: Int?
    public let activeSince: Int64?
    public let fragmentPath: String?
    public let result: String?
    public let execMainStatus: Int32?
    public let documentation: [String]?

    private enum CodingKeys: String, CodingKey {
        case name, description, state, enabled, result, documentation
        case displayName = "display_name"
        case activeState = "active_state"
        case subState = "sub_state"
        case mainPID = "main_pid"
        case memoryBytes = "memory_bytes"
        case cpuUsageNsec = "cpu_usage_nsec"
        case tasksCurrent = "tasks_current"
        case tasksMax = "tasks_max"
        case restartCount = "restart_count"
        case activeSince = "active_since"
        case fragmentPath = "fragment_path"
        case execMainStatus = "exec_main_status"
    }
}

// MARK: - Docker

public struct DockerInfo: Decodable, Sendable {
    public let version: String
    public let apiVersion: String
    public let rootDir: String?
    public let storageDriver: String?
    public let containersTotal: Int
    public let containersRunning: Int
    public let containersStopped: Int
    public let containersPaused: Int
    public let images: Int
    public let cpus: Int?
    public let memoryBytes: Int64?
    public let cgroupVersion: String?
    public let liveRestore: Bool?
    public let warnings: [String]?

    private enum CodingKeys: String, CodingKey {
        case version, images, cpus, warnings
        case apiVersion = "api_version"
        case rootDir = "root_dir"
        case storageDriver = "storage_driver"
        case containersTotal = "containers_total"
        case containersRunning = "containers_running"
        case containersStopped = "containers_stopped"
        case containersPaused = "containers_paused"
        case memoryBytes = "memory_bytes"
        case cgroupVersion = "cgroup_version"
        case liveRestore = "live_restore"
    }
}

public struct DockerContainerList: Decodable, Sendable {
    public let total: Int
    public let items: [DockerContainer]
    public let running: Int
    public let statsSampled: Int?
    public let statsTruncated: Bool?

    private enum CodingKeys: String, CodingKey {
        case total, items, running
        case statsSampled = "stats_sampled"
        case statsTruncated = "stats_truncated"
    }
}

public struct DockerContainer: Decodable, Sendable, Identifiable {
    public let id: String
    public let shortID: String
    public let name: String
    public let image: String
    public let imageID: String?
    public let state: String
    public let status: String
    public let health: String?
    public let createdAt: Int64
    public let startedAt: Int64?
    public let restartCount: Int?
    public let ports: [DockerPort]
    public let labels: [String: String]?
    public let composeProject: String?
    public let composeService: String?
    public let networks: [String]?
    public let cpuPercent: Double?
    public let memoryBytes: Int64?
    public let memoryLimitBytes: Int64?
    public let memoryPercent: Double?

    private enum CodingKeys: String, CodingKey {
        case id, name, image, state, status, health, ports, labels, networks
        case shortID = "short_id"
        case imageID = "image_id"
        case createdAt = "created_at"
        case startedAt = "started_at"
        case restartCount = "restart_count"
        case composeProject = "compose_project"
        case composeService = "compose_service"
        case cpuPercent = "cpu_percent"
        case memoryBytes = "memory_bytes"
        case memoryLimitBytes = "memory_limit_bytes"
        case memoryPercent = "memory_percent"
    }

    public var isRunning: Bool { state == "running" }
    public var isPaused: Bool { state == "paused" }
    /// Exited, dead or created — anything the user would call "not running".
    public var isStopped: Bool { !isRunning && !isPaused }
    public var isUnhealthy: Bool { health == "unhealthy" }

    /// What the user calls this container. Compose service names are friendlier
    /// than the generated `project-service-1` container name.
    public var displayName: String { composeService ?? name }
}

public struct DockerPort: Decodable, Sendable, Identifiable {
    public let `private`: Int
    public let `public`: Int?
    public let type: String
    public let ip: String?

    public var id: String { "\(ip ?? "")-\(`private`)-\(`public` ?? 0)-\(type)" }

    /// `8080 → 80/tcp`, or `80/tcp` when nothing is published.
    public var describedMapping: String {
        if let published = `public` {
            return "\(published) → \(`private`)/\(type)"
        }
        return "\(`private`)/\(type)"
    }
}

public struct DockerContainerDetail: Decodable, Sendable {
    public let id: String
    public let shortID: String
    public let name: String
    public let image: String
    public let imageID: String?
    public let state: String
    public let status: String
    public let health: String?
    public let createdAt: Int64
    public let startedAt: Int64?
    public let finishedAt: Int64?
    public let restartCount: Int?
    public let exitCode: Int32?
    public let ports: [DockerPort]
    public let labels: [String: String]?
    public let composeProject: String?
    public let composeService: String?
    public let networks: [DockerNetworkAttachment]?
    public let command: [String]?
    public let entrypoint: [String]?
    public let workingDir: String?
    public let user: String?
    public let tty: Bool?
    public let platform: String?
    public let restartPolicy: DockerRestartPolicy?
    public let mounts: [DockerMount]?
    public let env: [DockerEnvVar]?
    public let healthCheck: DockerHealthCheck?

    private enum CodingKeys: String, CodingKey {
        case id, name, image, state, status, health, ports, labels, networks
        case command, entrypoint, user, tty, platform, mounts, env
        case shortID = "short_id"
        case imageID = "image_id"
        case createdAt = "created_at"
        case startedAt = "started_at"
        case finishedAt = "finished_at"
        case restartCount = "restart_count"
        case exitCode = "exit_code"
        case composeProject = "compose_project"
        case composeService = "compose_service"
        case workingDir = "working_dir"
        case restartPolicy = "restart_policy"
        case healthCheck = "health_check"
    }

    public var isRunning: Bool { state == "running" }
}

public struct DockerNetworkAttachment: Decodable, Sendable, Identifiable {
    public let name: String
    public let ipAddress: String?
    public let gateway: String?
    public let macAddress: String?

    public var id: String { name }

    private enum CodingKeys: String, CodingKey {
        case name, gateway
        case ipAddress = "ip_address"
        case macAddress = "mac_address"
    }
}

public struct DockerRestartPolicy: Decodable, Sendable {
    public let name: String
    public let maxRetryCount: Int?

    private enum CodingKeys: String, CodingKey {
        case name
        case maxRetryCount = "max_retry_count"
    }

    /// "Always", "On failure (max 3)", "Never".
    public var described: String {
        switch name {
        case "always": return "Always"
        case "unless-stopped": return "Unless stopped"
        case "on-failure":
            if let max = maxRetryCount, max > 0 { return "On failure (up to \(max) times)" }
            return "On failure"
        default: return "Never"
        }
    }
}

public struct DockerMount: Decodable, Sendable, Identifiable {
    public let type: String
    public let source: String?
    public let destination: String
    public let mode: String?
    public let rw: Bool?

    public var id: String { destination }
}

/// An environment variable, with its value withheld when it looks like a secret.
///
/// `value` is `nil` exactly when `masked` is true. The two are kept separate so
/// the UI can render a deliberate "hidden" affordance rather than an empty
/// string that looks like a bug.
public struct DockerEnvVar: Decodable, Sendable, Identifiable {
    public let key: String
    public let value: String?
    public let masked: Bool

    public var id: String { key }
}

public struct DockerHealthCheck: Decodable, Sendable {
    public let status: String?
    public let failingStreak: Int?
    public let test: [String]?

    private enum CodingKeys: String, CodingKey {
        case status, test
        case failingStreak = "failing_streak"
    }
}

public struct DockerImage: Decodable, Sendable, Identifiable {
    public let id: String
    public let shortID: String
    public let repoTags: [String]?
    public let repository: String?
    public let tag: String?
    public let sizeBytes: Int64
    public let createdAt: Int64
    public let containers: Int?
    public let dangling: Bool

    private enum CodingKeys: String, CodingKey {
        case id, repository, tag, containers, dangling
        case shortID = "short_id"
        case repoTags = "repo_tags"
        case sizeBytes = "size_bytes"
        case createdAt = "created_at"
    }

    public var displayName: String {
        if let repo = repository, let tag { return "\(repo):\(tag)" }
        return repoTags?.first ?? shortID
    }
}

public struct DockerVolume: Decodable, Sendable, Identifiable {
    public let name: String
    public let driver: String
    public let mountpoint: String
    public let createdAt: Int64?
    public let labels: [String: String]?
    public let sizeBytes: Int64?
    public let inUse: Bool?

    public var id: String { name }

    private enum CodingKeys: String, CodingKey {
        case name, driver, mountpoint, labels
        case createdAt = "created_at"
        case sizeBytes = "size_bytes"
        case inUse = "in_use"
    }
}

public struct DockerNetwork: Decodable, Sendable, Identifiable {
    public let id: String
    public let name: String
    public let driver: String
    public let scope: String
    public let `internal`: Bool
    public let subnet: String?
    public let gateway: String?
    public let containerCount: Int?

    private enum CodingKeys: String, CodingKey {
        case id, name, driver, scope, `internal`, subnet, gateway
        case containerCount = "container_count"
    }
}

public struct DockerStats: Decodable, Sendable {
    public let cpuPercent: Double
    public let memoryBytes: Int64
    public let memoryLimitBytes: Int64
    public let memoryPercent: Double
    public let onlineCPUs: Int?

    private enum CodingKeys: String, CodingKey {
        case cpuPercent = "cpu_percent"
        case memoryBytes = "memory_bytes"
        case memoryLimitBytes = "memory_limit_bytes"
        case memoryPercent = "memory_percent"
        case onlineCPUs = "online_cpus"
    }
}

// MARK: - Projects

public struct ProjectList: Decodable, Sendable {
    public let total: Int
    public let items: [Project]
    public let running: Int?
    /// Projects with some containers up and some down — the state that most
    /// often means something is quietly broken.
    public let degraded: Int?
}

public struct Project: Decodable, Sendable, Identifiable {
    public let name: String
    public let serviceCount: Int
    public let containerCount: Int
    public let running: Int
    public let state: String
    public let workingDir: String?
    public let services: [String]
    public let containers: [DockerContainer]?

    public var id: String { name }

    private enum CodingKeys: String, CodingKey {
        case name, running, state, services, containers
        case serviceCount = "service_count"
        case containerCount = "container_count"
        case workingDir = "working_dir"
    }

    public var isFullyRunning: Bool { state == "running" }
    public var isPartiallyRunning: Bool { state == "partial" }
}

// MARK: - Databases

public struct DatabaseInstance: Decodable, Sendable, Identifiable {
    public let port: Int
    public let socketDir: String?
    public let reachable: Bool

    public var id: String { "\(socketDir ?? "tcp"):\(port)" }

    private enum CodingKeys: String, CodingKey {
        case port, reachable
        case socketDir = "socket_dir"
    }
}

public struct PostgresOverview: Decodable, Sendable {
    public let version: String?
    public let versionNum: Int?
    public let uptimeSeconds: Int64?
    public let startedAt: Int64?
    public let dataDirectory: String?
    public let maxConnections: Int?
    public let currentConnections: Int?
    public let connectionUsagePercent: Double?
    public let databaseCount: Int?
    public let totalSizeBytes: Int64?
    public let cacheHitRatio: Double?
    public let transactionsCommitted: Int64?
    public let transactionsRolledBack: Int64?
    public let deadlocks: Int64?
    public let health: String
    public let healthReason: String?

    private enum CodingKeys: String, CodingKey {
        case version, deadlocks, health
        case versionNum = "version_num"
        case uptimeSeconds = "uptime_seconds"
        case startedAt = "started_at"
        case dataDirectory = "data_directory"
        case maxConnections = "max_connections"
        case currentConnections = "current_connections"
        case connectionUsagePercent = "connection_usage_percent"
        case databaseCount = "database_count"
        case totalSizeBytes = "total_size_bytes"
        case cacheHitRatio = "cache_hit_ratio"
        case transactionsCommitted = "transactions_committed"
        case transactionsRolledBack = "transactions_rolled_back"
        case healthReason = "health_reason"
    }
}

public struct PostgresDatabase: Decodable, Sendable, Identifiable {
    public let name: String
    public let owner: String?
    public let sizeBytes: Int64?
    public let encoding: String?
    public let collation: String?
    public let connectionLimit: Int?
    public let isTemplate: Bool?
    public let tableCount: Int?

    public var id: String { name }

    private enum CodingKeys: String, CodingKey {
        case name, owner, encoding, collation
        case sizeBytes = "size_bytes"
        case connectionLimit = "connection_limit"
        case isTemplate = "is_template"
        case tableCount = "table_count"
    }
}

public struct PostgresTable: Decodable, Sendable, Identifiable {
    public let schema: String
    public let name: String
    public let rowsEstimate: Int64?
    public let totalSizeBytes: Int64?
    public let tableSizeBytes: Int64?
    public let indexSizeBytes: Int64?
    public let seqScans: Int64?
    public let indexScans: Int64?
    // Epoch seconds, as the agent's `extract(epoch FROM …)::bigint` produces
    // and `int(row, …)` emits — a JSON number, not a string. These were
    // `String?`, which decoded fine only as long as every value was null;
    // the first table that had actually been vacuumed made the whole tab
    // fail with "expected String but found number". Same shape as the
    // query_start/state_change bug on the Connections tab.
    public let lastVacuum: Int64?
    public let lastAnalyze: Int64?

    public var id: String { "\(schema).\(name)" }

    private enum CodingKeys: String, CodingKey {
        case schema, name
        case rowsEstimate = "rows_estimate"
        case totalSizeBytes = "total_size_bytes"
        case tableSizeBytes = "table_size_bytes"
        case indexSizeBytes = "index_size_bytes"
        case seqScans = "seq_scans"
        case indexScans = "index_scans"
        case lastVacuum = "last_vacuum"
        case lastAnalyze = "last_analyze"
    }
}

public struct PostgresConnection: Decodable, Sendable, Identifiable {
    public let pid: Int32
    public let user: String?
    public let database: String?
    public let clientAddr: String?
    public let applicationName: String?
    public let state: String?
    /// Epoch seconds. The agent selects `extract(epoch FROM query_start)`
    /// rather than a formatted timestamp, so the client never has to guess at
    /// the server's timezone or PostgreSQL's `DateStyle`.
    public let queryStart: Int64?
    public let stateChange: Int64?
    public let waitEventType: String?
    public let backendType: String?
    /// Present only when an operator explicitly asked to see query text.
    public let queryPreview: String?

    public var id: Int32 { pid }

    private enum CodingKeys: String, CodingKey {
        case pid, user, database, state
        case clientAddr = "client_addr"
        case applicationName = "application_name"
        case queryStart = "query_start"
        case stateChange = "state_change"
        case waitEventType = "wait_event_type"
        case backendType = "backend_type"
        case queryPreview = "query_preview"
    }
}

public struct PostgresRole: Decodable, Sendable, Identifiable {
    public let name: String
    public let isSuperuser: Bool?
    public let canCreateDB: Bool?
    public let canCreateRole: Bool?
    public let canLogin: Bool?
    public let isReplication: Bool?
    public let bypassesRLS: Bool?
    /// PostgreSQL reports "no limit" as -1; the UI shows "Unlimited".
    public let connectionLimit: Int?
    /// Epoch seconds (a JSON number), for the same reason as `PostgresTable`'s
    /// timestamps. A role with a password expiry would otherwise have crashed
    /// the Roles tab; every role in the fixture had `valid_until: null`, so
    /// nothing revealed it here either.
    public let validUntil: Int64?

    public var id: String { name }

    private enum CodingKeys: String, CodingKey {
        case name
        case isSuperuser = "is_superuser"
        case canCreateDB = "can_create_db"
        case canCreateRole = "can_create_role"
        case canLogin = "can_login"
        case isReplication = "is_replication"
        case bypassesRLS = "bypasses_rls"
        case connectionLimit = "connection_limit"
        case validUntil = "valid_until"
    }

    public var hasUnlimitedConnections: Bool { (connectionLimit ?? -1) < 0 }

    /// The privileges worth showing as chips, in the order they matter.
    public var privileges: [String] {
        var out: [String] = []
        if isSuperuser == true { out.append("Superuser") }
        if canCreateDB == true { out.append("Create DB") }
        if canCreateRole == true { out.append("Create role") }
        if isReplication == true { out.append("Replication") }
        if bypassesRLS == true { out.append("Bypasses RLS") }
        if canLogin != true { out.append("Cannot log in") }
        return out
    }
}

// MARK: - Files

public struct DirectoryListing: Decodable, Sendable {
    public let path: String
    public let parent: String?
    public let entries: [FileEntry]
    public let total: Int?
    public let truncated: Bool?
}

public struct FileEntry: Decodable, Sendable, Identifiable {
    public let name: String
    public let path: String
    public let kind: String
    public let sizeBytes: Int64?
    public let modifiedAt: Int64?
    public let mode: String?
    public let modeOctal: UInt32?
    public let owner: String?
    public let group: String?
    public let uid: UInt32?
    public let gid: UInt32?
    public let isSymlink: Bool
    public let symlinkTarget: String?
    public let isReadable: Bool?
    public let isWritable: Bool?
    public let `extension`: String?
    public let isText: Bool?

    public var id: String { path }

    private enum CodingKeys: String, CodingKey {
        case name, path, kind, mode, owner, group, uid, gid
        case sizeBytes = "size_bytes"
        case modifiedAt = "modified_at"
        case modeOctal = "mode_octal"
        case isSymlink = "is_symlink"
        case symlinkTarget = "symlink_target"
        case isReadable = "is_readable"
        case isWritable = "is_writable"
        case `extension` = "extension"
        case isText = "is_text"
    }

    public var isDirectory: Bool { kind == "directory" }
    public var isRegularFile: Bool { kind == "file" }
    /// Whether double-clicking it should open the text editor.
    public var isEditable: Bool { isRegularFile && (isText ?? false) && (isReadable ?? false) }
}

public struct TextFileContents: Decodable, Sendable {
    public let path: String
    public let content: String
    public let encoding: String
    public let lineCount: Int
    public let sizeBytes: Int64
    public let truncated: Bool
    public let lineEnding: String?
    public let readonly: Bool?

    private enum CodingKeys: String, CodingKey {
        case path, content, encoding, truncated, readonly
        case lineCount = "line_count"
        case sizeBytes = "size_bytes"
        case lineEnding = "line_ending"
    }
}

// MARK: - Logs

public struct LogBatch: Decodable, Sendable {
    public let lines: [LogLine]
    public let source: String?
    public let truncated: Bool?
}

public struct LogLine: Decodable, Sendable, Identifiable, Hashable {
    public let timestamp: Int64?
    public let level: String?
    public let message: String
    public let raw: String?
    public let source: String?
    /// Docker's multiplexed stream tells stdout from stderr; the UI tints
    /// stderr so a crash is visible in a wall of ordinary output.
    public let stream: String?

    /// Log lines have no server-side identity. A composite of position and
    /// content is stable enough for SwiftUI's diffing within one view.
    public var id: String { "\(timestamp ?? 0)-\(message.hashValue)" }

    public var isError: Bool { level == "error" || level == "fatal" || stream == "stderr" }
    public var isWarning: Bool { level == "warn" }
    public var date: Date? {
        timestamp.map { Date(timeIntervalSince1970: TimeInterval($0)) }
    }
}

// MARK: - Activity

public struct ActivityEvent: Decodable, Sendable, Identifiable, Hashable {
    public let id: Int64
    public let at: Int64
    public let action: String
    public let resourceType: String
    public let resourceID: String
    public let actor: String
    public let peer: String?
    public let outcome: String
    public let summary: String

    private enum CodingKeys: String, CodingKey {
        case id, at, action, actor, peer, outcome, summary
        case resourceType = "resource_type"
        case resourceID = "resource_id"
    }

    public var succeeded: Bool { outcome == "succeeded" }
    public var date: Date { Date(timeIntervalSince1970: TimeInterval(at)) }
}

// MARK: - Live stream frames

/// A frame pushed over the `/v1/stream` WebSocket.
public enum StreamFrame: Sendable {
    case welcome(StreamWelcome)
    case metrics(Metrics)
    case docker(DockerContainerList)
    case services([ServiceUnit])
    case activity([ActivityEvent])
    case subscribed([String])
    case pong
    case failure(code: String, message: String)
}

public struct StreamWelcome: Decodable, Sendable {
    public let agentVersion: String
    public let apiVersion: String
    public let serverID: String
    public let channels: [String]
    public let metricsIntervalMs: Int
    public let capabilities: AgentCapabilities

    private enum CodingKeys: String, CodingKey {
        case channels, capabilities
        case agentVersion = "agent_version"
        case apiVersion = "api_version"
        case serverID = "server_id"
        case metricsIntervalMs = "metrics_interval_ms"
    }
}
