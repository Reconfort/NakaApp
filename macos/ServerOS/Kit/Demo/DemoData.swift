//  DemoData.swift
//  ServerOS
//
//  Three servers that do not exist.
//
//  ──────────────────────────────────────────────────────────────────────────
//  DEMO DATA MUST NEVER BE MISTAKABLE FOR REAL INFRASTRUCTURE.
//
//  This is an infrastructure tool. Someone who believes a demo container is
//  their production container will eventually click "Stop" on it, and the
//  moment they realise what they thought they were doing is the moment they
//  stop trusting the product — whichever way it turns out.
//
//  So the separation is structural, not cosmetic:
//
//    * every demo server's name begins with "Demo ";
//    * every demo `ServerSummary` has `isDemo == true`, and the UI is required
//      to show a persistent badge on the server, on its header, and on any
//      destructive confirmation inside it;
//    * every demo hostname is under `.invalid`, a TLD reserved by RFC 2606 that
//      can never resolve — so a copied hostname cannot accidentally point at
//      anything;
//    * nothing here opens a socket. `DemoAgentClient` never touches the
//      network, so a demo screen cannot act on a real machine even if it were
//      somehow handed one.
//  ──────────────────────────────────────────────────────────────────────────
//
//  # Why the numbers move
//
//  A demo with frozen metrics looks like a screenshot, and a screenshot cannot
//  show whether the metric animations, the health transitions or the sparkline
//  smoothing actually work. So each server walks its own CPU, memory, disk and
//  network figures between calls, from a generator seeded by the server's id —
//  the walk is random-looking but identical on every launch, which is what
//  makes a demo usable for screenshots *and* for testing.

import Foundation

// MARK: - Deterministic randomness

/// xorshift64*, seeded per server.
///
/// Not `SystemRandomNumberGenerator`: a demo that looks different on every
/// launch cannot be screenshotted twice, and a test cannot assert on it.
struct DemoRandom {
    private var state: UInt64

    init(seed: UInt64) {
        // Zero is a fixed point of xorshift; nudge it to the golden-ratio
        // constant instead.
        state = seed == 0 ? 0x9E37_79B9_7F4A_7C15 : seed
    }

    /// Seed a generator from any string, so a server's id picks its walk.
    init(text: String) {
        var hash: UInt64 = 0xCBF2_9CE4_8422_2325
        for byte in Array(text.utf8) {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3
        }
        self.init(seed: hash)
    }

    mutating func next() -> UInt64 {
        state ^= state >> 12
        state ^= state << 25
        state ^= state >> 27
        return state &* 2_685_821_657_736_338_717
    }

    /// A value in `0..<1`.
    mutating func unit() -> Double {
        Double(next() >> 11) * (1.0 / 9_007_199_254_740_992.0)
    }

    mutating func double(in range: ClosedRange<Double>) -> Double {
        range.lowerBound + unit() * (range.upperBound - range.lowerBound)
    }
}

/// One quantity drifting around a resting value.
///
/// Metrics that jump from 20% to 80% and back look broken; metrics that never
/// move look frozen. A walk with a pull toward its resting point gives the
/// third thing — movement that reads as a real machine breathing.
struct DemoWalk {
    var value: Double
    let resting: Double
    let step: Double
    let bounds: ClosedRange<Double>

    /// Take one step.
    ///
    /// - Parameter noise: a value in `0..<1`. Taken as a parameter rather than
    ///   drawn here so the caller never holds two overlapping mutations of its
    ///   own stored properties at once.
    mutating func advance(noise: Double) -> Double {
        let drift = (noise * 2 - 1) * step
        let pull = (resting - value) * 0.18
        value = min(max(value + drift + pull, bounds.lowerBound), bounds.upperBound)
        return value
    }
}

// MARK: - The servers

/// The fixed facts about one demo server.
public struct DemoProfile: Sendable {
    public let id: String
    public let name: String
    public let hostname: String
    public let sshUsername: String
    public let osName: String
    public let osVersion: String
    public let osID: String
    public let osPretty: String
    public let kernel: String
    public let architecture: String
    public let cpuModel: String
    public let cores: Int
    public let threads: Int
    public let memoryTotalBytes: Int64
    public let swapTotalBytes: Int64
    public let diskTotalBytes: Int64
    public let uptimeSeconds: Int64

    /// Where the walks rest. Staging sits high on disk on purpose, so the
    /// "Needs Attention" state is reachable without waiting for luck.
    public let restingCPU: Double
    public let restingMemory: Double
    public let restingDisk: Double

    public let capabilities: AgentCapabilities
    let containers: [DemoContainerSpec]
    let services: [DemoServiceSpec]
    let people: [DemoUserSpec]
    public let projectName: String?
}

struct DemoContainerSpec: Sendable {
    let name: String
    let image: String
    let service: String
    let running: Bool
    let health: String?
    let publishedPort: Int?
    let containerPort: Int?
}

struct DemoServiceSpec: Sendable {
    let unit: String
    let display: String
    let summary: String
    let state: String
}

struct DemoUserSpec: Sendable {
    let username: String
    let uid: UInt32
    let fullName: String?
    let shell: String
    let sudo: Bool
    let system: Bool
}

/// The three fake servers, and the clients that serve them.
///
/// Hold one of these for the lifetime of the app: each `DemoAgentClient` owns
/// the walk state that makes its metrics move, and rebuilding the environment
/// restarts every walk from its seed.
public struct DemoEnvironment: Sendable {

    /// The shared environment. One walk per server, for the whole session.
    public static let shared = DemoEnvironment()

    /// The demo servers, ready to insert into `ServerStore`.
    public let servers: [ServerSummary]

    private let clients: [String: DemoAgentClient]

    public init() {
        let profiles = DemoEnvironment.profiles
        var summaries: [ServerSummary] = []
        var built: [String: DemoAgentClient] = [:]

        for (index, profile) in profiles.enumerated() {
            summaries.append(ServerSummary(
                id: profile.id,
                name: profile.name,
                hostname: profile.hostname,
                sshPort: 22,
                sshUsername: profile.sshUsername,
                agentPort: 8723,
                osPretty: profile.osPretty,
                arch: profile.architecture,
                lastSeenAt: Date(),
                addedAt: Date(timeIntervalSinceNow: -86_400 * Double(index + 3)),
                tags: profile.id == "demo-production" ? ["demo", "production"] : ["demo"],
                sortIndex: index,
                isDemo: true
            ))
            built[profile.id] = DemoAgentClient(profile: profile)
        }

        self.servers = summaries
        self.clients = built
    }

    /// The client for one demo server.
    public func client(for serverID: String) -> DemoAgentClient? {
        clients[serverID]
    }

    /// The profile for one demo server.
    public static func profile(for serverID: String) -> DemoProfile? {
        profiles.first { $0.id == serverID }
    }

    /// Every demo profile.
    public static let profiles: [DemoProfile] = [
        DemoProfile(
            id: "demo-production",
            name: "Demo Production",
            hostname: "prod.demo.invalid",
            sshUsername: "deploy",
            osName: "Ubuntu",
            osVersion: "24.04.3 LTS",
            osID: "ubuntu",
            osPretty: "Ubuntu 24.04.3 LTS",
            kernel: "6.8.0-45-generic",
            architecture: "x86_64",
            cpuModel: "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz",
            cores: 8,
            threads: 16,
            memoryTotalBytes: 34_359_738_368,
            swapTotalBytes: 4_294_967_296,
            diskTotalBytes: 536_870_912_000,
            uptimeSeconds: 4_218_640,
            restingCPU: 23,
            restingMemory: 61,
            restingDisk: 48,
            capabilities: AgentCapabilities(
                metrics: true, processes: true, users: true, files: true, logs: true,
                docker: true, dockerAPIVersion: "1.43", services: true, serviceBackend: "systemd",
                journal: true, postgres: true
            ),
            containers: [
                DemoContainerSpec(name: "estatify-api-1", image: "estatify/api:2.14.0", service: "api", running: true, health: "healthy", publishedPort: 3000, containerPort: 3000),
                DemoContainerSpec(name: "estatify-web-1", image: "estatify/web:2.14.0", service: "web", running: true, health: "healthy", publishedPort: 8080, containerPort: 80),
                DemoContainerSpec(name: "estatify-worker-1", image: "estatify/api:2.14.0", service: "worker", running: true, health: nil, publishedPort: nil, containerPort: nil),
                DemoContainerSpec(name: "estatify-postgres-1", image: "postgres:16.4-alpine", service: "postgres", running: true, health: "healthy", publishedPort: nil, containerPort: 5432),
                DemoContainerSpec(name: "estatify-redis-1", image: "redis:7.4-alpine", service: "redis", running: true, health: nil, publishedPort: nil, containerPort: 6379),
                DemoContainerSpec(name: "estatify-migrate-1", image: "estatify/api:2.14.0", service: "migrate", running: false, health: nil, publishedPort: nil, containerPort: nil),
            ],
            services: [
                DemoServiceSpec(unit: "nginx.service", display: "nginx", summary: "A high performance web server and a reverse proxy server", state: "running"),
                DemoServiceSpec(unit: "docker.service", display: "docker", summary: "Docker Application Container Engine", state: "running"),
                DemoServiceSpec(unit: "ssh.service", display: "ssh", summary: "OpenBSD Secure Shell server", state: "running"),
                DemoServiceSpec(unit: "postgresql.service", display: "postgresql", summary: "PostgreSQL RDBMS", state: "running"),
                DemoServiceSpec(unit: "serveros-agent.service", display: "serveros-agent", summary: "ServerOS management agent", state: "running"),
                DemoServiceSpec(unit: "fail2ban.service", display: "fail2ban", summary: "Ban hosts that cause multiple authentication errors", state: "failed"),
            ],
            people: [
                DemoUserSpec(username: "root", uid: 0, fullName: "root", shell: "/bin/bash", sudo: false, system: true),
                DemoUserSpec(username: "deploy", uid: 1000, fullName: "Deploy", shell: "/bin/bash", sudo: true, system: false),
                DemoUserSpec(username: "abebe", uid: 1001, fullName: "Abebe Bikila", shell: "/bin/zsh", sudo: true, system: false),
                DemoUserSpec(username: "www-data", uid: 33, fullName: "www-data", shell: "/usr/sbin/nologin", sudo: false, system: true),
                DemoUserSpec(username: "postgres", uid: 114, fullName: "PostgreSQL administrator", shell: "/bin/bash", sudo: false, system: true),
            ],
            projectName: "estatify"
        ),
        DemoProfile(
            id: "demo-staging",
            name: "Demo Staging",
            hostname: "staging.demo.invalid",
            sshUsername: "deploy",
            osName: "Debian GNU/Linux",
            osVersion: "12 (bookworm)",
            osID: "debian",
            osPretty: "Debian GNU/Linux 12 (bookworm)",
            kernel: "6.1.0-23-amd64",
            architecture: "x86_64",
            cpuModel: "AMD EPYC 7R13 Processor",
            cores: 4,
            threads: 8,
            memoryTotalBytes: 17_179_869_184,
            swapTotalBytes: 2_147_483_648,
            diskTotalBytes: 214_748_364_800,
            uptimeSeconds: 913_284,
            restingCPU: 14,
            restingMemory: 47,
            // Deliberately in warning territory, so the "Storage is filling up"
            // card is reachable in a demo without waiting for luck.
            restingDisk: 83,
            capabilities: AgentCapabilities(
                metrics: true, processes: true, users: true, files: true, logs: true,
                docker: true, dockerAPIVersion: "1.43", services: true, serviceBackend: "systemd",
                journal: true, postgres: true
            ),
            containers: [
                DemoContainerSpec(name: "estatify-api-1", image: "estatify/api:2.15.0-rc3", service: "api", running: true, health: "healthy", publishedPort: 3000, containerPort: 3000),
                DemoContainerSpec(name: "estatify-web-1", image: "estatify/web:2.15.0-rc3", service: "web", running: true, health: nil, publishedPort: 8080, containerPort: 80),
                DemoContainerSpec(name: "estatify-postgres-1", image: "postgres:16.4-alpine", service: "postgres", running: true, health: "healthy", publishedPort: nil, containerPort: 5432),
                DemoContainerSpec(name: "estatify-mailpit-1", image: "axllent/mailpit:v1.20", service: "mailpit", running: false, health: nil, publishedPort: 8025, containerPort: 8025),
            ],
            services: [
                DemoServiceSpec(unit: "nginx.service", display: "nginx", summary: "A high performance web server and a reverse proxy server", state: "running"),
                DemoServiceSpec(unit: "docker.service", display: "docker", summary: "Docker Application Container Engine", state: "running"),
                DemoServiceSpec(unit: "ssh.service", display: "ssh", summary: "OpenBSD Secure Shell server", state: "running"),
                DemoServiceSpec(unit: "serveros-agent.service", display: "serveros-agent", summary: "ServerOS management agent", state: "running"),
            ],
            people: [
                DemoUserSpec(username: "root", uid: 0, fullName: "root", shell: "/bin/bash", sudo: false, system: true),
                DemoUserSpec(username: "deploy", uid: 1000, fullName: "Deploy", shell: "/bin/bash", sudo: true, system: false),
                DemoUserSpec(username: "www-data", uid: 33, fullName: "www-data", shell: "/usr/sbin/nologin", sudo: false, system: true),
            ],
            projectName: "estatify"
        ),
        DemoProfile(
            id: "demo-development",
            name: "Demo Development",
            hostname: "dev.demo.invalid",
            sshUsername: "abebe",
            osName: "Ubuntu",
            osVersion: "24.04.3 LTS",
            osID: "ubuntu",
            osPretty: "Ubuntu 24.04.3 LTS",
            kernel: "6.8.0-45-generic",
            architecture: "aarch64",
            cpuModel: "Neoverse-N1",
            cores: 2,
            threads: 2,
            memoryTotalBytes: 8_589_934_592,
            swapTotalBytes: 0,
            diskTotalBytes: 107_374_182_400,
            uptimeSeconds: 7_412,
            restingCPU: 6,
            restingMemory: 34,
            restingDisk: 22,
            // No systemd and no PostgreSQL, on purpose: this is the server that
            // proves the sidebar hides sections a host does not have instead of
            // showing ones that fail when opened.
            capabilities: AgentCapabilities(
                metrics: true, processes: true, users: true, files: true, logs: true,
                docker: true, dockerAPIVersion: "1.43", services: false, serviceBackend: nil,
                journal: false, postgres: false
            ),
            containers: [
                DemoContainerSpec(name: "dev-api-1", image: "estatify/api:dev", service: "api", running: true, health: nil, publishedPort: 3000, containerPort: 3000),
                DemoContainerSpec(name: "dev-postgres-1", image: "postgres:16.4-alpine", service: "postgres", running: true, health: "healthy", publishedPort: 5432, containerPort: 5432),
            ],
            services: [],
            people: [
                DemoUserSpec(username: "root", uid: 0, fullName: "root", shell: "/bin/bash", sudo: false, system: true),
                DemoUserSpec(username: "abebe", uid: 1000, fullName: "Abebe Bikila", shell: "/bin/zsh", sudo: true, system: false),
            ],
            projectName: "dev"
        ),
    ]
}

// MARK: - The client

/// An `AgentAPI` that answers from memory and never opens a socket.
///
/// Conforming to the same protocol as `AgentClient` is what keeps demo mode
/// honest: the screens cannot tell which one they hold, so a screen that works
/// in the demo works against a server, and a screen that has not been built for
/// a state cannot quietly special-case the demo to hide it.
public actor DemoAgentClient: AgentAPI {

    /// The server's display name.
    public let serverName: String

    /// What this demo server "can do".
    public private(set) var capabilities: AgentCapabilities

    private let profile: DemoProfile
    private let startedAt: Date
    private var random: DemoRandom
    private var cpuWalk: DemoWalk
    private var memoryWalk: DemoWalk
    private var diskWalk: DemoWalk
    private var networkReceiveWalk: DemoWalk
    private var networkSendWalk: DemoWalk
    private var receivedTotal: Int64
    private var sentTotal: Int64

    /// Container and service states the user has changed during the session.
    private var containerStates: [String: Bool] = [:]
    private var serviceStates: [String: String] = [:]
    private var events: [ActivityEvent]
    private var nextEventID: Int64

    public init(profile: DemoProfile) {
        self.profile = profile
        self.serverName = profile.name
        self.capabilities = profile.capabilities
        self.startedAt = Date()
        self.random = DemoRandom(text: profile.id)
        self.cpuWalk = DemoWalk(value: profile.restingCPU, resting: profile.restingCPU, step: 6, bounds: 1...99)
        self.memoryWalk = DemoWalk(value: profile.restingMemory, resting: profile.restingMemory, step: 1.5, bounds: 5...99)
        self.diskWalk = DemoWalk(value: profile.restingDisk, resting: profile.restingDisk, step: 0.08, bounds: 1...99)
        self.networkReceiveWalk = DemoWalk(value: 240_000, resting: 260_000, step: 90_000, bounds: 0...12_000_000)
        self.networkSendWalk = DemoWalk(value: 180_000, resting: 200_000, step: 70_000, bounds: 0...12_000_000)
        self.receivedTotal = 84_120_993_281
        self.sentTotal = 21_884_003_119

        let seeded = DemoAgentClient.seedEvents(profile: profile)
        self.events = seeded.events
        self.nextEventID = seeded.nextID
    }

    // MARK: Meta

    public func health() async throws -> AgentHealth {
        AgentHealth(
            status: "ok",
            agentVersion: "0.1.0",
            apiVersion: "1",
            serverID: profile.id,
            uptimeSeconds: Int(Date().timeIntervalSince(startedAt)),
            capabilities: capabilities
        )
    }

    public func fetchCapabilities() async throws -> AgentCapabilities {
        capabilities
    }

    public func system() async throws -> SystemInfo {
        SystemInfo(
            hostname: profile.hostname,
            os: SystemInfo.OSInfo(
                name: profile.osName,
                version: profile.osVersion,
                id: profile.osID,
                pretty: profile.osPretty
            ),
            kernel: profile.kernel,
            architecture: profile.architecture,
            cpu: SystemInfo.CPUInfo(
                model: profile.cpuModel,
                cores: profile.cores,
                threads: profile.threads,
                mhz: 2900
            ),
            memoryTotalBytes: profile.memoryTotalBytes,
            swapTotalBytes: profile.swapTotalBytes,
            bootTime: Int64(Date().timeIntervalSince1970) - profile.uptimeSeconds,
            uptimeSeconds: profile.uptimeSeconds,
            virtualization: "kvm",
            loadAverage: loadAverage(),
            agent: SystemInfo.AgentInfo(
                version: "0.1.0",
                uptimeSeconds: Int64(Date().timeIntervalSince(startedAt)),
                startedAt: Int64(startedAt.timeIntervalSince1970),
                enrolled: true
            )
        )
    }

    public func metrics() async throws -> Metrics {
        // Each draw is taken into a local first, so no walk is being mutated
        // while the generator is.
        let cpuNoise = random.unit()
        let memoryNoise = random.unit()
        let diskNoise = random.unit()
        let receiveNoise = random.unit()
        let sendNoise = random.unit()

        let cpuPercent = cpuWalk.advance(noise: cpuNoise)
        let memoryPercent = memoryWalk.advance(noise: memoryNoise)
        let diskPercent = diskWalk.advance(noise: diskNoise)
        let receiveRate = networkReceiveWalk.advance(noise: receiveNoise)
        let sendRate = networkSendWalk.advance(noise: sendNoise)

        receivedTotal += Int64(receiveRate * 2)
        sentTotal += Int64(sendRate * 2)

        let memoryUsed = Int64(Double(profile.memoryTotalBytes) * memoryPercent / 100)
        let diskUsed = Int64(Double(profile.diskTotalBytes) * diskPercent / 100)
        let swapUsed = profile.swapTotalBytes > 0
            ? Int64(Double(profile.swapTotalBytes) * random.double(in: 0...0.12))
            : 0

        var perCore: [Double] = []
        for _ in 0..<profile.threads {
            let jitter = random.double(in: (-12.0)...12.0)
            perCore.append(min(max(cpuPercent + jitter, 0), 100))
        }

        return Metrics(
            sampledAt: Int64(Date().timeIntervalSince1970),
            cpu: CPUMetrics(
                usagePercent: cpuPercent,
                userPercent: cpuPercent * 0.68,
                systemPercent: cpuPercent * 0.24,
                iowaitPercent: cpuPercent * 0.08,
                perCore: perCore,
                loadAverage: loadAverage(),
                coreCount: profile.threads
            ),
            memory: MemoryMetrics(
                totalBytes: profile.memoryTotalBytes,
                usedBytes: memoryUsed,
                availableBytes: profile.memoryTotalBytes - memoryUsed,
                cachedBytes: Int64(Double(profile.memoryTotalBytes) * 0.17),
                buffersBytes: Int64(Double(profile.memoryTotalBytes) * 0.02),
                usagePercent: memoryPercent,
                swapTotalBytes: profile.swapTotalBytes,
                swapUsedBytes: swapUsed,
                swapUsagePercent: profile.swapTotalBytes > 0
                    ? Double(swapUsed) / Double(profile.swapTotalBytes) * 100
                    : 0
            ),
            disk: DiskMetrics(
                totalBytes: profile.diskTotalBytes,
                usedBytes: diskUsed,
                availableBytes: profile.diskTotalBytes - diskUsed,
                usagePercent: diskPercent,
                filesystems: [
                    DiskMetrics.Filesystem(
                        device: "/dev/nvme0n1p2",
                        mountPoint: "/",
                        fstype: "ext4",
                        totalBytes: profile.diskTotalBytes,
                        usedBytes: diskUsed,
                        availableBytes: profile.diskTotalBytes - diskUsed,
                        usagePercent: diskPercent,
                        inodesTotal: 32_768_000,
                        inodesUsed: 1_284_301
                    ),
                    DiskMetrics.Filesystem(
                        device: "/dev/nvme0n1p1",
                        mountPoint: "/boot/efi",
                        fstype: "vfat",
                        totalBytes: 536_870_912,
                        usedBytes: 12_582_912,
                        availableBytes: 524_288_000,
                        usagePercent: 2.3,
                        inodesTotal: nil,
                        inodesUsed: nil
                    ),
                ]
            ),
            network: NetworkMetrics(
                rxBytesTotal: receivedTotal,
                txBytesTotal: sentTotal,
                rxBytesPerSec: receiveRate,
                txBytesPerSec: sendRate,
                interfaces: [
                    NetworkMetrics.Interface(
                        name: "eth0",
                        rxBytes: receivedTotal,
                        txBytes: sentTotal,
                        rxBytesPerSec: receiveRate,
                        txBytesPerSec: sendRate,
                        rxErrors: 0,
                        txErrors: 0,
                        up: true
                    ),
                    NetworkMetrics.Interface(
                        name: "lo",
                        rxBytes: 1_284_000,
                        txBytes: 1_284_000,
                        rxBytesPerSec: 0,
                        txBytesPerSec: 0,
                        rxErrors: 0,
                        txErrors: 0,
                        up: true
                    ),
                ]
            ),
            warmingUp: false
        )
    }

    public func activity(limit: Int, since: Int64?) async throws -> [ActivityEvent] {
        var found = events
        if let since {
            found = found.filter { $0.id > since }
        }
        return Array(found.prefix(limit))
    }

    // MARK: Processes

    public func processes(sort: ProcessSort, limit: Int, search: String?) async throws -> ProcessList {
        var items = demoProcesses()
        if let search, !search.isEmpty {
            let needle = search.lowercased()
            items = items.filter {
                $0.name.lowercased().contains(needle) || $0.command.lowercased().contains(needle)
            }
        }
        switch sort {
        case .cpu: items.sort { $0.cpuPercent > $1.cpuPercent }
        case .memory: items.sort { $0.memoryBytes > $1.memoryBytes }
        case .pid: items.sort { $0.pid < $1.pid }
        case .name: items.sort { $0.name < $1.name }
        }
        let capped = Array(items.prefix(max(limit, 1)))
        return ProcessList(total: capped.count, items: capped, sort: sort.rawValue, limit: limit)
    }

    public func signalProcess(pid: Int32, signal: ProcessSignal) async throws {
        record(action: "process.signal", resourceType: "process", resourceID: String(pid),
               summary: "Sent SIG\(signal.rawValue) to process \(pid)")
    }

    // MARK: Users

    public func users(includeSystem: Bool) async throws -> UserList {
        let all = profile.people.map { self.demoUser($0) }
        let shown = includeSystem ? all : all.filter { !$0.isSystem }
        return UserList(
            total: shown.count,
            items: shown,
            people: all.filter { !$0.isSystem }.count,
            system: all.filter { $0.isSystem }.count
        )
    }

    public func groups() async throws -> [LinuxGroup] {
        [
            LinuxGroup(name: "root", gid: 0, members: []),
            LinuxGroup(name: "sudo", gid: 27, members: profile.people.filter { $0.sudo }.map { $0.username }),
            LinuxGroup(name: "docker", gid: 999, members: profile.people.filter { !$0.system }.map { $0.username }),
            LinuxGroup(name: "www-data", gid: 33, members: []),
        ]
    }

    public func user(named name: String) async throws -> LinuxUser {
        guard let spec = profile.people.first(where: { $0.username == name }) else {
            throw DemoAgentClient.notFound("user", name)
        }
        return demoUser(spec)
    }

    public func createUser(_ request: NewUser) async throws -> LinuxUser {
        record(action: "user.create", resourceType: "user", resourceID: request.username,
               summary: "Created user \(request.username)")
        return LinuxUser(
            username: request.username,
            uid: 1100,
            gid: 1100,
            fullName: request.fullName,
            home: "/home/\(request.username)",
            shell: request.shell ?? "/bin/bash",
            groups: request.groups ?? [request.username],
            isSystem: false,
            canSudo: (request.groups ?? []).contains("sudo"),
            locked: false,
            hasPassword: request.password != nil,
            sshKeyCount: 0,
            lastLogin: nil
        )
    }

    public func updateUser(named name: String, changes: UserChanges) async throws -> LinuxUser {
        let existing = try await user(named: name)
        record(action: "user.update", resourceType: "user", resourceID: name,
               summary: "Updated user \(name)")
        return LinuxUser(
            username: existing.username,
            uid: existing.uid,
            gid: existing.gid,
            fullName: changes.fullName ?? existing.fullName,
            home: existing.home,
            shell: changes.shell ?? existing.shell,
            groups: changes.groups ?? existing.groups,
            isSystem: existing.isSystem,
            canSudo: (changes.groups ?? existing.groups).contains("sudo"),
            locked: changes.locked ?? existing.locked,
            hasPassword: existing.hasPassword,
            sshKeyCount: existing.sshKeyCount,
            lastLogin: existing.lastLogin
        )
    }

    public func deleteUser(named name: String, removeHome: Bool) async throws {
        record(action: "user.delete", resourceType: "user", resourceID: name,
               summary: "Deleted user \(name)")
    }

    public func sshKeys(forUser name: String) async throws -> [SSHKeyEntry] {
        guard let spec = profile.people.first(where: { $0.username == name }), !spec.system else {
            return []
        }
        return [
            SSHKeyEntry(
                fingerprint: "SHA256:2n4Ld9KqVQ0oN6v1TzL8bR3uYcW7jH5pXeA1sDfGhIk",
                type: "ssh-ed25519",
                comment: "\(spec.username)@demo-mac"
            )
        ]
    }

    public func addSSHKey(forUser name: String, publicKey: String) async throws {
        record(action: "user.key.add", resourceType: "user", resourceID: name,
               summary: "Added an SSH key to \(name)")
    }

    public func removeSSHKey(forUser name: String, fingerprint: String) async throws {
        record(action: "user.key.remove", resourceType: "user", resourceID: name,
               summary: "Removed an SSH key from \(name)")
    }

    // MARK: Services

    public func services(type: String?) async throws -> [ServiceUnit] {
        guard capabilities.services else {
            throw DemoAgentClient.unavailable("Service management")
        }
        return profile.services.map { self.demoService($0) }
    }

    public func service(unit: String) async throws -> ServiceUnitDetail {
        guard capabilities.services else {
            throw DemoAgentClient.unavailable("Service management")
        }
        guard let spec = profile.services.first(where: { $0.unit == unit || $0.display == unit }) else {
            throw DemoAgentClient.notFound("service", unit)
        }
        let state = serviceStates[spec.unit] ?? spec.state
        return ServiceUnitDetail(
            name: spec.unit,
            displayName: spec.display,
            description: spec.summary,
            state: state,
            activeState: state == "running" ? "active" : (state == "failed" ? "failed" : "inactive"),
            subState: state == "running" ? "running" : "dead",
            enabled: "enabled",
            mainPID: state == "running" ? 1284 : nil,
            memoryBytes: state == "running" ? 94_371_840 : nil,
            cpuUsageNsec: state == "running" ? 18_204_913_000 : nil,
            tasksCurrent: state == "running" ? 12 : nil,
            tasksMax: 4_915,
            restartCount: state == "failed" ? 17 : 0,
            activeSince: state == "running"
                ? Int64(Date().timeIntervalSince1970) - 412_004
                : nil,
            fragmentPath: "/lib/systemd/system/\(spec.unit)",
            result: state == "failed" ? "exit-code" : "success",
            execMainStatus: state == "failed" ? 1 : 0,
            documentation: ["man:\(spec.display)(8)"]
        )
    }

    public func performServiceAction(_ action: ServiceAction, unit: String) async throws {
        guard capabilities.services else {
            throw DemoAgentClient.unavailable("Service management")
        }
        // The UI may pass "nginx" where the specs say "nginx.service", exactly
        // as the agent's own route does. Resolve before recording the override,
        // or the listing would never reflect the change.
        let name = serviceUnitName(for: unit)
        switch action {
        case .start, .restart, .reload:
            serviceStates[name] = "running"
        case .stop:
            serviceStates[name] = "stopped"
        case .enable, .disable:
            break
        }
        record(action: "service.\(action.rawValue)", resourceType: "service", resourceID: name,
               summary: "\(action.completedLabel) \(name)")
    }

    // MARK: Docker

    public func dockerInfo() async throws -> DockerInfo {
        let list = demoContainers()
        return DockerInfo(
            version: "27.3.1",
            apiVersion: "1.43",
            rootDir: "/var/lib/docker",
            storageDriver: "overlay2",
            containersTotal: list.count,
            containersRunning: list.filter { $0.isRunning }.count,
            containersStopped: list.filter { $0.isStopped }.count,
            containersPaused: 0,
            images: list.count + 2,
            cpus: profile.threads,
            memoryBytes: profile.memoryTotalBytes,
            cgroupVersion: "2",
            liveRestore: false,
            warnings: nil
        )
    }

    public func containers(all: Bool, stats: Bool) async throws -> DockerContainerList {
        var items = demoContainers()
        if !all {
            items = items.filter { $0.isRunning }
        }
        return DockerContainerList(
            total: items.count,
            items: items,
            running: items.filter { $0.isRunning }.count,
            statsSampled: stats ? items.count : 0,
            statsTruncated: false
        )
    }

    public func container(id: String, revealEnvironment: Bool) async throws -> DockerContainerDetail {
        let matches = demoContainers().first { $0.id == id || $0.shortID == id || $0.name == id }
        guard let container = matches else {
            throw DemoAgentClient.notFound("container", id)
        }
        return DockerContainerDetail(
            id: container.id,
            shortID: container.shortID,
            name: container.name,
            image: container.image,
            imageID: container.imageID,
            state: container.state,
            status: container.status,
            health: container.health,
            createdAt: container.createdAt,
            startedAt: container.startedAt,
            finishedAt: container.isRunning ? nil : container.createdAt + 42,
            restartCount: container.restartCount,
            exitCode: container.isRunning ? nil : 0,
            ports: container.ports,
            labels: container.labels,
            composeProject: container.composeProject,
            composeService: container.composeService,
            networks: [
                DockerNetworkAttachment(
                    name: "\(profile.projectName ?? "demo")_default",
                    ipAddress: "172.24.0.4",
                    gateway: "172.24.0.1",
                    macAddress: "02:42:ac:18:00:04"
                )
            ],
            command: ["node", "dist/server.js"],
            entrypoint: ["docker-entrypoint.sh"],
            workingDir: "/app",
            user: "node",
            tty: false,
            platform: "linux",
            restartPolicy: DockerRestartPolicy(name: "unless-stopped", maxRetryCount: 0),
            mounts: [
                DockerMount(type: "volume", source: "estatify_uploads", destination: "/app/uploads", mode: "rw", rw: true)
            ],
            env: [
                DockerEnvVar(key: "NODE_ENV", value: "production", masked: false),
                DockerEnvVar(key: "PORT", value: "3000", masked: false),
                // The masked case is the one worth seeing in a demo: the UI has
                // to render a deliberate "hidden" affordance, not an empty row.
                DockerEnvVar(
                    key: "DATABASE_URL",
                    value: revealEnvironment ? "postgres://estatify:demo@postgres:5432/estatify" : nil,
                    masked: !revealEnvironment
                ),
                DockerEnvVar(
                    key: "SESSION_SECRET",
                    value: revealEnvironment ? "demo-secret-not-a-real-credential" : nil,
                    masked: !revealEnvironment
                ),
            ],
            healthCheck: DockerHealthCheck(
                status: container.health,
                failingStreak: 0,
                test: ["CMD-SHELL", "curl -fsS http://localhost:3000/health || exit 1"]
            )
        )
    }

    public func containerStats(id: String) async throws -> DockerStats {
        let used = Int64(random.double(in: 120_000_000...900_000_000))
        let limit: Int64 = 2_147_483_648
        return DockerStats(
            cpuPercent: random.double(in: 0.4...18),
            memoryBytes: used,
            memoryLimitBytes: limit,
            memoryPercent: Double(used) / Double(limit) * 100,
            onlineCPUs: profile.threads
        )
    }

    public func containerLogs(id: String, tail: Int, since: Int64?, timestamps: Bool) async throws -> [LogLine] {
        Array(demoLogLines(source: id).suffix(max(tail, 1)))
    }

    public func performContainerAction(_ action: ContainerAction, id: String, graceSeconds: Int?) async throws {
        // The UI may pass a name, a short id or a full id; the session's
        // overrides are keyed by name, so resolve first or a "Stop" would set a
        // key nothing ever reads and the row would never change.
        let name = containerName(for: id)
        switch action {
        case .start, .restart, .unpause:
            containerStates[name] = true
        case .stop, .pause:
            containerStates[name] = false
        }
        record(action: "docker.container.\(action.rawValue)", resourceType: "container", resourceID: id,
               summary: "\(action.completedLabel) \(id)")
    }

    public func removeContainer(id: String, force: Bool, removeVolumes: Bool) async throws {
        record(action: "docker.container.remove", resourceType: "container", resourceID: id,
               summary: "Removed \(id)")
    }

    public func images() async throws -> [DockerImage] {
        var seen: [String] = []
        var result: [DockerImage] = []
        for (index, spec) in profile.containers.enumerated() where !seen.contains(spec.image) {
            seen.append(spec.image)
            let parts = spec.image.split(separator: ":", maxSplits: 1).map(String.init)
            result.append(DockerImage(
                id: "sha256:\(DemoAgentClient.fakeDigest(spec.image))",
                shortID: String(DemoAgentClient.fakeDigest(spec.image).prefix(12)),
                repoTags: [spec.image],
                repository: parts.first,
                tag: parts.count > 1 ? parts[1] : "latest",
                sizeBytes: Int64(64_000_000 + index * 31_400_000),
                createdAt: Int64(Date().timeIntervalSince1970) - Int64(86_400 * (index + 2)),
                containers: 1,
                dangling: false
            ))
        }
        return result
    }

    public func volumes() async throws -> [DockerVolume] {
        let project = profile.projectName ?? "demo"
        return [
            DockerVolume(
                name: "\(project)_postgres_data",
                driver: "local",
                mountpoint: "/var/lib/docker/volumes/\(project)_postgres_data/_data",
                createdAt: Int64(Date().timeIntervalSince1970) - 4_218_640,
                labels: ["com.docker.compose.project": project],
                sizeBytes: 18_412_838_912,
                inUse: true
            ),
            DockerVolume(
                name: "\(project)_uploads",
                driver: "local",
                mountpoint: "/var/lib/docker/volumes/\(project)_uploads/_data",
                createdAt: Int64(Date().timeIntervalSince1970) - 4_218_600,
                labels: ["com.docker.compose.project": project],
                sizeBytes: 3_104_882_176,
                inUse: true
            ),
        ]
    }

    public func networks() async throws -> [DockerNetwork] {
        let project = profile.projectName ?? "demo"
        return [
            DockerNetwork(
                id: DemoAgentClient.fakeDigest("bridge"),
                name: "bridge",
                driver: "bridge",
                scope: "local",
                internal: false,
                subnet: "172.17.0.0/16",
                gateway: "172.17.0.1",
                containerCount: 0
            ),
            DockerNetwork(
                id: DemoAgentClient.fakeDigest(project),
                name: "\(project)_default",
                driver: "bridge",
                scope: "local",
                internal: false,
                subnet: "172.24.0.0/16",
                gateway: "172.24.0.1",
                containerCount: profile.containers.count
            ),
        ]
    }

    // MARK: Projects

    public func projects() async throws -> ProjectList {
        guard let name = profile.projectName else {
            return ProjectList(total: 0, items: [], running: 0, degraded: 0)
        }
        let project = try await self.project(named: name)
        return ProjectList(
            total: 1,
            items: [project],
            running: project.isFullyRunning ? 1 : 0,
            degraded: project.isPartiallyRunning ? 1 : 0
        )
    }

    public func project(named name: String) async throws -> Project {
        guard let projectName = profile.projectName, projectName == name else {
            throw DemoAgentClient.notFound("project", name)
        }
        let items = demoContainers()
        let running = items.filter { $0.isRunning }.count
        return Project(
            name: projectName,
            serviceCount: profile.containers.count,
            containerCount: items.count,
            running: running,
            state: running == items.count ? "running" : (running == 0 ? "stopped" : "partial"),
            workingDir: "/srv/\(projectName)",
            services: profile.containers.map { $0.service },
            containers: items
        )
    }

    // MARK: Databases

    public func databaseInstances() async throws -> [DatabaseInstance] {
        guard capabilities.postgres else { return [] }
        return [DatabaseInstance(port: 5432, socketDir: "/var/run/postgresql", reachable: true)]
    }

    public func postgresOverview() async throws -> PostgresOverview {
        guard capabilities.postgres else {
            throw DemoAgentClient.unavailable("PostgreSQL")
        }
        return PostgresOverview(
            version: "16.4",
            versionNum: 160_004,
            uptimeSeconds: profile.uptimeSeconds - 120,
            startedAt: Int64(Date().timeIntervalSince1970) - profile.uptimeSeconds + 120,
            dataDirectory: "/var/lib/postgresql/16/main",
            maxConnections: 100,
            currentConnections: 14,
            connectionUsagePercent: 14,
            databaseCount: 3,
            totalSizeBytes: 18_412_838_912,
            cacheHitRatio: 99.2,
            transactionsCommitted: 41_882_913,
            transactionsRolledBack: 1_204,
            deadlocks: 0,
            health: "healthy",
            healthReason: nil
        )
    }

    public func postgresDatabases() async throws -> [PostgresDatabase] {
        guard capabilities.postgres else {
            throw DemoAgentClient.unavailable("PostgreSQL")
        }
        return [
            PostgresDatabase(name: "estatify", owner: "estatify", sizeBytes: 17_884_901_376, encoding: "UTF8", collation: "en_GB.UTF-8", connectionLimit: -1, isTemplate: false, tableCount: 42),
            PostgresDatabase(name: "postgres", owner: "postgres", sizeBytes: 8_405_504, encoding: "UTF8", collation: "en_GB.UTF-8", connectionLimit: -1, isTemplate: false, tableCount: 0),
            PostgresDatabase(name: "template1", owner: "postgres", sizeBytes: 7_520_783, encoding: "UTF8", collation: "en_GB.UTF-8", connectionLimit: -1, isTemplate: true, tableCount: 0),
        ]
    }

    public func postgresTables(database: String?) async throws -> [PostgresTable] {
        guard capabilities.postgres else {
            throw DemoAgentClient.unavailable("PostgreSQL")
        }
        return [
            PostgresTable(schema: "public", name: "properties", rowsEstimate: 184_302, totalSizeBytes: 2_148_007_936, tableSizeBytes: 1_610_612_736, indexSizeBytes: 537_395_200, seqScans: 214, indexScans: 8_412_004, lastVacuum: nil, lastAnalyze: nil),
            PostgresTable(schema: "public", name: "viewings", rowsEstimate: 918_441, totalSizeBytes: 3_221_225_472, tableSizeBytes: 2_684_354_560, indexSizeBytes: 536_870_912, seqScans: 12, indexScans: 21_004_881, lastVacuum: nil, lastAnalyze: nil),
            PostgresTable(schema: "public", name: "users", rowsEstimate: 12_884, totalSizeBytes: 41_943_040, tableSizeBytes: 25_165_824, indexSizeBytes: 16_777_216, seqScans: 4, indexScans: 984_113, lastVacuum: nil, lastAnalyze: nil),
        ]
    }

    public func postgresConnections(includeQueryText: Bool) async throws -> [PostgresConnection] {
        guard capabilities.postgres else {
            throw DemoAgentClient.unavailable("PostgreSQL")
        }
        return [
            PostgresConnection(
                pid: 18_412, user: "estatify", database: "estatify", clientAddr: "172.24.0.4",
                applicationName: "estatify-api", state: "active", queryStart: nil, stateChange: nil,
                waitEventType: nil, backendType: "client backend",
                queryPreview: includeQueryText ? "SELECT * FROM properties WHERE city = $1 LIMIT 20" : nil
            ),
            PostgresConnection(
                pid: 18_413, user: "estatify", database: "estatify", clientAddr: "172.24.0.6",
                applicationName: "estatify-worker", state: "idle", queryStart: nil, stateChange: nil,
                waitEventType: "Client", backendType: "client backend", queryPreview: nil
            ),
            PostgresConnection(
                pid: 18_401, user: nil, database: nil, clientAddr: nil,
                applicationName: "", state: nil, queryStart: nil, stateChange: nil,
                waitEventType: "Activity", backendType: "checkpointer", queryPreview: nil
            ),
        ]
    }

    public func postgresRoles() async throws -> [PostgresRole] {
        guard capabilities.postgres else {
            throw DemoAgentClient.unavailable("PostgreSQL")
        }
        return [
            PostgresRole(name: "postgres", isSuperuser: true, canCreateDB: true, canCreateRole: true, canLogin: true, isReplication: true, bypassesRLS: true, connectionLimit: -1, validUntil: nil),
            PostgresRole(name: "estatify", isSuperuser: false, canCreateDB: false, canCreateRole: false, canLogin: true, isReplication: false, bypassesRLS: false, connectionLimit: 40, validUntil: nil),
            PostgresRole(name: "readonly", isSuperuser: false, canCreateDB: false, canCreateRole: false, canLogin: true, isReplication: false, bypassesRLS: false, connectionLimit: 5, validUntil: nil),
        ]
    }

    // MARK: Logs

    public func fileLog(path: String, lines: Int, since: Int64?, filter: String?, isRegex: Bool) async throws -> LogBatch {
        var found = demoLogLines(source: path)
        if let filter, !filter.isEmpty {
            found = found.filter { $0.message.localizedCaseInsensitiveContains(filter) }
        }
        return LogBatch(lines: Array(found.suffix(max(lines, 1))), source: "file", truncated: false)
    }

    public func journal(unit: String?, lines: Int, since: Int64?, filter: String?, isRegex: Bool) async throws -> LogBatch {
        guard capabilities.journal else {
            throw DemoAgentClient.unavailable("The system journal")
        }
        var found = demoLogLines(source: unit ?? "system")
        if let filter, !filter.isEmpty {
            found = found.filter { $0.message.localizedCaseInsensitiveContains(filter) }
        }
        return LogBatch(lines: Array(found.suffix(max(lines, 1))), source: "journal", truncated: false)
    }

    // MARK: Files

    public func listDirectory(path: String, showHidden: Bool, sort: FileSort, limit: Int, offset: Int) async throws -> DirectoryListing {
        let normalised = path.isEmpty ? "/" : path
        var entries = DemoAgentClient.tree(at: normalised, project: profile.projectName ?? "demo")
        if !showHidden {
            entries = entries.filter { !$0.name.hasPrefix(".") }
        }
        return DirectoryListing(
            path: normalised,
            parent: normalised == "/" ? nil : DemoAgentClient.parentPath(of: normalised),
            entries: entries,
            total: entries.count,
            truncated: false
        )
    }

    public func stat(path: String) async throws -> FileEntry {
        let parent = DemoAgentClient.parentPath(of: path) ?? "/"
        let entries = DemoAgentClient.tree(at: parent, project: profile.projectName ?? "demo")
        guard let entry = entries.first(where: { $0.path == path }) else {
            throw DemoAgentClient.notFound("file", path)
        }
        return entry
    }

    public func readTextFile(path: String) async throws -> TextFileContents {
        let body = """
        # Demo file — \(path)
        #
        # Nothing here is real. This server does not exist and this file was
        # generated by ServerOS to show what the editor looks like.

        listen 80;
        server_name \(profile.hostname);
        root /srv/\(profile.projectName ?? "demo")/public;
        """
        return TextFileContents(
            path: path,
            content: body,
            encoding: "utf-8",
            lineCount: body.split(separator: "\n", omittingEmptySubsequences: false).count,
            sizeBytes: Int64(body.utf8.count),
            truncated: false,
            lineEnding: "lf",
            readonly: false
        )
    }

    public func downloadFile(path: String) async throws -> Data {
        Data("Demo file — \(path)\nThis server does not exist.\n".utf8)
    }

    public func writeTextFile(path: String, contents: String) async throws -> FileEntry {
        record(action: "file.write", resourceType: "file", resourceID: path,
               summary: "Wrote \(contents.utf8.count) bytes to \(path)")
        return DemoAgentClient.file(named: DemoAgentClient.lastComponent(of: path), at: path, size: Int64(contents.utf8.count))
    }

    public func createDirectory(path: String) async throws -> FileEntry {
        record(action: "file.mkdir", resourceType: "directory", resourceID: path,
               summary: "Created the folder \(path)")
        return DemoAgentClient.directory(named: DemoAgentClient.lastComponent(of: path), at: path)
    }

    public func move(from: String, to: String) async throws -> FileEntry {
        record(action: "file.rename", resourceType: "file", resourceID: from,
               summary: "Renamed \(from) to \(to)")
        return DemoAgentClient.file(named: DemoAgentClient.lastComponent(of: to), at: to, size: 4_096)
    }

    public func changeMode(path: String, mode: String) async throws -> FileEntry {
        record(action: "file.chmod", resourceType: "file", resourceID: path,
               summary: "Changed \(path) to \(mode)")
        return DemoAgentClient.file(named: DemoAgentClient.lastComponent(of: path), at: path, size: 4_096)
    }

    public func deleteFile(path: String, recursive: Bool) async throws -> FileDeletion {
        record(action: "file.delete", resourceType: "file", resourceID: path,
               summary: "Moved \(path) to the trash")
        return FileDeletion(
            path: path,
            trashed: true,
            restorePath: "/var/lib/serveros/trash\(path)",
            filesDeleted: 1,
            directoriesDeleted: 0,
            bytesFreed: 4_096
        )
    }

    public func uploadFile(path: String, contents: Data, overwrite: Bool) async throws -> FileEntry {
        record(action: "file.upload", resourceType: "file", resourceID: path,
               summary: "Uploaded \(path)")
        return DemoAgentClient.file(named: DemoAgentClient.lastComponent(of: path), at: path, size: Int64(contents.count))
    }

    // MARK: - Building the fake world

    private func loadAverage() -> LoadAverage {
        let base = cpuWalk.value / 100 * Double(profile.threads)
        return LoadAverage(
            one: (base * 1.05 * 100).rounded() / 100,
            five: (base * 0.94 * 100).rounded() / 100,
            fifteen: (base * 0.81 * 100).rounded() / 100
        )
    }

    private func demoUser(_ spec: DemoUserSpec) -> LinuxUser {
        LinuxUser(
            username: spec.username,
            uid: spec.uid,
            gid: spec.uid,
            fullName: spec.fullName,
            home: spec.username == "root" ? "/root" : "/home/\(spec.username)",
            shell: spec.shell,
            groups: spec.sudo ? [spec.username, "sudo", "docker"] : [spec.username],
            isSystem: spec.system,
            canSudo: spec.sudo,
            locked: spec.system && spec.username != "root",
            hasPassword: !spec.system,
            sshKeyCount: spec.system ? 0 : 1,
            lastLogin: spec.system ? nil : Int64(Date().timeIntervalSince1970) - 5_400
        )
    }

    private func demoService(_ spec: DemoServiceSpec) -> ServiceUnit {
        let state = serviceStates[spec.unit] ?? spec.state
        return ServiceUnit(
            name: spec.unit,
            displayName: spec.display,
            description: spec.summary,
            loadState: "loaded",
            activeState: state == "running" ? "active" : (state == "failed" ? "failed" : "inactive"),
            subState: state == "running" ? "running" : "dead",
            state: state,
            enabled: "enabled",
            canStart: state != "running",
            canStop: state == "running",
            canRestart: true
        )
    }

    private func demoContainers() -> [DockerContainer] {
        let project = profile.projectName ?? "demo"
        let now = Int64(Date().timeIntervalSince1970)
        var result: [DockerContainer] = []

        for (index, spec) in profile.containers.enumerated() {
            let running = containerStates[spec.name] ?? spec.running
            var ports: [DockerPort] = []
            if let containerPort = spec.containerPort {
                ports.append(DockerPort(
                    private: containerPort,
                    public: spec.publishedPort,
                    type: "tcp",
                    ip: spec.publishedPort == nil ? nil : "0.0.0.0"
                ))
            }
            let digest = DemoAgentClient.fakeDigest("\(profile.id)-\(spec.name)")
            result.append(DockerContainer(
                id: digest,
                shortID: String(digest.prefix(12)),
                name: spec.name,
                image: spec.image,
                imageID: "sha256:\(DemoAgentClient.fakeDigest(spec.image))",
                state: running ? "running" : "exited",
                status: running ? "Up 3 days" : "Exited (0) 2 days ago",
                health: running ? spec.health : nil,
                createdAt: now - Int64(86_400 * (index + 2)),
                startedAt: running ? now - Int64(259_200) : nil,
                restartCount: 0,
                ports: ports,
                labels: [
                    "com.docker.compose.project": project,
                    "com.docker.compose.service": spec.service,
                ],
                composeProject: project,
                composeService: spec.service,
                networks: ["\(project)_default"],
                cpuPercent: running ? (cpuWalk.value / Double(max(profile.containers.count, 1))) : nil,
                memoryBytes: running ? Int64(180_000_000 + index * 64_000_000) : nil,
                memoryLimitBytes: 2_147_483_648,
                memoryPercent: running ? Double(180 + index * 64) / 2_048 * 100 : nil
            ))
        }
        return result
    }

    /// Accept `nginx` or `nginx.service`, as the agent's route does.
    private func serviceUnitName(for unit: String) -> String {
        if let match = profile.services.first(where: { $0.unit == unit || $0.display == unit }) {
            return match.unit
        }
        return unit
    }

    /// Accept a name, a short id or a full id wherever the UI has one.
    private func containerName(for id: String) -> String {
        if profile.containers.contains(where: { $0.name == id }) {
            return id
        }
        if let match = demoContainers().first(where: { $0.id == id || $0.shortID == id }) {
            return match.name
        }
        return id
    }

    private func demoProcesses() -> [ProcessInfo] {
        let now = Int64(Date().timeIntervalSince1970)
        var result: [ProcessInfo] = [
            ProcessInfo(pid: 1, ppid: 0, name: "systemd", command: "/sbin/init", user: "root", uid: 0, state: "sleeping", cpuPercent: 0.1, memoryBytes: 12_582_912, memoryPercent: 0.1, threads: 1, startedAt: now - profile.uptimeSeconds),
            ProcessInfo(pid: 842, ppid: 1, name: "dockerd", command: "/usr/bin/dockerd -H fd://", user: "root", uid: 0, state: "sleeping", cpuPercent: 1.4, memoryBytes: 184_549_376, memoryPercent: 0.6, threads: 24, startedAt: now - profile.uptimeSeconds + 40),
            ProcessInfo(pid: 1_284, ppid: 1, name: "nginx", command: "nginx: master process /usr/sbin/nginx", user: "root", uid: 0, state: "sleeping", cpuPercent: 0.3, memoryBytes: 25_165_824, memoryPercent: 0.1, threads: 1, startedAt: now - 412_004),
            ProcessInfo(pid: 4_918, ppid: 842, name: "node", command: "node dist/server.js", user: "deploy", uid: 1_000, state: "running", cpuPercent: 12.8, memoryBytes: 612_368_384, memoryPercent: 1.8, threads: 11, startedAt: now - 259_200),
            ProcessInfo(pid: 5_002, ppid: 842, name: "postgres", command: "postgres: estatify estatify 172.24.0.4(51422) SELECT", user: "postgres", uid: 114, state: "running", cpuPercent: 8.2, memoryBytes: 428_867_584, memoryPercent: 1.2, threads: 1, startedAt: now - 259_100),
            ProcessInfo(pid: 5_113, ppid: 1, name: "serveros-agent", command: "/usr/local/bin/serveros-agent", user: "root", uid: 0, state: "sleeping", cpuPercent: 0.2, memoryBytes: 9_437_184, memoryPercent: 0.1, threads: 4, startedAt: now - 86_400),
        ]
        if !capabilities.services {
            result.removeAll { $0.name == "systemd" }
        }
        return result
    }

    private func demoLogLines(source: String) -> [LogLine] {
        let now = Int64(Date().timeIntervalSince1970)
        let script: [(String, String)] = [
            ("info", "Server started on port 3000"),
            ("info", "Connected to PostgreSQL at postgres:5432"),
            ("info", "GET /api/properties 200 — 41ms"),
            ("info", "GET /api/properties/1842 200 — 12ms"),
            ("warn", "Cache miss for key properties:city:addis-ababa"),
            ("info", "POST /api/viewings 201 — 88ms"),
            ("error", "Database query timed out after 5000ms"),
            ("info", "Retrying query (attempt 2 of 3)"),
            ("info", "GET /api/health 200 — 2ms"),
        ]
        var result: [LogLine] = []
        for (index, entry) in script.enumerated() {
            result.append(LogLine(
                timestamp: now - Int64((script.count - index) * 7),
                level: entry.0,
                message: entry.1,
                raw: nil,
                source: source,
                stream: entry.0 == "error" ? "stderr" : "stdout"
            ))
        }
        return result
    }

    private func record(action: String, resourceType: String, resourceID: String, summary: String) {
        let event = ActivityEvent(
            id: nextEventID,
            at: Int64(Date().timeIntervalSince1970),
            action: action,
            resourceType: resourceType,
            resourceID: resourceID,
            actor: "Demo",
            peer: "127.0.0.1",
            outcome: "succeeded",
            summary: summary
        )
        nextEventID += 1
        events.insert(event, at: 0)
        if events.count > 200 {
            events.removeLast(events.count - 200)
        }
    }

    private static func seedEvents(profile: DemoProfile) -> (events: [ActivityEvent], nextID: Int64) {
        let now = Int64(Date().timeIntervalSince1970)
        let script: [(String, String, String, String, Int64)] = [
            ("docker.container.restart", "container", "estatify-api-1", "Restarted estatify-api-1", 240),
            ("service.reload", "service", "nginx.service", "Reloaded nginx", 1_920),
            ("file.write", "file", "/etc/nginx/sites-enabled/default", "Wrote 1,284 bytes to /etc/nginx/sites-enabled/default", 3_600),
            ("user.key.add", "user", "deploy", "Added an SSH key to deploy", 86_400),
            ("agent.start", "agent", profile.id, "ServerOS agent 0.1.0 started", 90_000),
        ]
        var result: [ActivityEvent] = []
        var identifier: Int64 = 1
        for entry in script {
            result.append(ActivityEvent(
                id: identifier,
                at: now - entry.4,
                action: entry.0,
                resourceType: entry.1,
                resourceID: entry.2,
                actor: "Demo",
                peer: "127.0.0.1",
                outcome: "succeeded",
                summary: entry.3
            ))
            identifier += 1
        }
        return (result.sorted { $0.at > $1.at }, identifier)
    }

    // MARK: - Small helpers

    /// A hex string that looks like a Docker digest but is derived from a name,
    /// so the same demo container has the same id on every launch.
    static func fakeDigest(_ text: String) -> String {
        var random = DemoRandom(text: text)
        var out = ""
        while out.count < 64 {
            out += String(random.next(), radix: 16)
        }
        return String(out.prefix(64))
    }

    static func parentPath(of path: String) -> String? {
        guard path != "/" else { return nil }
        var components = path.split(separator: "/").map(String.init)
        guard !components.isEmpty else { return nil }
        components.removeLast()
        return components.isEmpty ? "/" : "/" + components.joined(separator: "/")
    }

    static func lastComponent(of path: String) -> String {
        path.split(separator: "/").map(String.init).last ?? path
    }

    static func directory(named name: String, at path: String) -> FileEntry {
        FileEntry(
            name: name, path: path, kind: "directory", sizeBytes: 4_096,
            modifiedAt: Int64(Date().timeIntervalSince1970) - 86_400,
            mode: "0755", modeOctal: 0o755, owner: "root", group: "root", uid: 0, gid: 0,
            isSymlink: false, symlinkTarget: nil, isReadable: true, isWritable: true,
            extension: nil, isText: false
        )
    }

    static func file(named name: String, at path: String, size: Int64) -> FileEntry {
        let dot = name.split(separator: ".").map(String.init)
        return FileEntry(
            name: name, path: path, kind: "file", sizeBytes: size,
            modifiedAt: Int64(Date().timeIntervalSince1970) - 3_600,
            mode: "0644", modeOctal: 0o644, owner: "root", group: "root", uid: 0, gid: 0,
            isSymlink: false, symlinkTarget: nil, isReadable: true, isWritable: true,
            extension: dot.count > 1 ? dot[dot.count - 1] : nil, isText: true
        )
    }

    /// A tiny synthetic filesystem — enough to browse two or three levels.
    ///
    /// An `if` chain rather than a `switch`, because one of the paths depends on
    /// the project name and an interpolated case pattern reads like a trick.
    static func tree(at path: String, project: String) -> [FileEntry] {
        let projectRoot = "/srv/\(project)"

        if path == "/" {
            return [
                directory(named: "etc", at: "/etc"),
                directory(named: "home", at: "/home"),
                directory(named: "srv", at: "/srv"),
                directory(named: "var", at: "/var"),
            ]
        }
        if path == "/etc" {
            return [
                directory(named: "nginx", at: "/etc/nginx"),
                file(named: "hostname", at: "/etc/hostname", size: 14),
                file(named: "hosts", at: "/etc/hosts", size: 221),
                file(named: "os-release", at: "/etc/os-release", size: 386),
            ]
        }
        if path == "/etc/nginx" {
            return [
                directory(named: "sites-enabled", at: "/etc/nginx/sites-enabled"),
                file(named: "nginx.conf", at: "/etc/nginx/nginx.conf", size: 1_482),
            ]
        }
        if path == "/srv" {
            return [directory(named: project, at: projectRoot)]
        }
        if path == projectRoot {
            return [
                file(named: "docker-compose.yml", at: "\(projectRoot)/docker-compose.yml", size: 2_184),
                file(named: ".env", at: "\(projectRoot)/.env", size: 412),
                directory(named: "public", at: "\(projectRoot)/public"),
            ]
        }
        if path == "/var" {
            return [directory(named: "log", at: "/var/log")]
        }
        if path == "/var/log" {
            return [
                file(named: "syslog", at: "/var/log/syslog", size: 4_182_004),
                file(named: "auth.log", at: "/var/log/auth.log", size: 918_441),
                directory(named: "nginx", at: "/var/log/nginx"),
            ]
        }
        if path == "/var/log/nginx" {
            return [
                file(named: "access.log", at: "/var/log/nginx/access.log", size: 18_884_913),
                file(named: "error.log", at: "/var/log/nginx/error.log", size: 214_004),
            ]
        }
        return []
    }

    static func notFound(_ kind: String, _ name: String) -> ServerOSError {
        ServerOSError(
            code: "not_found",
            headline: "No \(kind) named \u{201C}\(name)\u{201D} on this server.",
            causes: ["It may have been removed since this screen last loaded."],
            technical: nil,
            isRetryable: true
        )
    }

    static func unavailable(_ subsystem: String) -> ServerOSError {
        ServerOSError(
            code: "subsystem_unavailable",
            headline: "\(subsystem) is not available on this server.",
            causes: [],
            technical: "the demo server does not provide this subsystem",
            isRetryable: false
        )
    }
}
