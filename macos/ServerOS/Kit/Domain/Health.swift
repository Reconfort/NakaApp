//  Health.swift
//  ServerOS
//
//  The single most visible piece of logic in the product.
//
//  Everything the dashboard says — the dot, the headline, the sentence beneath
//  it, the button — comes from here. It is deliberately pure: inputs in, a
//  verdict out, no networking, no clock beyond what is passed in. That makes it
//  exhaustively testable, and it means the same verdict can be computed on a
//  future iOS app, in the control plane, or in a test, and agree every time.
//
//  Design rule, from the product brief: never communicate state through colour
//  alone. Every `ServerHealth` carries an icon, a label, a sentence and an
//  action, and the UI is expected to show all four.

import Foundation

/// A server's overall condition, ordered by severity so `max()` works.
public enum HealthState: Int, Comparable, Sendable, CaseIterable {
    case unknown = 0
    case healthy = 1
    case warning = 2
    case critical = 3
    case offline = 4

    public static func < (lhs: HealthState, rhs: HealthState) -> Bool {
        lhs.rawValue < rhs.rawValue
    }

    /// The short word shown next to the status dot.
    public var label: String {
        switch self {
        case .healthy: return "Healthy"
        case .warning: return "Needs Attention"
        case .critical: return "Critical"
        case .offline: return "Offline"
        case .unknown: return "Unknown"
        }
    }

    /// SF Symbol. Shape carries the meaning for anyone who cannot distinguish
    /// the colours.
    public var symbolName: String {
        switch self {
        case .healthy: return "checkmark.circle.fill"
        case .warning: return "exclamationmark.triangle.fill"
        case .critical: return "xmark.octagon.fill"
        case .offline: return "bolt.horizontal.circle.fill"
        case .unknown: return "questionmark.circle.fill"
        }
    }

    /// Spoken by VoiceOver in place of the dot.
    public var accessibilityLabel: String {
        switch self {
        case .healthy: return "Healthy"
        case .warning: return "Needs attention"
        case .critical: return "Critical"
        case .offline: return "Offline"
        case .unknown: return "Status unknown"
        }
    }
}

/// Where the UI should take someone who acts on a health verdict.
public enum HealthAction: Equatable, Sendable {
    case none
    case openStorage
    case openDocker(containerID: String?)
    case openServices(unit: String?)
    case openProcesses
    case openDatabases
    case reconnect
    case openLogs

    /// Button title. Nil means the card shows no button.
    public var title: String? {
        switch self {
        case .none: return nil
        case .openStorage: return "Review Storage"
        case .openDocker(let id): return id == nil ? "Open Docker" : "Open Container"
        case .openServices(let unit): return unit == nil ? "Open Services" : "Open Service"
        case .openProcesses: return "Open Processes"
        case .openDatabases: return "Open Databases"
        case .reconnect: return "Reconnect"
        case .openLogs: return "View Logs"
        }
    }
}

/// A complete verdict, ready to render.
public struct ServerHealth: Equatable, Sendable {
    public let state: HealthState
    /// One sentence explaining the state. Always present, always plain English.
    public let summary: String
    /// The specific finding, when there is one. Nil when everything is fine.
    public let reason: String?
    public let action: HealthAction

    public init(state: HealthState, summary: String, reason: String? = nil, action: HealthAction = .none) {
        self.state = state
        self.summary = summary
        self.reason = reason
        self.action = action
    }

    public static let unknown = ServerHealth(
        state: .unknown,
        summary: "ServerOS hasn't heard from this server yet.",
        reason: nil,
        action: .none
    )

    public static let offline = ServerHealth(
        state: .offline,
        summary: "ServerOS can't reach this server.",
        reason: "The agent didn't respond. The server may be offline, or the connection may have dropped.",
        action: .reconnect
    )
}

/// One thing that is wrong, before the rollup picks a winner.
public struct HealthFinding: Equatable, Sendable {
    public let state: HealthState
    public let summary: String
    public let reason: String
    public let action: HealthAction

    public init(state: HealthState, summary: String, reason: String, action: HealthAction) {
        self.state = state
        self.summary = summary
        self.reason = reason
        self.action = action
    }
}

/// Everything the evaluator needs to reach a verdict.
///
/// A struct rather than a long parameter list so a new signal can be added
/// without touching every call site, and so tests read as a table.
public struct HealthInput: Sendable {
    public var isReachable: Bool
    /// Seconds since the agent last answered. Nil when it never has.
    public var secondsSinceLastContact: TimeInterval?
    public var metrics: Metrics?
    public var stoppedContainers: [String]
    public var unhealthyContainers: [String]
    public var failedServices: [String]
    public var postgresHealth: String?
    public var postgresReason: String?

    public init(
        isReachable: Bool = true,
        secondsSinceLastContact: TimeInterval? = 0,
        metrics: Metrics? = nil,
        stoppedContainers: [String] = [],
        unhealthyContainers: [String] = [],
        failedServices: [String] = [],
        postgresHealth: String? = nil,
        postgresReason: String? = nil
    ) {
        self.isReachable = isReachable
        self.secondsSinceLastContact = secondsSinceLastContact
        self.metrics = metrics
        self.stoppedContainers = stoppedContainers
        self.unhealthyContainers = unhealthyContainers
        self.failedServices = failedServices
        self.postgresHealth = postgresHealth
        self.postgresReason = postgresReason
    }
}

/// Thresholds, in one place so they can be reviewed as a set.
///
/// These are judgement calls, not physics. They are gathered here because the
/// difference between a useful dashboard and an ignored one is whether its
/// warnings mean anything, and that is a tuning decision someone will revisit.
public enum HealthThresholds {
    /// Beyond this with no contact, the server is presumed offline. Three
    /// missed two-second metric ticks plus slack.
    public static let offlineAfterSeconds: TimeInterval = 90

    public static let diskWarningPercent: Double = 80
    public static let diskCriticalPercent: Double = 95
    public static let memoryWarningPercent: Double = 90
    public static let memoryCriticalPercent: Double = 97
    public static let cpuWarningPercent: Double = 90
    public static let swapWarningPercent: Double = 50

    /// Load average per core above which the machine is considered saturated.
    /// 1.0 per core means "fully busy"; 2.0 means twice as much work queued as
    /// the machine can run, which is where latency becomes visible.
    public static let loadPerCoreWarning: Double = 2.0
}

public enum HealthEvaluator {

    /// Produce the verdict shown on the server card and the server header.
    public static func evaluate(_ input: HealthInput) -> ServerHealth {
        // Unreachable beats everything: nothing else we know is current.
        if !input.isReachable {
            return .offline
        }
        if let since = input.secondsSinceLastContact, since > HealthThresholds.offlineAfterSeconds {
            return ServerHealth(
                state: .offline,
                summary: "ServerOS can't reach this server.",
                reason: "No response for \(Formatting.duration(seconds: Int(since))). The server may be offline, or the connection may have dropped.",
                action: .reconnect
            )
        }
        if input.metrics == nil && input.secondsSinceLastContact == nil {
            return .unknown
        }

        let findings = findings(for: input)

        guard let worst = findings.max(by: { $0.state < $1.state }) else {
            return ServerHealth(
                state: .healthy,
                summary: "Everything is operating normally.",
                reason: nil,
                action: .none
            )
        }

        // More than one problem: lead with the worst, but say how many there
        // are so the user knows the card is not the whole story.
        let sameSeverity = findings.filter { $0.state == worst.state }
        if sameSeverity.count > 1 {
            let others = sameSeverity.count - 1
            return ServerHealth(
                state: worst.state,
                summary: worst.summary,
                reason: "\(worst.reason) There \(others == 1 ? "is" : "are") also \(others) other \(others == 1 ? "issue" : "issues") at this level.",
                action: worst.action
            )
        }

        return ServerHealth(
            state: worst.state,
            summary: worst.summary,
            reason: worst.reason,
            action: worst.action
        )
    }

    /// Every problem found, most severe first. The server detail screen lists
    /// these rather than showing only the winner.
    public static func findings(for input: HealthInput) -> [HealthFinding] {
        var found: [HealthFinding] = []

        if let metrics = input.metrics {
            found.append(contentsOf: diskFindings(metrics.disk))
            found.append(contentsOf: memoryFindings(metrics.memory))
            found.append(contentsOf: cpuFindings(metrics.cpu, warmingUp: metrics.isWarmingUp))
        }

        if !input.failedServices.isEmpty {
            let names = Formatting.list(input.failedServices, limit: 2)
            found.append(HealthFinding(
                state: .critical,
                summary: input.failedServices.count == 1
                    ? "\(input.failedServices[0]) has failed."
                    : "\(input.failedServices.count) services have failed.",
                reason: "\(names) stopped unexpectedly and \(input.failedServices.count == 1 ? "has" : "have") not recovered.",
                action: .openServices(unit: input.failedServices.count == 1 ? input.failedServices[0] : nil)
            ))
        }

        if !input.unhealthyContainers.isEmpty {
            let names = Formatting.list(input.unhealthyContainers, limit: 2)
            found.append(HealthFinding(
                state: .critical,
                summary: input.unhealthyContainers.count == 1
                    ? "\(input.unhealthyContainers[0]) is unhealthy."
                    : "\(input.unhealthyContainers.count) containers are unhealthy.",
                reason: "\(names) \(input.unhealthyContainers.count == 1 ? "is" : "are") running but failing \(input.unhealthyContainers.count == 1 ? "its" : "their") health check.",
                action: .openDocker(containerID: input.unhealthyContainers.count == 1 ? input.unhealthyContainers[0] : nil)
            ))
        }

        if !input.stoppedContainers.isEmpty {
            let names = Formatting.list(input.stoppedContainers, limit: 2)
            found.append(HealthFinding(
                state: .warning,
                summary: input.stoppedContainers.count == 1
                    ? "\(input.stoppedContainers[0]) is not running."
                    : "\(input.stoppedContainers.count) containers are not running.",
                reason: "\(names) \(input.stoppedContainers.count == 1 ? "is" : "are") stopped.",
                action: .openDocker(containerID: input.stoppedContainers.count == 1 ? input.stoppedContainers[0] : nil)
            ))
        }

        switch input.postgresHealth {
        case "critical":
            found.append(HealthFinding(
                state: .critical,
                summary: "PostgreSQL needs attention.",
                reason: input.postgresReason ?? "The database reported a critical condition.",
                action: .openDatabases
            ))
        case "warning":
            found.append(HealthFinding(
                state: .warning,
                summary: "PostgreSQL needs attention.",
                reason: input.postgresReason ?? "The database reported a warning.",
                action: .openDatabases
            ))
        default:
            break
        }

        return found.sorted { $0.state > $1.state }
    }

    // MARK: - Individual signals

    private static func diskFindings(_ disk: DiskMetrics) -> [HealthFinding] {
        // Judge each filesystem, not the aggregate: a full `/var` with a roomy
        // `/home` averages out to "fine" and is anything but.
        var worst: HealthFinding?

        for fs in disk.filesystems {
            guard let percent = fs.usagePercent else { continue }
            let where_ = fs.mountPoint == "/" ? "The root filesystem" : fs.mountPoint

            let finding: HealthFinding?
            if percent >= HealthThresholds.diskCriticalPercent {
                finding = HealthFinding(
                    state: .critical,
                    summary: "Storage is almost full.",
                    reason: "\(where_) is \(Formatting.percent(percent)) full\(fs.availableBytes.map { " — only \(Formatting.bytes($0)) left" } ?? "").",
                    action: .openStorage
                )
            } else if percent >= HealthThresholds.diskWarningPercent {
                finding = HealthFinding(
                    state: .warning,
                    summary: "Storage is filling up.",
                    reason: "\(where_) is \(Formatting.percent(percent)) full.",
                    action: .openStorage
                )
            } else {
                finding = nil
            }

            if let finding, worst == nil || finding.state > worst!.state {
                worst = finding
            }
        }

        return worst.map { [$0] } ?? []
    }

    private static func memoryFindings(_ memory: MemoryMetrics) -> [HealthFinding] {
        var found: [HealthFinding] = []

        if memory.usagePercent >= HealthThresholds.memoryCriticalPercent {
            found.append(HealthFinding(
                state: .critical,
                summary: "Memory is nearly exhausted.",
                reason: "\(Formatting.percent(memory.usagePercent)) of memory is in use. The kernel may start killing processes.",
                action: .openProcesses
            ))
        } else if memory.usagePercent >= HealthThresholds.memoryWarningPercent {
            found.append(HealthFinding(
                state: .warning,
                summary: "Memory is running low.",
                reason: "\(Formatting.percent(memory.usagePercent)) of memory is in use.",
                action: .openProcesses
            ))
        }

        // Swap in use on a server usually means memory pressure, and swapping
        // is felt as latency long before memory reads as full.
        if memory.hasSwap && memory.swapUsagePercent >= HealthThresholds.swapWarningPercent {
            found.append(HealthFinding(
                state: .warning,
                summary: "The server is swapping.",
                reason: "\(Formatting.percent(memory.swapUsagePercent)) of swap is in use, which usually means memory pressure.",
                action: .openProcesses
            ))
        }

        return found
    }

    private static func cpuFindings(_ cpu: CPUMetrics, warmingUp: Bool) -> [HealthFinding] {
        // A single sample says nothing about sustained load, and the first
        // sample after connecting is always zero. Don't cry wolf on either.
        guard !warmingUp else { return [] }

        var found: [HealthFinding] = []

        if cpu.coreCount > 0 {
            let perCore = cpu.loadAverage.five / Double(cpu.coreCount)
            if perCore >= HealthThresholds.loadPerCoreWarning {
                found.append(HealthFinding(
                    state: .warning,
                    summary: "The server is under heavy load.",
                    reason: "Load average is \(Formatting.decimal(cpu.loadAverage.five, places: 2)) across \(cpu.coreCount) core\(cpu.coreCount == 1 ? "" : "s") — about \(Formatting.decimal(perCore, places: 1))× what it can run at once.",
                    action: .openProcesses
                ))
            }
        }

        // High instantaneous CPU with low load average is a busy moment, not a
        // problem. Only flag CPU when the load average agrees.
        if cpu.usagePercent >= HealthThresholds.cpuWarningPercent
            && cpu.coreCount > 0
            && cpu.loadAverage.one / Double(cpu.coreCount) >= 1.0
            && found.isEmpty {
            found.append(HealthFinding(
                state: .warning,
                summary: "CPU is saturated.",
                reason: "CPU has been at \(Formatting.percent(cpu.usagePercent)) with a load average of \(Formatting.decimal(cpu.loadAverage.one, places: 2)).",
                action: .openProcesses
            ))
        }

        return found
    }

    // MARK: - Fleet rollup

    /// The one-line summary at the top of the Overview screen.
    public static func fleetSummary(_ healths: [ServerHealth]) -> String {
        guard !healths.isEmpty else {
            return "No servers yet."
        }
        let offline = healths.filter { $0.state == .offline }.count
        let critical = healths.filter { $0.state == .critical }.count
        let warning = healths.filter { $0.state == .warning }.count

        if critical == 0 && warning == 0 && offline == 0 {
            return healths.count == 1
                ? "Your server is operating normally."
                : "All \(healths.count) servers are operating normally."
        }

        var parts: [String] = []
        if critical > 0 { parts.append("\(critical) need\(critical == 1 ? "s" : "") attention urgently") }
        if offline > 0 { parts.append("\(offline) \(offline == 1 ? "is" : "are") offline") }
        if warning > 0 { parts.append("\(warning) ha\(warning == 1 ? "s" : "ve") warnings") }
        return parts.joined(separator: ", ").capitalizingFirstLetter() + "."
    }
}

extension String {
    /// Uppercase the first character without touching the rest, so acronyms
    /// and product names survive.
    public func capitalizingFirstLetter() -> String {
        guard let first else { return self }
        return String(first).uppercased() + dropFirst()
    }
}
