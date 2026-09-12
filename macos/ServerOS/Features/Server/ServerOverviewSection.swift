//  ServerOverviewSection.swift
//  ServerOS
//
//  What is true about this server right now, in the order a person asks it.
//
//  The brief's rule governs the whole screen: **meaning first, data second.** A
//  wall of gauges is technically informative and practically exhausting, so the
//  page reads top to bottom as a conversation:
//
//    "Is it all right?"        → the health card, with a verdict and one action
//    "What else is wrong?"     → every finding, not only the worst one
//    "What are my resources?"  → decision cards, one question and one action each
//    "Is it getting worse?"    → CPU and memory over time
//    "What just happened?"     → recent activity
//
//  Every card here answers exactly one question and offers exactly one way to
//  act on it. A card that needed two buttons would be two cards — or, more
//  likely, a screen.

import SwiftUI

/// A server's Overview: the verdict, then the evidence.
public struct ServerOverviewSection: View {

    @Environment(\.colorScheme) private var scheme

    private let session: ServerSession
    private let navigation: NavigationModel

    /// PostgreSQL's summary is a request rather than a stream, so it gets its
    /// own state. A database that is unreachable must not take the whole
    /// Overview down with it — the card degrades, the screen does not.
    @State private var postgres: ScreenState<PostgresOverview> = .loading

    /// Likewise the account list, which the Users card summarises.
    @State private var users: ScreenState<UserList> = .loading

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.section) {
                healthBlock
                findingsCard
                decisionCards
                trends
                recentActivity
            }
            .readableWidth()
            .screenPadding()
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        // Capabilities land a moment after the connection is ready, so both are
        // in the key: a card must not be stranded on what was true mid-handshake.
        .task(id: loadTrigger) { await loadPostgres() }
        .task(id: loadTrigger) { await loadUsers() }
    }

    private var loadTrigger: OverviewLoadTrigger {
        OverviewLoadTrigger(isReady: session.phase.isReady, capabilities: session.capabilities)
    }

    // MARK: - 1. The verdict

    private var healthBlock: some View {
        HealthCard(
            title: "Server Health",
            health: session.health,
            metrics: session.metrics,
            onAction: perform
        )
    }

    /// Where a health verdict takes you when you act on it. One place, so the
    /// card, the findings list and the fleet dashboard can never disagree about
    /// what "Open Docker" means.
    private func perform(_ action: HealthAction) {
        switch action {
        case .none:
            break
        case .openStorage:
            navigation.currentFilePath = "/"
            navigation.select(section: .files)
        case .openDocker(let containerID):
            navigation.selectedContainerID = containerID
            navigation.select(section: .docker)
        case .openServices(let unit):
            navigation.selectedServiceUnit = unit
            navigation.select(section: .services)
        case .openProcesses:
            navigation.select(section: .processes)
        case .openDatabases:
            navigation.select(section: .databases)
        case .openLogs:
            navigation.select(section: .logs)
        case .reconnect:
            session.reconnect()
        }
    }

    // MARK: - 2. Everything else that is wrong

    /// The health card shows only the most severe finding. When there is more
    /// than one, the rest must be reachable without hunting for them — a user
    /// who fixes the disk and assumes they are done, while a service is still
    /// dead, has been misled by the interface.
    @ViewBuilder
    private var findingsCard: some View {
        if session.findings.count > 1 {
            Card(
                title: "Needs Attention",
                subtitle: "\(Formatting.count(session.findings.count)) things on this server are asking for a look.",
                systemImage: "exclamationmark.triangle"
            ) {
                VStack(spacing: 0) {
                    ForEach(Array(session.findings.enumerated()), id: \.offset) { index, finding in
                        if index > 0 {
                            Divider().overlay(Palette.divider)
                        }
                        findingRow(finding)
                    }
                }
            }
        }
    }

    private func findingRow(_ finding: HealthFinding) -> some View {
        HStack(alignment: .top, spacing: Spacing.group) {
            StatusDot(finding.state, size: 11)
                .padding(.top, 1)

            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(finding.summary)
                    .font(Typography.body.weight(.medium))
                    .foregroundStyle(Palette.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(finding.reason)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            Spacer(minLength: Spacing.element)

            if let title = finding.action.title {
                Button(title) { perform(finding.action) }
                    .buttonStyle(RowActionButtonStyle(tint: Palette.color(for: finding.state)))
            }
        }
        .padding(.vertical, Spacing.element)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(finding.state.accessibilityLabel). \(finding.summary) \(finding.reason)")
    }

    // MARK: - 3. Decision cards

    private var decisionCards: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader("Resources")

            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 280), spacing: Spacing.between, alignment: .top)],
                alignment: .leading,
                spacing: Spacing.between
            ) {
                storageCard
                if session.capabilities.docker { dockerCard }
                if session.capabilities.services { servicesCard }
                if session.capabilities.postgres { databasesCard }
                if session.capabilities.users { usersCard }
                networkCard
            }
        }
    }

    // --- Storage ------------------------------------------------------------

    private var storageCard: some View {
        Card(
            title: "Storage",
            subtitle: storageSubtitle,
            systemImage: "internaldrive",
            action: Card.CardAction(title: "Manage Storage") {
                navigation.currentFilePath = "/"
                navigation.select(section: .files)
            }
        ) {
            if let filesystems = session.metrics?.disk.filesystems, !filesystems.isEmpty {
                VStack(alignment: .leading, spacing: Spacing.group) {
                    ForEach(filesystems) { filesystem in
                        filesystemRow(filesystem)
                    }
                }
            } else if session.metrics == nil {
                SkeletonRow(showsLeading: false)
            } else {
                Text("This server didn't report any mounted filesystems.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
            }
        }
    }

    private var storageSubtitle: String? {
        guard let disk = session.metrics?.disk else { return nil }
        return Formatting.usage(used: disk.usedBytes, total: disk.totalBytes)
    }

    private func filesystemRow(_ filesystem: DiskMetrics.Filesystem) -> some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
                Text(filesystem.mountPoint)
                    .font(Typography.body)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                Spacer(minLength: Spacing.snug)
                Text(Formatting.percent(filesystem.usagePercent))
                    .font(Typography.metricSmall)
                    .foregroundStyle(Palette.textPrimary)
            }

            UsageBar(fraction: filesystem.usagePercent.map { $0 / 100 })

            Text(Formatting.usage(used: filesystem.usedBytes, total: filesystem.totalBytes))
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .lineLimit(1)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(filesystem.mountPoint), \(filesystem.fstype)")
        .accessibilityValue(
            "\(Formatting.percent(filesystem.usagePercent)) full, "
            + Formatting.usage(used: filesystem.usedBytes, total: filesystem.totalBytes)
        )
    }

    // --- Docker -------------------------------------------------------------

    private var dockerCard: some View {
        let containers = session.containers
        let running = containers.filter(\.isRunning).count
        let stopped = containers.filter(\.isStopped)
        let unhealthy = containers.filter(\.isUnhealthy)

        return Card(
            title: "Docker",
            subtitle: containers.isEmpty
                ? nil
                : "\(Formatting.count(containers.count)) container\(containers.count == 1 ? "" : "s") · \(running) running · \(stopped.count) stopped",
            systemImage: "shippingbox",
            action: Card.CardAction(title: "Open Docker") {
                navigation.selectedContainerID = nil
                navigation.select(section: .docker)
            }
        ) {
            if containers.isEmpty {
                Text("Docker is installed but nothing is running here yet.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(alignment: .leading, spacing: Spacing.element) {
                    if !unhealthy.isEmpty {
                        namedList(
                            label: "Failing their health check",
                            names: unhealthy.map(\.displayName),
                            tint: Palette.critical
                        )
                    }
                    if !stopped.isEmpty {
                        namedList(
                            label: "Stopped",
                            names: stopped.map(\.displayName),
                            tint: Palette.warning
                        )
                    }
                    if unhealthy.isEmpty && stopped.isEmpty {
                        HStack(spacing: Spacing.snug) {
                            RunPill(.running)
                            Text("Every container is up.")
                                .font(Typography.secondary)
                                .foregroundStyle(Palette.textSecondary)
                        }
                    }
                }
            }
        }
    }

    // --- Services -----------------------------------------------------------

    private var servicesCard: some View {
        let services = session.services
        let running = services.filter(\.isRunning).count
        let failed = services.filter(\.hasFailed)

        return Card(
            title: "Services",
            subtitle: services.isEmpty
                ? nil
                : "\(Formatting.count(services.count)) unit\(services.count == 1 ? "" : "s") · \(running) running · \(failed.count) failed",
            systemImage: "gearshape.2",
            action: Card.CardAction(title: "Open Services") {
                navigation.selectedServiceUnit = nil
                navigation.select(section: .services)
            }
        ) {
            if services.isEmpty {
                Text("ServerOS hasn't read this server's services yet.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
            } else if failed.isEmpty {
                HStack(spacing: Spacing.snug) {
                    RunPill(.running)
                    Text("Nothing has failed.")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                }
            } else {
                namedList(
                    label: failed.count == 1 ? "Failed" : "Failed units",
                    names: failed.map(\.displayName),
                    tint: Palette.critical
                )
            }
        }
    }

    // --- Databases ----------------------------------------------------------

    private var databasesCard: some View {
        Card(
            title: "Databases",
            subtitle: databasesSubtitle,
            systemImage: "cylinder.split.1x2",
            action: Card.CardAction(title: "Open Databases") {
                navigation.select(section: .databases)
            }
        ) {
            // A card is too small a space for the full-screen unavailable and
            // error treatments, so a degraded card explains itself inline and
            // leaves the rest of the Overview alone.
            switch postgres {
            case .loading:
                SkeletonRow(showsLeading: false)

            case .loaded(let overview):
                postgresBody(overview)

            case .empty:
                Text("PostgreSQL is installed but reported nothing about itself.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

            case .failed(let error):
                InlineBanner(.warning, error.headline, actionTitle: "Try Again") {
                    Task { await loadPostgres(force: true) }
                }

            case .unavailable(_, let reason):
                InlineBanner(.info, reason)
            }
        }
    }

    private var databasesSubtitle: String? {
        guard let version = postgres.value?.version else { return nil }
        return "PostgreSQL \(version)"
    }

    @ViewBuilder
    private func postgresBody(_ overview: PostgresOverview) -> some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            HStack(spacing: Spacing.element) {
                HealthBadge(ServerOverviewSection.postgresState(overview.health), compact: true)
                if let reason = overview.healthReason {
                    Text(reason)
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textSecondary)
                        .lineLimit(1)
                }
            }

            VStack(alignment: .leading, spacing: Spacing.tight) {
                HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
                    Text("Connections")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                    Spacer(minLength: Spacing.snug)
                    Text(connectionsLabel(overview))
                        .font(Typography.metricSmall)
                        .foregroundStyle(Palette.textPrimary)
                }
                UsageBar(fraction: overview.connectionUsagePercent.map { $0 / 100 })
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("PostgreSQL connections")
            .accessibilityValue(connectionsLabel(overview))

            if let count = overview.databaseCount {
                Text("\(Formatting.count(count)) database\(count == 1 ? "" : "s") · \(Formatting.bytes(overview.totalSizeBytes))")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
            }
        }
    }

    private func connectionsLabel(_ overview: PostgresOverview) -> String {
        switch (overview.currentConnections, overview.maxConnections) {
        case let (.some(current), .some(maximum)):
            return "\(Formatting.count(current)) of \(Formatting.count(maximum))"
        case let (.some(current), .none):
            return Formatting.count(current)
        default:
            return "Unknown"
        }
    }

    /// The agent's word for PostgreSQL's condition, in the app's vocabulary.
    private static func postgresState(_ health: String) -> HealthState {
        switch health {
        case "healthy": return .healthy
        case "warning": return .warning
        case "critical": return .critical
        case "unreachable", "offline": return .offline
        default: return .unknown
        }
    }

    // --- Users --------------------------------------------------------------

    private var usersCard: some View {
        Card(
            title: "Users",
            subtitle: usersSubtitle,
            systemImage: "person.2",
            action: Card.CardAction(title: "Open Users") {
                navigation.selectedUserName = nil
                navigation.select(section: .users)
            }
        ) {
            switch users {
            case .loading:
                SkeletonRow(showsLeading: false)

            case .loaded(let list):
                let sudoers = list.items.filter(\.canSudo).map(\.username)
                if sudoers.isEmpty {
                    Text("No account on this server can use sudo.")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    namedList(label: "Can use sudo", names: sudoers, tint: Palette.informational)
                }

            case .empty:
                Text("This server reported no accounts, which is unusual.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

            case .failed(let error):
                InlineBanner(.warning, error.headline, actionTitle: "Try Again") {
                    Task { await loadUsers(force: true) }
                }

            case .unavailable(_, let reason):
                InlineBanner(.info, reason)
            }
        }
    }

    private var usersSubtitle: String? {
        guard let list = users.value else { return nil }
        let people = list.people ?? list.items.filter { !$0.isSystem }.count
        let system = list.system ?? list.items.filter(\.isSystem).count
        return "\(Formatting.count(people)) \(people == 1 ? "person" : "people") · \(Formatting.count(system)) system account\(system == 1 ? "" : "s")"
    }

    // --- Network ------------------------------------------------------------

    private var networkCard: some View {
        Card(
            title: "Network",
            subtitle: networkSubtitle,
            systemImage: "network"
        ) {
            if let network = session.metrics?.network {
                VStack(alignment: .leading, spacing: Spacing.group) {
                    HStack(alignment: .top, spacing: Spacing.section) {
                        throughput(label: "In", symbol: "arrow.down", rate: network.rxBytesPerSec, total: network.rxBytesTotal)
                        throughput(label: "Out", symbol: "arrow.up", rate: network.txBytesPerSec, total: network.txBytesTotal)
                        Spacer(minLength: 0)
                    }
                }
            } else {
                SkeletonRow(showsLeading: false)
            }
        }
    }

    private var networkSubtitle: String? {
        guard let interfaces = session.metrics?.network.interfaces else { return nil }
        let up = interfaces.filter(\.up).count
        return "\(Formatting.count(up)) of \(Formatting.count(interfaces.count)) interface\(interfaces.count == 1 ? "" : "s") up"
    }

    private func throughput(label: String, symbol: String, rate: Double, total: Int64) -> some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            HStack(spacing: Spacing.tight) {
                Image(systemName: symbol)
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundStyle(Palette.textSecondary)
                    .accessibilityHidden(true)
                Text(label)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .textCase(.uppercase)
                    .tracking(0.4)
            }
            Text(Formatting.rate(rate))
                .font(Typography.metricSmall)
                .foregroundStyle(Palette.textPrimary)
                .contentTransition(.numericText())
            Text("\(Formatting.bytes(total)) total")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label == "In" ? "Network received" : "Network sent")
        .accessibilityValue("\(Formatting.rate(rate)), \(Formatting.bytes(total)) in total")
    }

    // --- A short list of names, used by several cards -----------------------

    private func namedList(label: String, names: [String], tint: Color) -> some View {
        VStack(alignment: .leading, spacing: Spacing.snug) {
            Text(label)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
            // A wrapping row of chips rather than a truncated sentence: with
            // twelve stopped containers the sentence becomes useless and the
            // chips stay readable.
            ChipFlowLayout(spacing: Spacing.tight) {
                ForEach(names.prefix(6), id: \.self) { name in
                    Chip(name, tint: tint)
                }
                if names.count > 6 {
                    Chip("+\(names.count - 6) more", tint: Palette.inactive)
                }
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(label): \(Formatting.list(names, limit: 4))")
    }

    // MARK: - 4. Trends

    private var trends: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader("CPU & Memory Over Time")

            HStack(alignment: .top, spacing: Spacing.between) {
                trendCard(
                    title: "CPU",
                    value: currentCPUPercent,
                    history: session.cpuHistory,
                    tint: Palette.accent,
                    caption: loadCaption
                )
                trendCard(
                    title: "Memory",
                    value: session.metrics?.memory.usagePercent,
                    history: session.memoryHistory,
                    tint: Palette.informational,
                    caption: memoryCaption
                )
            }

            if let perCore = session.metrics?.cpu.perCore, perCore.count > 1 {
                perCoreCard(perCore)
            }
        }
    }

    /// Nil while the sampler is warming up: the first CPU sample after
    /// connecting is always zero, and a confident "0%" is a lie.
    private var currentCPUPercent: Double? {
        guard let metrics = session.metrics, !metrics.isWarmingUp else { return nil }
        return metrics.cpu.usagePercent
    }

    private func trendCard(
        title: String,
        value: Double?,
        history: [Double],
        tint: Color,
        caption: String?
    ) -> some View {
        Card(title: title) {
            VStack(alignment: .leading, spacing: Spacing.element) {
                Text(value.map { Formatting.percent($0) } ?? "—")
                    .font(Typography.metric)
                    .foregroundStyle(value == nil ? Palette.textMuted : Palette.textPrimary)
                    .contentTransition(.numericText())
                    .accessibilityLabel(title)
                    .accessibilityValue(value.map { "\(Int($0.rounded())) percent" } ?? "Not available yet")

                if history.count >= 2 {
                    Sparkline(values: history, tint: tint)
                        .frame(height: 42)
                } else {
                    // A one-point "trend" is a dot pretending to be information.
                    Text("Collecting samples…")
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                        .frame(height: 42, alignment: .center)
                }

                if let caption {
                    Text(caption)
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(2)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private var loadCaption: String? {
        guard let cpu = session.metrics?.cpu else { return nil }
        let load = cpu.loadAverage
        return "Load \(Formatting.decimal(load.one, places: 2)) · \(Formatting.decimal(load.five, places: 2)) · \(Formatting.decimal(load.fifteen, places: 2)) across \(cpu.coreCount) core\(cpu.coreCount == 1 ? "" : "s")"
    }

    private var memoryCaption: String? {
        guard let memory = session.metrics?.memory else { return nil }
        var caption = Formatting.usage(used: memory.usedBytes, total: memory.totalBytes)
        if memory.hasSwap {
            caption += " · Swap \(Formatting.percent(memory.swapUsagePercent))"
        }
        return caption
    }

    private func perCoreCard(_ perCore: [Double]) -> some View {
        Card(title: "Per Core", subtitle: "\(Formatting.count(perCore.count)) logical processors") {
            LazyVGrid(
                columns: Array(
                    repeating: GridItem(.flexible(), spacing: Spacing.group, alignment: .leading),
                    count: min(8, max(1, perCore.count))
                ),
                alignment: .leading,
                spacing: Spacing.element
            ) {
                ForEach(Array(perCore.enumerated()), id: \.offset) { index, usage in
                    VStack(alignment: .leading, spacing: Spacing.hairline) {
                        Text("\(index)")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                            .monospacedDigit()
                        UsageBar(fraction: usage / 100)
                        Text(Formatting.percent(usage))
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textSecondary)
                            .monospacedDigit()
                    }
                    .accessibilityElement(children: .ignore)
                    .accessibilityLabel("Core \(index)")
                    .accessibilityValue("\(Int(usage.rounded())) percent")
                }
            }
        }
    }

    // MARK: - 5. Recent activity

    private var recentActivity: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader("Recent Activity", count: session.activity.isEmpty ? nil : session.activity.count) {
                Button("View All") { navigation.go(to: .activity) }
                    .buttonStyle(.rowAction)
            }

            if session.activity.isEmpty {
                EmptyState(
                    systemImage: "clock.arrow.circlepath",
                    title: "Nothing has happened here yet",
                    message: "Every change ServerOS makes on \(session.name) — a restarted container, a new user, an edited file — is recorded here so you can see who did what.",
                    actionTitle: nil,
                    action: nil
                )
                .frame(minHeight: 200)
                .cardSurface(scheme: scheme)
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(session.activity.prefix(8).enumerated()), id: \.element.id) { index, event in
                        if index > 0 {
                            Divider().overlay(Palette.divider)
                        }
                        activityRow(event)
                    }
                }
                .padding(.horizontal, Spacing.card)
                .padding(.vertical, Spacing.tight)
                .cardSurface(scheme: scheme)
            }
        }
    }

    private func activityRow(_ event: ActivityEvent) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            Image(systemName: event.succeeded ? "checkmark.circle" : "xmark.circle")
                .font(.system(size: 11))
                .foregroundStyle(event.succeeded ? Palette.healthy : Palette.critical)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(event.summary)
                    .font(Typography.body)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                Text("\(event.actor) · \(Formatting.relative(event.date))")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
            }

            Spacer(minLength: 0)
        }
        .padding(.vertical, Spacing.element)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(event.summary), by \(event.actor), \(Formatting.relative(event.date)), \(event.succeeded ? "succeeded" : "failed")")
    }

    // MARK: - Loading

    private func loadPostgres(force: Bool = false) async {
        guard let api = session.api else {
            if force { postgres = .loading }
            return
        }
        guard session.capabilities.postgres else {
            postgres = .unavailable(
                subsystem: "PostgreSQL",
                reason: "ServerOS didn't find a PostgreSQL server on \(session.name)."
            )
            return
        }
        if force { postgres = .loading }

        do {
            let overview = try await api.postgresOverview()
            postgres = .loaded(overview)
        } catch let error as ServerOSError {
            postgres = error.code == "subsystem_unavailable"
                ? .unavailable(subsystem: "PostgreSQL", reason: error.headline)
                : .failed(error)
        } catch {
            postgres = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }

    private func loadUsers(force: Bool = false) async {
        guard let api = session.api else {
            if force { users = .loading }
            return
        }
        guard session.capabilities.users else {
            users = .unavailable(
                subsystem: "Users",
                reason: "This server's agent can't read its account list."
            )
            return
        }
        if force { users = .loading }

        do {
            let list = try await api.users(includeSystem: true)
            users = list.items.isEmpty ? .empty : .loaded(list)
        } catch let error as ServerOSError {
            users = .failed(error)
        } catch {
            users = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }
}

// MARK: - Load trigger

/// What makes the Overview's request-backed cards ask again: the connection
/// becoming usable, and the agent telling us what it can do.
private struct OverviewLoadTrigger: Equatable {
    let isReady: Bool
    let capabilities: AgentCapabilities
}

// MARK: - Flow row

/// A row of chips that wraps.
///
/// `Layout` rather than a `LazyVGrid`: the chips are different widths and should
/// sit next to each other, not in columns, and a grid of one-word cells looks
/// like a table of nothing. File-scoped on purpose — sibling screens have their
/// own layouts and this one carries no decisions worth sharing.
/// `SwiftUI.Layout` in full: the design system has its own `Layout` enum for
/// window metrics, and an unqualified `Layout` here resolves to that one. Same
/// reason `LayoutSubviews` is spelled out rather than the protocol's nested
/// `Subviews` alias.
private struct ChipFlowLayout: SwiftUI.Layout {
    var spacing: CGFloat = Spacing.tight

    func sizeThatFits(proposal: ProposedViewSize, subviews: LayoutSubviews, cache: inout ()) -> CGSize {
        let maxWidth = proposal.width ?? .infinity
        var x: CGFloat = 0
        var y: CGFloat = 0
        var rowHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > 0 && x + size.width > maxWidth {
                x = 0
                y += rowHeight + spacing
                rowHeight = 0
            }
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }

        return CGSize(width: proposal.width ?? x, height: y + rowHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: LayoutSubviews, cache: inout ()) {
        var x = bounds.minX
        var y = bounds.minY
        var rowHeight: CGFloat = 0

        for subview in subviews {
            let size = subview.sizeThatFits(.unspecified)
            if x > bounds.minX && x + size.width > bounds.maxX {
                x = bounds.minX
                y += rowHeight + spacing
                rowHeight = 0
            }
            subview.place(at: CGPoint(x: x, y: y), anchor: .topLeading, proposal: ProposedViewSize(size))
            x += size.width + spacing
            rowHeight = max(rowHeight, size.height)
        }
    }
}

// MARK: - Preview

private struct ServerOverviewPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        ServerOverviewSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 980, height: 760)
            .onAppear {
                navigation.enter(serverID: session.id)
                session.connect()
            }
    }
}

#Preview("Server overview") {
    ServerOverviewPreviewHost()
}
