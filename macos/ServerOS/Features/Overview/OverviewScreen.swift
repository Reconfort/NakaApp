//  OverviewScreen.swift
//  ServerOS
//
//  WHY THIS SCREEN EXISTS
//
//  It answers one question, in under two seconds, before the user has clicked
//  anything: **is anything wrong, and where?**
//
//  That is the whole brief for this screen, and it is why it is not a wall of
//  charts. A dashboard that shows CPU, memory, disk, network and container
//  counts for every server at once is technically complete and practically
//  useless — the reader has to do the triage themselves, every morning, with
//  their eyes. So the hierarchy here is deliberately:
//
//      verdict  →  what needs attention  →  everything else  →  what changed
//
//  The headline is a sentence, not a number. Servers that need attention come
//  first and are given the full-width `HealthCard` treatment, because the point
//  of the screen is that the bad one finds *you*. Healthy servers are compact,
//  below, in a grid — present, reassuring, not competing for attention.
//
//  Recent Activity closes the screen because "what changed" is the second
//  question anybody asks after "is it healthy", and because an audit feed on the
//  front page is what makes a shared server feel accountable rather than spooky.

import Combine
import SwiftData
import SwiftUI

/// The fleet dashboard: an executive snapshot of every server ServerOS manages.
public struct OverviewScreen: View {

    @Environment(AppModel.self) private var model

    private let navigation: NavigationModel
    private let onAddServer: () -> Void

    /// Written here and read by ``ServersScreen`` so a tally tile can open the
    /// server list already narrowed to what the user clicked. Navigation itself
    /// carries no payload, and a notification would arrive before the Servers
    /// screen had mounted.
    @AppStorage(ServerListFilter.requestKey) private var requestedServerFilter: String = ""

    @State private var isDemoNoticeDismissed = false
    @State private var demoFailure: ServerOSError?

    public init(navigation: NavigationModel, onAddServer: @escaping () -> Void) {
        self.navigation = navigation
        self.onAddServer = onAddServer
    }

    public var body: some View {
        ScrollView {
            StatefulContent(state, retry: { reloadServers() }) { servers in
                loaded(servers)
            } empty: {
                noServersYet
            }
        }
        .background(Palette.background)
        .sheet(item: $demoFailure) { failure in
            VStack(spacing: Spacing.section) {
                ErrorState(error: failure)
                Button("Close") { demoFailure = nil }
                    .buttonStyle(.primary)
            }
            .padding(Spacing.section)
            .frame(width: 460)
        }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            refreshEverything()
        }
    }

    // MARK: - State

    /// The Overview is backed by the local server list rather than by one
    /// server, so "unavailable" cannot happen here — a capability belongs to a
    /// server, and this screen is about all of them. Every other state is real.
    private var state: ScreenState<[ServerSummary]> {
        if let error = model.loadError { return .failed(error) }
        if model.isLoading && model.servers.isEmpty { return .loading }
        if model.servers.isEmpty { return .empty }
        return .loaded(model.servers)
    }

    // MARK: - Loaded

    @ViewBuilder
    private func loaded(_ servers: [ServerSummary]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.section) {
            if model.isShowingDemo && !model.hasRealServers && !isDemoNoticeDismissed {
                demoNotice
            }

            headline

            tallyRow

            let needingAttention = attentionServers
            if !needingAttention.isEmpty {
                attentionSection(needingAttention)
            }

            let settled = calmServers
            if !settled.isEmpty {
                calmSection(settled)
            }

            activitySection
        }
        .readableWidth()
        .screenPadding()
        .frame(maxWidth: .infinity, alignment: .topLeading)
    }

    // MARK: - Headline

    /// Greeting, then the verdict. The verdict is the largest text on screen
    /// whether it is good news or bad — a dashboard that only shouts when
    /// something breaks trains people to ignore it the rest of the time.
    private var headline: some View {
        VStack(alignment: .leading, spacing: Spacing.snug) {
            Text(greeting)
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)

            Text(model.fleetSummaryLine)
                .font(Typography.pageTitle)
                .foregroundStyle(needsAttentionOverall ? Palette.color(for: worstState) : Palette.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
        }
    }

    private var greeting: String {
        switch Calendar.current.component(.hour, from: Date()) {
        case 0..<12: return "Good morning."
        case 12..<18: return "Good afternoon."
        default: return "Good evening."
        }
    }

    private var worstState: HealthState {
        // Not `map(\.health.state)`: Swift has no key paths into tuple members,
        // and `fleetHealth` is a tuple list.
        model.fleetHealth.map { $0.health.state }.max() ?? .unknown
    }

    private var needsAttentionOverall: Bool {
        worstState >= .warning
    }

    // MARK: - Tally

    private var tallyRow: some View {
        HStack(spacing: Spacing.between) {
            FleetTallyTile(
                label: "Servers",
                count: model.servers.count,
                state: nil,
                action: { open(filter: .all) }
            )
            FleetTallyTile(
                label: "Healthy",
                count: count(of: .healthy),
                state: .healthy,
                action: { open(filter: .all) }
            )
            FleetTallyTile(
                label: "Needs Attention",
                count: attentionServers.count,
                state: .warning,
                action: { open(filter: .needsAttention) }
            )
            FleetTallyTile(
                label: "Offline",
                count: count(of: .offline),
                state: .offline,
                action: { open(filter: .offline) }
            )
            Spacer(minLength: 0)
        }
    }

    private func count(of state: HealthState) -> Int {
        model.fleetHealth.filter { $0.health.state == state }.count
    }

    private func open(filter: ServerListFilter) {
        requestedServerFilter = filter.rawValue
        navigation.go(to: .servers)
    }

    // MARK: - Attention first

    /// Warning, critical and offline, worst first. This is the part of the
    /// screen that exists to be noticed.
    private var attentionServers: [FleetServerEntry] {
        fleet
            .filter { $0.health.state >= .warning }
            .sorted { $0.health.state > $1.health.state }
    }

    private var calmServers: [FleetServerEntry] {
        fleet.filter { $0.health.state < .warning }
    }

    /// `AppModel.fleetHealth` is a list of tuples, and SwiftUI's `ForEach` needs
    /// an `Identifiable` element — Swift has no key paths into tuple members.
    private var fleet: [FleetServerEntry] {
        model.fleetHealth.map { FleetServerEntry(summary: $0.summary, health: $0.health) }
    }

    private func attentionSection(_ entries: [FleetServerEntry]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader("Needs Attention", count: entries.count)

            ForEach(entries) { entry in
                VStack(alignment: .leading, spacing: Spacing.element) {
                    HealthCard(
                        title: entry.summary.name,
                        health: entry.health,
                        metrics: model.sessions[entry.summary.id]?.metrics
                    ) { action in
                        perform(action, on: entry.summary.id)
                    }

                    // The health action is the *recommended* next step; opening
                    // the server is always available beside it, never instead
                    // of it.
                    HStack(spacing: Spacing.element) {
                        Spacer(minLength: 0)
                        Button("Open Server") {
                            navigation.enter(serverID: entry.summary.id)
                        }
                        .buttonStyle(.rowAction)
                        .accessibilityLabel("Open \(entry.summary.name)")
                    }
                }
                .accessibilityElement(children: .contain)
                .accessibilityLabel("\(entry.summary.name), \(entry.health.state.accessibilityLabel)")
            }
        }
    }

    // MARK: - Everything else

    private func calmSection(_ entries: [FleetServerEntry]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader(
                attentionServers.isEmpty ? "Your Servers" : "Everything Else",
                count: entries.count
            )

            LazyVGrid(
                columns: [GridItem(.adaptive(minimum: 300), spacing: Spacing.between)],
                alignment: .leading,
                spacing: Spacing.between
            ) {
                ForEach(entries) { entry in
                    CompactServerCard(
                        summary: entry.summary,
                        session: model.sessions[entry.summary.id],
                        health: entry.health,
                        onOpen: { navigation.enter(serverID: entry.summary.id) },
                        onReconnect: { model.session(for: entry.summary.id)?.reconnect() }
                    )
                }
            }
        }
    }

    // MARK: - Activity

    private var recentActivity: [OverviewActivityEntry] {
        model.recentActivity(limit: 12).map {
            // Event ids are minted per agent, so two servers can hand back the
            // same id. Namespacing by server is what keeps SwiftUI's diffing
            // from confusing one machine's restart with another's.
            OverviewActivityEntry(
                id: "\($0.server.id):\($0.event.id)",
                server: $0.server,
                event: $0.event
            )
        }
    }

    @ViewBuilder
    private var activitySection: some View {
        let entries = recentActivity

        VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader("Recent Activity") {
                Button("See All") { navigation.go(to: .activity) }
                    .buttonStyle(.rowAction)
            }

            if entries.isEmpty {
                Card {
                    Text("Nothing has happened yet. Actions you take in ServerOS — restarting a container, editing a file, adding a user — appear here with the server they happened on.")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                VStack(spacing: 0) {
                    ForEach(entries) { entry in
                        Button {
                            navigation.enter(serverID: entry.server.id)
                        } label: {
                            OverviewActivityRow(entry: entry)
                        }
                        .buttonStyle(.plain)
                        .hoverHighlight()

                        if entry.id != entries.last?.id {
                            Divider().overlay(Palette.divider)
                        }
                    }
                }
                .padding(.vertical, Spacing.tight)
                .cardSurface()
            }
        }
    }

    // MARK: - Empty & demo

    private var noServersYet: some View {
        EmptyState(
            systemImage: "server.rack",
            title: "No servers yet",
            message: "Connect your first Linux server to start managing your infrastructure from your Mac.",
            actionTitle: "Add Server",
            action: onAddServer,
            secondaryActionTitle: "Explore with Demo Data",
            secondaryAction: { startDemo() }
        )
        .frame(minHeight: 420)
    }

    private var demoNotice: some View {
        HStack(spacing: Spacing.element) {
            InlineBanner(
                .info,
                "These are demo servers. They don't exist, nothing here touches a real machine, and no action you take leaves your Mac.",
                actionTitle: "Add a Real Server",
                action: onAddServer
            )

            Button {
                withAnimation(Motion.appear) { isDemoNoticeDismissed = true }
            } label: {
                Image(systemName: "xmark")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundStyle(Palette.textMuted)
                    .padding(Spacing.snug)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Dismiss the demo notice")
        }
    }

    // MARK: - Actions

    private func perform(_ action: HealthAction, on serverID: String) {
        switch action {
        case .none, .openStorage:
            // Storage lives on the server's own Overview; there is no separate
            // storage section to send someone to.
            navigation.enter(serverID: serverID, section: .overview)
        case .openDocker(let containerID):
            navigation.selectedContainerID = containerID
            navigation.enter(serverID: serverID, section: .docker)
        case .openServices(let unit):
            navigation.selectedServiceUnit = unit
            navigation.enter(serverID: serverID, section: .services)
        case .openProcesses:
            navigation.enter(serverID: serverID, section: .processes)
        case .openDatabases:
            navigation.enter(serverID: serverID, section: .databases)
        case .openLogs:
            navigation.enter(serverID: serverID, section: .logs)
        case .reconnect:
            model.session(for: serverID)?.reconnect()
        }
    }

    private func startDemo() {
        Task {
            do { try await model.enableDemoMode() }
            catch { demoFailure = .listChangeFailed(what: "start demo mode", underlying: error) }
        }
    }

    private func reloadServers() {
        Task { await model.load() }
    }

    private func refreshEverything() {
        let sessions = Array(model.sessions.values)
        Task {
            await model.load()
            for session in sessions {
                await session.refreshAll()
            }
        }
    }
}

// MARK: - Fleet entry

/// One server plus its verdict, as an `Identifiable` value.
private struct FleetServerEntry: Identifiable {
    let summary: ServerSummary
    let health: ServerHealth
    var id: String { summary.id }
}

// MARK: - Tally tile

/// One number in the fleet tally, and a way into the list it counts.
///
/// Colour alone would be meaningless here, so every tile that stands for a
/// health state pairs it with a `StatusDot` (whose *shape* differs per state)
/// and a word.
private struct FleetTallyTile: View {
    let label: String
    let count: Int
    let state: HealthState?
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: Spacing.tight) {
                HStack(spacing: Spacing.tight) {
                    if let state {
                        StatusDot(state, size: 9)
                    }
                    Text(label)
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textSecondary)
                        .lineLimit(1)
                }
                Text(Formatting.count(count))
                    .font(Typography.metric)
                    .foregroundStyle(tint)
                    .contentTransition(.numericText())
            }
            .padding(.horizontal, Spacing.group)
            .padding(.vertical, Spacing.group)
            .frame(minWidth: 132, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .cardSurface()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue("\(count)")
        .accessibilityAddTraits(.isButton)
    }

    private var tint: Color {
        guard let state, count > 0, state >= .warning else { return Palette.textPrimary }
        return Palette.color(for: state)
    }
}

// MARK: - Compact server card

/// A healthy server, in the grid below the fold.
///
/// Name, verdict, the three numbers that matter and a CPU sparkline — enough to
/// notice a machine that is climbing, not so much that four of them turn into a
/// spreadsheet.
private struct CompactServerCard: View {
    let summary: ServerSummary
    let session: ServerSession?
    let health: ServerHealth
    let onOpen: () -> Void
    let onReconnect: () -> Void

    var body: some View {
        // The card's own `action:` slot takes a `Card<Content>.CardAction`,
        // whose type depends on the content being inferred in the same
        // expression. The button is built into the content instead — same
        // result, no inference knot.
        Card(title: summary.name, subtitle: subtitle, interactive: true) {
            VStack(alignment: .leading, spacing: Spacing.group) {
                HStack(spacing: Spacing.element) {
                    HealthBadge(health.state, compact: true)
                    if summary.isDemo {
                        Chip("Demo", tint: Palette.informational, systemImage: "wand.and.stars")
                    }
                    Spacer(minLength: 0)
                }

                if isStale {
                    StaleDataBanner(lastUpdated: session?.lastContact, onReconnect: onReconnect)
                }

                if let metrics = session?.metrics {
                    MetricStrip(metrics: metrics)
                } else {
                    Text(session?.phase.describedStep ?? "Not connected")
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                }

                if let history = session?.cpuHistory, history.count >= 2 {
                    VStack(alignment: .leading, spacing: Spacing.hairline) {
                        Text("CPU, last few minutes")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                        Sparkline(values: history)
                            .frame(height: 28)
                    }
                }

                Divider().overlay(Palette.divider)

                Button("Open Server", action: onOpen)
                    .buttonStyle(.secondary)
                    .accessibilityLabel("Open \(summary.name)")
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(summary.name), \(health.state.accessibilityLabel)")
    }

    /// Reachable servers show where they are; unreachable ones show why the
    /// numbers underneath may be out of date.
    private var subtitle: String {
        guard let session else { return summary.describedEndpoint }
        return session.phase.isReady ? summary.describedEndpoint : session.phase.describedStep
    }

    private var isStale: Bool {
        guard let session else { return false }
        return !session.phase.isReady && session.lastContact != nil
    }
}

// MARK: - Activity

/// One line of the fleet audit feed, namespaced so ids stay unique across
/// servers.
private struct OverviewActivityEntry: Identifiable {
    let id: String
    let server: ServerSummary
    let event: ActivityEvent
}

private struct OverviewActivityRow: View {
    let entry: OverviewActivityEntry

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            Image(systemName: entry.event.succeeded ? symbol : "exclamationmark.triangle.fill")
                .font(.system(size: 11))
                .foregroundStyle(entry.event.succeeded ? Palette.textSecondary : Palette.critical)
                .frame(width: 16)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(entry.event.summary)
                    .font(Typography.body)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                    .truncationMode(.middle)

                HStack(spacing: Spacing.snug) {
                    Text(entry.server.name)
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textSecondary)
                    Text("·")
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                    Text(Formatting.relative(entry.event.date))
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                }
            }

            Spacer(minLength: Spacing.element)

            if !entry.event.succeeded {
                Chip("Failed", tint: Palette.critical, systemImage: "xmark")
            }
        }
        .padding(.horizontal, Spacing.card)
        .padding(.vertical, Spacing.element)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(
            "\(entry.event.summary), \(entry.server.name), \(Formatting.relative(entry.event.date))"
                + (entry.event.succeeded ? "" : ", failed")
        )
    }

    private var symbol: String {
        ActivitySymbol.name(for: entry.event.resourceType)
    }
}

// MARK: - Previews

@MainActor
private func previewOverviewModel() -> AppModel {
    let container = try? ServerStore.makeContainer(inMemory: true)
    return AppModel(store: ServerStore(container: container ?? ServerStore.emptyContainer()))
}

#Preview("Overview — demo fleet") {
    let model = previewOverviewModel()
    OverviewScreen(navigation: NavigationModel(), onAddServer: {})
        .environment(model)
        .task { try? await model.enableDemoMode() }
        .frame(width: 980, height: 760)
}

#Preview("Overview — no servers") {
    OverviewScreen(navigation: NavigationModel(), onAddServer: {})
        .environment(previewOverviewModel())
        .frame(width: 980, height: 620)
}
