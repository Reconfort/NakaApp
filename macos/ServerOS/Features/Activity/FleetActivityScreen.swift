//  FleetActivityScreen.swift
//  ServerOS
//
//  WHY THIS SCREEN EXISTS
//
//  Every action ServerOS performs on a server is recorded by the agent, with who
//  asked for it and whether it worked. This screen is where that record is read.
//
//  The question it answers is **"what happened, and did it work?"** — most often
//  asked in one of two moments:
//
//    * something broke and the first suspicion is "did somebody change it?"
//    * somebody is handing a server over and wants to see what they did.
//
//  Two consequences for the design. First, the feed is grouped by day with real
//  headings rather than being an undifferentiated stream: "was that today or
//  last week?" is half the question. Second, failures are given a treatment of
//  their own rather than a slightly different shade of grey — a restart that
//  *didn't* happen is the single most useful row on the screen, and it must not
//  be possible to skim past it.
//
//  The inspector is where the exact facts live: the actor, the peer address, the
//  full resource identifier and the absolute timestamp. Those belong one click
//  away rather than in the row, because putting an IP address on every line
//  makes forty rows unreadable to find the one that matters.

import Combine
import SwiftData
import SwiftUI

// MARK: - Shared iconography

/// The glyph for one kind of audited resource.
///
/// Shared with the Overview's activity list so a container restart looks the
/// same wherever it is shown — one icon language, per the design system.
public enum ActivitySymbol {
    public static func name(for resourceType: String) -> String {
        switch resourceType {
        case "container", "image", "volume", "network": return "shippingbox"
        case "service": return "gearshape.2"
        case "user", "group": return "person"
        case "file": return "doc"
        case "directory": return "folder"
        case "process": return "list.bullet.rectangle"
        case "database", "postgres": return "cylinder.split.1x2"
        case "project": return "square.stack.3d.up"
        case "server", "agent": return "server.rack"
        default: return "bolt"
        }
    }
}

// MARK: - Filter

private enum ActivityOutcomeFilter: String, CaseIterable, Hashable {
    case all
    case succeeded
    case failed

    var title: String {
        switch self {
        case .all: return "All"
        case .succeeded: return "Succeeded"
        case .failed: return "Failed"
        }
    }

    func includes(_ event: ActivityEvent) -> Bool {
        switch self {
        case .all: return true
        case .succeeded: return event.succeeded
        case .failed: return !event.succeeded
        }
    }
}

// MARK: - Screen

/// The audit feed for every connected server, newest first.
public struct FleetActivityScreen: View {

    @Environment(AppModel.self) private var model

    private let navigation: NavigationModel

    @State private var query = ""
    @State private var outcome: ActivityOutcomeFilter = .all
    @State private var selectedEntryID: String?

    public init(navigation: NavigationModel) {
        self.navigation = navigation
    }

    public var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                controls
                Divider().overlay(Palette.divider)

                StatefulContent(state, retry: { reloadServers() }) { days in
                    feed(days)
                } empty: {
                    emptyState
                }
            }
            .frame(maxWidth: .infinity)

            if let entry = selectedEntry {
                Divider().overlay(Palette.divider)
                ActivityInspector(
                    entry: entry,
                    onOpenServer: { navigation.enter(serverID: entry.server.id) },
                    onClose: { selectedEntryID = nil }
                )
                .frame(width: 320)
                .transition(.move(edge: .trailing).combined(with: .opacity))
            }
        }
        .background(Palette.background)
        .animation(Motion.panel, value: selectedEntryID)
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            refreshEverything()
        }
    }

    // MARK: - Controls

    private var controls: some View {
        HStack(spacing: Spacing.group) {
            SearchField(text: $query, prompt: "Search activity")

            Picker("Outcome", selection: $outcome) {
                ForEach(ActivityOutcomeFilter.allCases, id: \.self) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 280)
            .accessibilityLabel("Filter by outcome")

            Spacer(minLength: 0)

            if failureCount > 0 {
                Chip(
                    "\(Formatting.count(failureCount)) failed",
                    tint: Palette.critical,
                    systemImage: "exclamationmark.triangle.fill"
                )
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.element)
    }

    // MARK: - State

    /// The feed is assembled from sessions that are already streaming, so there
    /// is no separate fetch to fail and no capability to be missing — but a
    /// failure to open the local server list is still possible, and is still the
    /// reason this screen would be blank.
    private var state: ScreenState<[ActivityDay]> {
        if let error = model.loadError { return .failed(error) }
        if model.isLoading && model.servers.isEmpty { return .loading }
        if model.servers.isEmpty { return .empty }
        let days = groupedDays
        if days.isEmpty { return .empty }
        return .loaded(days)
    }

    private var allEntries: [FleetActivityEntry] {
        model.recentActivity(limit: 200).map {
            // Event ids are per-agent; two servers routinely hand back the same
            // number. Namespacing by server keeps SwiftUI's diffing — and this
            // screen's selection — pointing at the right row.
            FleetActivityEntry(
                id: "\($0.server.id):\($0.event.id)",
                server: $0.server,
                event: $0.event
            )
        }
    }

    private var filteredEntries: [FleetActivityEntry] {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        return allEntries.filter { entry in
            guard outcome.includes(entry.event) else { return false }
            guard !needle.isEmpty else { return true }
            if entry.event.summary.lowercased().contains(needle) { return true }
            if entry.event.action.lowercased().contains(needle) { return true }
            if entry.event.resourceID.lowercased().contains(needle) { return true }
            if entry.event.resourceType.lowercased().contains(needle) { return true }
            if entry.event.actor.lowercased().contains(needle) { return true }
            return entry.server.name.lowercased().contains(needle)
        }
    }

    private var failureCount: Int {
        allEntries.filter { !$0.event.succeeded }.count
    }

    private var groupedDays: [ActivityDay] {
        let calendar = Calendar.current
        var buckets: [Date: [FleetActivityEntry]] = [:]

        for entry in filteredEntries {
            let day = calendar.startOfDay(for: entry.event.date)
            buckets[day, default: []].append(entry)
        }

        return buckets.keys.sorted(by: >).map { day in
            ActivityDay(
                date: day,
                title: dayTitle(day, calendar: calendar),
                entries: (buckets[day] ?? []).sorted { $0.event.at > $1.event.at }
            )
        }
    }

    private func dayTitle(_ date: Date, calendar: Calendar) -> String {
        if calendar.isDateInToday(date) { return "Today" }
        if calendar.isDateInYesterday(date) { return "Yesterday" }
        return date.formatted(date: .abbreviated, time: .omitted)
    }

    private var selectedEntry: FleetActivityEntry? {
        guard let selectedEntryID else { return nil }
        return allEntries.first { $0.id == selectedEntryID }
    }

    // MARK: - Feed

    /// Events stay in memory after a server drops, so a feed can quietly become
    /// a history rather than a live view. Saying so is the difference between
    /// "nothing has happened" and "ServerOS stopped being able to see".
    private var unreachableServersWithHistory: [ServerSummary] {
        model.servers.filter { summary in
            guard let session = model.sessions[summary.id] else { return false }
            return !session.phase.isReady && !session.activity.isEmpty
        }
    }

    @ViewBuilder
    private func feed(_ days: [ActivityDay]) -> some View {
        VStack(spacing: 0) {
            let stale = unreachableServersWithHistory
            if !stale.isEmpty {
                InlineBanner(
                    .warning,
                    "ServerOS can't reach \(Formatting.list(stale.map(\.name), limit: 2)), so activity from \(stale.count == 1 ? "it" : "them") stops here rather than being live.",
                    actionTitle: "Reconnect",
                    action: { reconnect(stale) }
                )
                .padding(.horizontal, Spacing.screen)
                .padding(.top, Spacing.element)
            }

            listing(days)
        }
    }

    private func listing(_ days: [ActivityDay]) -> some View {
        List(selection: $selectedEntryID) {
            ForEach(days) { day in
                Section {
                    ForEach(day.entries) { entry in
                        FleetActivityRow(entry: entry)
                            .tag(entry.id)
                            .listRowInsets(EdgeInsets(
                                top: Spacing.tight,
                                leading: Spacing.screen,
                                bottom: Spacing.tight,
                                trailing: Spacing.screen
                            ))
                            .contextMenu {
                                Button("Open \(entry.server.name)") {
                                    navigation.enter(serverID: entry.server.id)
                                }
                                Button("Show Details") { selectedEntryID = entry.id }
                            }
                    }
                } header: {
                    Text(day.title)
                        .font(Typography.sectionTitle)
                        .foregroundStyle(Palette.textSecondary)
                        .accessibilityAddTraits(.isHeader)
                }
            }
        }
        .listStyle(.inset)
        .scrollContentBackground(.hidden)
    }

    // MARK: - Empty

    @ViewBuilder
    private var emptyState: some View {
        let trimmed = query.trimmingCharacters(in: .whitespaces)

        if model.servers.isEmpty {
            EmptyState(
                systemImage: "clock.arrow.circlepath",
                title: "No activity yet",
                message: "Activity is the record of what ServerOS did on your servers — who restarted what, and whether it worked. Connect a server and it starts filling in.",
                actionTitle: "Show Servers",
                action: { navigation.go(to: .servers) }
            )
        } else if !trimmed.isEmpty {
            EmptyState(
                systemImage: "magnifyingglass",
                title: "No activity matches “\(trimmed)”.",
                message: "ServerOS searched what happened, the resource it happened to, who asked, and which server.",
                actionTitle: "Clear Search",
                action: { query = "" }
            )
        } else if outcome != .all {
            EmptyState(
                systemImage: outcome == .failed ? "checkmark.circle" : "clock.arrow.circlepath",
                title: outcome == .failed ? "Nothing has failed." : "Nothing has succeeded yet.",
                message: "Every recorded action is being hidden by the current outcome filter.",
                actionTitle: "Show All Activity",
                action: { outcome = .all }
            )
        } else {
            EmptyState(
                systemImage: "clock.arrow.circlepath",
                title: "Nothing has happened yet",
                message: "Actions you take in ServerOS — restarting a container, editing a file, adding a user — are recorded by each server's agent and appear here.",
                actionTitle: "Show Servers",
                action: { navigation.go(to: .servers) }
            )
        }
    }

    // MARK: - Actions

    private func reloadServers() {
        Task { await model.load() }
    }

    private func reconnect(_ servers: [ServerSummary]) {
        for summary in servers {
            model.session(for: summary.id)?.reconnect()
        }
    }

    private func refreshEverything() {
        let sessions = Array(model.sessions.values)
        Task {
            for session in sessions {
                await session.refreshAll()
            }
        }
    }
}

// MARK: - Values

/// One audited event, with the server it happened on, under an id that is unique
/// across the whole fleet.
private struct FleetActivityEntry: Identifiable {
    let id: String
    let server: ServerSummary
    let event: ActivityEvent
}

/// One day's worth of the feed.
private struct ActivityDay: Identifiable {
    let date: Date
    let title: String
    let entries: [FleetActivityEntry]
    var id: Date { date }
}

// MARK: - Row

private struct FleetActivityRow: View {
    let entry: FleetActivityEntry

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            Image(systemName: symbol)
                .font(.system(size: 12))
                .foregroundStyle(entry.event.succeeded ? Palette.textSecondary : Palette.critical)
                .frame(width: 18)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(entry.event.summary)
                    .font(Typography.body)
                    .foregroundStyle(entry.event.succeeded ? Palette.textPrimary : Palette.critical)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)

                Text("\(entry.server.name) · \(entry.event.actor)")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
            }

            Spacer(minLength: Spacing.element)

            if !entry.event.succeeded {
                Chip("Failed", tint: Palette.critical, systemImage: "xmark")
            }

            Text(Formatting.relative(entry.event.date))
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .lineLimit(1)
        }
        .padding(.vertical, Spacing.snug)
        .contentShape(Rectangle())
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(entry.event.summary)
        .accessibilityValue(
            "\(entry.server.name), \(entry.event.actor), \(Formatting.relative(entry.event.date)), "
                + (entry.event.succeeded ? "succeeded" : "failed")
        )
        .help(Formatting.timestamp(entry.event.date))
    }

    private var symbol: String {
        entry.event.succeeded
            ? ActivitySymbol.name(for: entry.event.resourceType)
            : "exclamationmark.triangle.fill"
    }
}

// MARK: - Inspector

/// The exact facts about one event. Everything here is precise rather than
/// friendly — this is the pane somebody reads when "4 minutes ago" is not
/// good enough.
private struct ActivityInspector: View {
    let entry: FleetActivityEntry
    let onOpenServer: () -> Void
    let onClose: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.group) {
                HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
                    Text("Details")
                        .font(Typography.sectionTitle)
                        .foregroundStyle(Palette.textPrimary)
                        .accessibilityAddTraits(.isHeader)
                    Spacer(minLength: 0)
                    Button(action: onClose) {
                        Image(systemName: "xmark")
                            .font(.system(size: 10, weight: .semibold))
                            .foregroundStyle(Palette.textMuted)
                            .padding(Spacing.tight)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                    .accessibilityLabel("Close details")
                }

                Text(entry.event.summary)
                    .font(Typography.body)
                    .foregroundStyle(Palette.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                    .textSelection(.enabled)

                if entry.event.succeeded {
                    Chip("Succeeded", tint: Palette.healthy, systemImage: "checkmark")
                } else {
                    InlineBanner(.error, "This action did not complete. The server's own logs usually say why.")
                }

                Divider().overlay(Palette.divider)

                VStack(alignment: .leading, spacing: 0) {
                    KeyValueRow("Server", entry.server.name)
                    KeyValueRow("Action", entry.event.action, monospaced: true, selectable: true)
                    KeyValueRow("Resource", entry.event.resourceID, monospaced: true, selectable: true)
                    KeyValueRow("Resource type", entry.event.resourceType)
                    KeyValueRow("Requested by", entry.event.actor)
                    KeyValueRow("From", entry.event.peer, placeholder: "Not recorded", monospaced: true)
                    KeyValueRow("Outcome", entry.event.outcome.capitalizingFirstLetter())
                    KeyValueRow("When", Formatting.timestamp(entry.event.date))
                }

                Button("Open \(entry.server.name)", action: onOpenServer)
                    .buttonStyle(.secondary)
            }
            .padding(Spacing.card)
        }
        .background(Palette.surface)
        .accessibilityElement(children: .contain)
    }
}

// MARK: - Previews

@MainActor
private func previewActivityModel() -> AppModel {
    let container = try? ServerStore.makeContainer(inMemory: true)
    return AppModel(store: ServerStore(container: container ?? ServerStore.emptyContainer()))
}

#Preview("Activity — demo fleet") {
    let model = previewActivityModel()
    FleetActivityScreen(navigation: NavigationModel())
        .environment(model)
        .task { try? await model.enableDemoMode() }
        .frame(width: 1000, height: 640)
}
