//  ServersScreen.swift
//  ServerOS
//
//  WHY THIS SCREEN EXISTS
//
//  The Overview answers "is anything wrong?". This screen answers the other
//  half: **which machines do I have, and what are they?**
//
//  It is the inventory. Somebody with eleven servers across three clients uses
//  this screen to find one of them, and somebody with two uses it to confirm
//  that both are where they left them. So the row is deliberately dense — name,
//  address, distribution, agent version, when it was last heard from, and the
//  three numbers — because a list you have to click through to identify
//  anything is not an inventory, it is a menu.
//
//  Two decisions here are worth defending:
//
//  * **Order is information.** People arrange servers the way they think about
//    them, so the order is draggable and persisted rather than alphabetical.
//  * **Removing a server is not uninstalling anything.** The confirmation says
//    so in as many words. Getting that wrong — letting somebody believe they had
//    torn down a production agent by tidying a list — would be exactly the kind
//    of moment that ends trust in an infrastructure tool.

import AppKit
import Combine
import SwiftData
import SwiftUI

// MARK: - Filter

/// Which servers the list is showing.
///
/// The cases are deliberately non-overlapping: "Needs Attention" means warning
/// or critical, and an unreachable server has its own filter, because "it is
/// broken" and "I cannot see it" are different problems with different fixes.
public enum ServerListFilter: String, CaseIterable, Hashable, Sendable {
    case all
    case needsAttention
    case offline

    public var title: String {
        switch self {
        case .all: return "All"
        case .needsAttention: return "Needs Attention"
        case .offline: return "Offline"
        }
    }

    /// The `@AppStorage` key the Overview's tally writes so this screen can open
    /// already narrowed. A route carries no payload and a notification would be
    /// posted before this screen had mounted to hear it.
    public static let requestKey = "com.orionsystems.ServerOS.requestedServerFilter"

    func includes(_ state: HealthState) -> Bool {
        switch self {
        case .all: return true
        case .needsAttention: return state == .warning || state == .critical
        case .offline: return state == .offline
        }
    }
}

// MARK: - Screen

/// Every server ServerOS knows about, with enough detail to tell them apart.
public struct ServersScreen: View {

    @Environment(AppModel.self) private var model

    private let navigation: NavigationModel
    private let onAddServer: () -> Void

    @AppStorage(ServerListFilter.requestKey) private var requestedFilter: String = ""

    @State private var query = ""
    @State private var filter: ServerListFilter = .all
    @State private var renameTarget: ServerSummary?
    @State private var removalTarget: ServerSummary?
    @State private var isConfirmingRemoval = false

    public init(navigation: NavigationModel, onAddServer: @escaping () -> Void) {
        self.navigation = navigation
        self.onAddServer = onAddServer
    }

    public var body: some View {
        VStack(spacing: 0) {
            controls
            Divider().overlay(Palette.divider)

            StatefulContent(state, retry: { reloadServers() }) { entries in
                listing(entries)
            } empty: {
                noServersYet
            }
        }
        .background(Palette.background)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button(action: onAddServer) {
                    Label("Add Server", systemImage: "plus")
                }
                .help("Connect a new Linux server")
                .accessibilityLabel("Add Server")
            }
        }
        .sheet(item: $renameTarget) { summary in
            RenameServerSheet(summary: summary) { newName in
                rename(summary, to: newName)
            }
        }
        .confirmDestructive(
            isPresented: $isConfirmingRemoval,
            title: removalTitle,
            target: removalTarget?.name ?? "",
            consequence: removalConsequence,
            isReversible: false,
            confirmTitle: "Remove Server",
            perform: { removeConfirmedServer() }
        )
        .task { consumeRequestedFilter() }
        .onChange(of: requestedFilter) { _, _ in consumeRequestedFilter() }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            refreshEverything()
        }
    }

    // MARK: - Controls

    private var controls: some View {
        HStack(spacing: Spacing.group) {
            SearchField(text: $query, prompt: "Search servers")

            Picker("Show", selection: $filter) {
                ForEach(ServerListFilter.allCases, id: \.self) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(maxWidth: 320)
            .accessibilityLabel("Filter servers")

            Spacer(minLength: 0)

            Text(countLabel)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .monospacedDigit()
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.element)
    }

    private var countLabel: String {
        let shown = visibleEntries.count
        let total = model.servers.count
        if shown == total { return total == 1 ? "1 server" : "\(Formatting.count(total)) servers" }
        return "\(Formatting.count(shown)) of \(Formatting.count(total))"
    }

    // MARK: - State

    /// Capabilities belong to a server, not to the list of servers, so there is
    /// no "unavailable" case here. The other four are all reachable.
    private var state: ScreenState<[ServerListEntry]> {
        if let error = model.loadError { return .failed(error) }
        if model.isLoading && model.servers.isEmpty { return .loading }
        if model.servers.isEmpty { return .empty }
        return .loaded(visibleEntries)
    }

    private var allEntries: [ServerListEntry] {
        model.fleetHealth.map { pair in
            ServerListEntry(
                summary: pair.summary,
                health: pair.health,
                session: model.sessions[pair.summary.id]
            )
        }
    }

    private var visibleEntries: [ServerListEntry] {
        allEntries.filter { entry in
            filter.includes(entry.health.state) && matches(entry.summary)
        }
    }

    private func matches(_ summary: ServerSummary) -> Bool {
        let needle = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return true }
        if summary.name.lowercased().contains(needle) { return true }
        if summary.hostname.lowercased().contains(needle) { return true }
        if summary.sshUsername.lowercased().contains(needle) { return true }
        if let os = summary.osPretty, os.lowercased().contains(needle) { return true }
        return summary.tags.contains { $0.lowercased().contains(needle) }
    }

    /// Reordering a filtered list would silently move servers the user cannot
    /// see, so it is only offered when the list is showing everything.
    private var canReorder: Bool {
        filter == .all && query.trimmingCharacters(in: .whitespaces).isEmpty
    }

    // MARK: - Listing

    @ViewBuilder
    private func listing(_ entries: [ServerListEntry]) -> some View {
        if entries.isEmpty {
            noMatches
        } else {
            List {
                ForEach(entries) { entry in
                    Button {
                        navigation.enter(serverID: entry.summary.id)
                    } label: {
                        ServerListRow(entry: entry)
                    }
                    .buttonStyle(.plain)
                    .listRowInsets(EdgeInsets(
                        top: Spacing.element,
                        leading: Spacing.screen,
                        bottom: Spacing.element,
                        trailing: Spacing.screen
                    ))
                    .contextMenu {
                        Button("Open") { navigation.enter(serverID: entry.summary.id) }
                        Button("Reconnect") { model.session(for: entry.summary.id)?.reconnect() }
                        Divider()
                        Button("Rename…") { renameTarget = entry.summary }
                        Button("Copy Hostname") { copyHostname(entry.summary) }
                        Divider()
                        Button("Remove from ServerOS…", role: .destructive) {
                            removalTarget = entry.summary
                            isConfirmingRemoval = true
                        }
                    }
                }
                .onMove { source, destination in
                    move(from: source, to: destination)
                }
            }
            .listStyle(.inset)
            .scrollContentBackground(.hidden)
        }
    }

    // MARK: - Empty states

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
    }

    /// Deliberately different copy from "No servers yet": one means the user has
    /// nothing, the other means the user has something and this screen is
    /// hiding it. Offering "Add Server" in the second case would be the wrong
    /// answer to the question they just asked.
    @ViewBuilder
    private var noMatches: some View {
        let trimmed = query.trimmingCharacters(in: .whitespaces)

        if !trimmed.isEmpty {
            EmptyState(
                systemImage: "magnifyingglass",
                title: "No servers match “\(trimmed)”.",
                message: "ServerOS searched names, hostnames, usernames, distributions and tags.",
                actionTitle: "Clear Search",
                action: { query = "" }
            )
        } else {
            EmptyState(
                systemImage: filter == .offline ? "bolt.horizontal.circle" : "checkmark.circle",
                title: filter == .offline ? "Every server is reachable." : "Nothing needs attention.",
                message: filter == .offline
                    ? "ServerOS is in touch with all \(Formatting.count(model.servers.count)) of your servers."
                    : "No server is reporting a warning or a critical condition right now.",
                actionTitle: "Show All Servers",
                action: { filter = .all }
            )
        }
    }

    // MARK: - Destructive copy

    private var removalTitle: String {
        guard let target = removalTarget else { return "Remove this server from ServerOS?" }
        return "Remove \(target.name) from ServerOS?"
    }

    /// The single most important sentence on this screen.
    private var removalConsequence: String {
        guard let target = removalTarget else {
            return "ServerOS will forget this server and delete its saved credential from this Mac."
        }
        return """
        ServerOS will forget \(target.name) and delete its saved credential from this Mac's Keychain.

        The ServerOS agent is not uninstalled and the server keeps running — nothing on \(target.hostname) changes. To manage it from this Mac again you would set it up once more.
        """
    }

    // MARK: - Actions

    private func consumeRequestedFilter() {
        guard let requested = ServerListFilter(rawValue: requestedFilter) else { return }
        filter = requested
        requestedFilter = ""
    }

    private func rename(_ summary: ServerSummary, to newName: String) {
        let trimmed = newName.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != summary.name else { return }
        Task { try? await model.rename(id: summary.id, to: trimmed) }
    }

    private func removeConfirmedServer() {
        guard let target = removalTarget else { return }
        removalTarget = nil
        navigation.forgetServer(id: target.id)
        Task { try? await model.remove(id: target.id) }
    }

    private func copyHostname(_ summary: ServerSummary) {
        let pasteboard = NSPasteboard.general
        // Both AppKit calls return a value nobody here needs.
        _ = pasteboard.clearContents()
        _ = pasteboard.setString(summary.hostname, forType: .string)
    }

    private func move(from source: IndexSet, to destination: Int) {
        guard canReorder else { return }
        var ids = model.servers.map(\.id)
        ids.move(fromOffsets: source, toOffset: destination)
        Task { try? await model.reorder(ids) }
    }

    private func startDemo() {
        Task { try? await model.enableDemoMode() }
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

// MARK: - Row model

/// One row's worth of state, as an `Identifiable` value — `AppModel.fleetHealth`
/// hands back tuples, and Swift has no key paths into tuple members.
private struct ServerListEntry: Identifiable {
    let summary: ServerSummary
    let health: ServerHealth
    let session: ServerSession?
    var id: String { summary.id }
}

// MARK: - Row

private struct ServerListRow: View {
    let entry: ServerListEntry

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.group) {
            StatusDot(entry.health.state, size: 11)
                .padding(.top, 2)

            identity

            Spacer(minLength: Spacing.group)

            metrics
        }
        .padding(.vertical, Spacing.snug)
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(entry.summary.name), \(entry.health.state.accessibilityLabel)")
        .help(entry.health.summary)
    }

    private var identity: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            HStack(spacing: Spacing.snug) {
                Text(entry.summary.name)
                    .font(Typography.body.weight(.medium))
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)

                if entry.summary.isDemo {
                    Chip("Demo", tint: Palette.informational, systemImage: "wand.and.stars")
                }

                HealthBadge(entry.health.state, compact: true)
            }

            Text(entry.summary.describedEndpoint)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
                .lineLimit(1)
                .textSelection(.enabled)

            Text(facts)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .lineLimit(1)
                .truncationMode(.tail)

            if !entry.summary.tags.isEmpty {
                HStack(spacing: Spacing.tight) {
                    ForEach(entry.summary.tags, id: \.self) { tag in
                        Chip(tag)
                    }
                }
            }
        }
    }

    /// Distribution, architecture, agent version and last contact, as one quiet
    /// line rather than four competing ones. A single `Text` rather than a row
    /// of them: the separators would need ids of their own in a `ForEach`, and
    /// the row already carries a combined label for VoiceOver.
    private var facts: String {
        var parts: [String] = []
        parts.append(entry.summary.osPretty ?? "Distribution unknown")
        if let arch = entry.summary.arch { parts.append(arch) }
        if let version = entry.session?.agentVersion {
            parts.append("Agent \(version)")
        }
        parts.append(lastSeen)
        return parts.joined(separator: " · ")
    }

    private var lastSeen: String {
        if entry.session?.phase.isReady == true { return "Connected" }
        if let contact = entry.session?.lastContact {
            return "Last seen \(Formatting.relative(contact))"
        }
        if let seen = entry.summary.lastSeenAt {
            return "Last seen \(Formatting.relative(seen))"
        }
        return "Never connected"
    }

    private var metrics: some View {
        HStack(alignment: .top, spacing: Spacing.card) {
            MetricTile(label: "CPU", value: cpuPercent)
            MetricTile(label: "Memory", value: entry.session?.metrics?.memory.usagePercent)
            MetricTile(label: "Storage", value: entry.session?.metrics?.disk.usagePercent)
        }
        .frame(width: 330, alignment: .trailing)
    }

    /// Nil, not zero, while the sampler is warming up — a confident 0% on a
    /// freshly connected server is a lie the user would act on.
    private var cpuPercent: Double? {
        // Named `sample` rather than `metrics` so it cannot be confused with
        // this row's `metrics` view.
        guard let sample = entry.session?.metrics, !sample.isWarmingUp else { return nil }
        return sample.cpu.usagePercent
    }
}

// MARK: - Rename

/// Renaming is local and cosmetic: the name never leaves this Mac and nothing on
/// the server changes, which is why this is a small sheet rather than a flow.
private struct RenameServerSheet: View {
    @Environment(\.dismiss) private var dismiss

    let summary: ServerSummary
    let onSave: (String) -> Void

    @State private var name: String
    @FocusState private var isFieldFocused: Bool

    init(summary: ServerSummary, onSave: @escaping (String) -> Void) {
        self.summary = summary
        self.onSave = onSave
        _name = State(initialValue: summary.name)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            Text("Rename Server")
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.textPrimary)
                .accessibilityAddTraits(.isHeader)

            Text("This name is only used on this Mac. \(summary.hostname) is unchanged.")
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            TextField("Name", text: $name)
                .textFieldStyle(.roundedBorder)
                .font(Typography.body)
                .focused($isFieldFocused)
                .onSubmit { save() }

            if trimmedName.isEmpty {
                Text("A name is required.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.critical)
            }

            HStack(spacing: Spacing.element) {
                Spacer(minLength: 0)
                Button("Cancel") { dismiss() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Button("Save") { save() }
                    .buttonStyle(.primary)
                    .disabled(trimmedName.isEmpty)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(Spacing.screen)
        .frame(width: 380)
        .background(Palette.background)
        .onAppear { isFieldFocused = true }
    }

    private var trimmedName: String {
        name.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private func save() {
        guard !trimmedName.isEmpty else { return }
        onSave(trimmedName)
        dismiss()
    }
}

// MARK: - Previews

@MainActor
private func previewServersModel() -> AppModel {
    let container = try? ServerStore.makeContainer(inMemory: true)
    return AppModel(store: ServerStore(container: container ?? ServerStore.emptyContainer()))
}

#Preview("Servers — demo fleet") {
    let model = previewServersModel()
    ServersScreen(navigation: NavigationModel(), onAddServer: {})
        .environment(model)
        .task { try? await model.enableDemoMode() }
        .frame(width: 1040, height: 640)
}

#Preview("Servers — empty") {
    ServersScreen(navigation: NavigationModel(), onAddServer: {})
        .environment(previewServersModel())
        .frame(width: 1040, height: 560)
}
