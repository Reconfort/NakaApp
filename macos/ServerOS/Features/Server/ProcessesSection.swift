//  ProcessesSection.swift
//  ServerOS
//
//  "What is eating my server?"
//
//  This is the one screen in ServerOS that is unapologetically a table, because
//  the question it answers is genuinely tabular: several hundred rows, eight
//  comparable columns, and an answer that comes from sorting rather than from
//  reading. Dressing that up as cards would be decoration at the cost of the
//  job.
//
//  Two decisions are worth knowing about:
//
//  * **Sorting and searching happen on the server.** The agent has the whole
//    process table; we ask it for the top N by a column. Pulling four thousand
//    processes across an SSH tunnel so the Mac can sort them would be slower and
//    would make the displayed list depend on what we happened to have fetched.
//    Column direction is then applied locally, so toggling ascending/descending
//    feels instant instead of costing a round trip.
//  * **Signals are the only mutation, and both are destructive.** Terminate asks
//    politely; Force Quit does not. Both name the process and its PID in the
//    confirmation, and Force Quit says plainly that unsaved work is lost.

import Combine
import SwiftUI

/// The process table for one server.
public struct ProcessesSection: View {

    /// How many rows we ask the agent for. Enough that the answer to "what is
    /// eating my server" is always in the list; small enough that it stays a
    /// single fast response.
    private static let rowLimit = 200

    /// How often the table refreshes while it is on screen. Processes change
    /// constantly; five seconds is often enough to be useful and slow enough
    /// that rows are readable.
    private static let refreshInterval: Duration = .seconds(5)

    /// Typing shouldn't fire a request per keystroke down an SSH tunnel.
    private static let searchDebounce: Duration = .milliseconds(250)

    private let session: ServerSession
    private let navigation: NavigationModel

    @State private var state: ScreenState<ProcessPage> = .loading
    @State private var searchText = ""
    @State private var request = Request()
    @State private var sortOrder = [KeyPathComparator(\ProcessRow.cpuPercent, order: .reverse)]
    @State private var selection = Set<Int32>()
    @State private var pendingSignal: PendingSignal?
    @State private var isConfirmingSignal = false
    @State private var actionError: ServerOSError?

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            toolbar

            if let actionError {
                InlineBanner(.error, actionError.headline, actionTitle: "Dismiss") {
                    self.actionError = nil
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.bottom, Spacing.element)
            }

            StatefulContent(state, retry: { request.nonce += 1 }) { page in
                table(page)
            } empty: {
                emptyState
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        // One request key: sort, search and an explicit nonce. Anything that
        // should re-ask the server changes it, and `.task(id:)` cancels the
        // in-flight request for free when it does.
        .task(id: request) { await runRequest() }
        // The periodic refresh runs only while the screen is on show, and
        // refreshes in place rather than dropping back to a skeleton.
        .task { await pollWhileVisible() }
        .onChange(of: searchText) { _, newValue in
            request = Request(sort: request.sort, search: newValue, nonce: request.nonce, isDebounced: true)
        }
        .onChange(of: sortOrder) { _, newValue in
            request = Request(
                sort: ProcessesSection.serverSort(for: newValue),
                search: request.search,
                nonce: request.nonce,
                isDebounced: false
            )
        }
        // The agent reports what it can do a moment after the connection is
        // ready; ask again when it does, rather than stranding the screen on
        // whatever was true during the handshake.
        .onChange(of: session.capabilities) { _, _ in request.nonce += 1 }
        .onChange(of: session.phase.isReady) { _, isReady in
            if isReady { request.nonce += 1 }
        }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            Task { await load(showsLoading: false) }
        }
        .confirmDestructive(
            isPresented: $isConfirmingSignal,
            title: pendingSignal?.title ?? "Stop this process?",
            target: pendingSignal?.processName ?? "",
            consequence: pendingSignal?.consequence ?? "",
            isReversible: false,
            confirmTitle: pendingSignal?.confirmTitle ?? "Stop"
        ) {
            if let pending = pendingSignal { send(pending) }
        }
    }

    // MARK: - Toolbar

    private var toolbar: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Processes")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(countLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Spacer(minLength: Spacing.group)

            SearchField(text: $searchText, prompt: "Search processes")
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    /// The list is capped, and saying so is the difference between "these are
    /// the processes" and "these are the ones that matter most right now".
    private var countLine: String {
        guard let page = state.value else {
            return "Reading the process table on \(session.name)…"
        }
        let sorted = ProcessesSection.sortDescription(for: request.sort)
        if page.total > page.rows.count {
            return "Showing the top \(Formatting.count(page.rows.count)) of \(Formatting.count(page.total)) processes, by \(sorted)."
        }
        return "\(Formatting.count(page.rows.count)) process\(page.rows.count == 1 ? "" : "es"), by \(sorted)."
    }

    // MARK: - The table

    private func table(_ page: ProcessPage) -> some View {
        // Membership comes from the server; the comparator only orders the page
        // we were given, so flipping a column's direction is instant.
        let rows = page.rows.sorted(using: sortOrder)

        return Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Process", value: \.name) { row in
                VStack(alignment: .leading, spacing: 0) {
                    Text(row.name)
                        .font(Typography.body)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                    Text(row.command)
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .padding(.vertical, 2)
                .help(row.command)
            }
            .width(min: 180, ideal: 280)

            TableColumn("PID", value: \.pid) { row in
                Text(String(row.pid))
                    .font(Typography.codeSmall)
                    .foregroundStyle(Palette.textSecondary)
            }
            .width(min: 56, ideal: 64, max: 90)

            TableColumn("User", value: \.owner) { row in
                Text(row.owner)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
            }
            .width(min: 70, ideal: 96, max: 140)

            TableColumn("CPU", value: \.cpuPercent) { row in
                Text(Formatting.percent(row.cpuPercent))
                    .font(Typography.metricSmall)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityLabel("CPU")
                    .accessibilityValue(Formatting.percent(row.cpuPercent))
            }
            .width(min: 56, ideal: 70, max: 90)

            TableColumn("Memory", value: \.memoryBytes) { row in
                VStack(alignment: .leading, spacing: 0) {
                    Text(Formatting.bytes(row.memoryBytes))
                        .font(Typography.metricSmall)
                        .foregroundStyle(Palette.textPrimary)
                    Text(Formatting.percent(row.memoryPercent))
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                }
                .padding(.vertical, 2)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Memory")
                .accessibilityValue("\(Formatting.bytes(row.memoryBytes)), \(Formatting.percent(row.memoryPercent)) of this server")
            }
            .width(min: 80, ideal: 110, max: 150)

            TableColumn("Threads", value: \.threads) { row in
                Text(Formatting.count(row.threads))
                    .font(Typography.metricSmall)
                    .foregroundStyle(Palette.textSecondary)
            }
            .width(min: 60, ideal: 70, max: 100)

            TableColumn("State", value: \.state) { row in
                // Never colour alone: the pill carries the word too.
                Chip(row.stateLabel, tint: ProcessesSection.tint(forState: row.state))
            }
            .width(min: 92, ideal: 110, max: 150)

            TableColumn("Started", value: \.startedAt) { row in
                Text(row.startedLabel)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
            }
            .width(min: 90, ideal: 120, max: 170)
        }
        .tableStyle(.inset)
        .contextMenu(forSelectionType: Int32.self) { ids in
            if let id = ids.first, ids.count == 1, let row = rows.first(where: { $0.id == id }) {
                Button("Terminate…") { ask(.terminate, row) }
                Button("Force Quit…", role: .destructive) { ask(.forceQuit, row) }
            }
        }
        .padding(.horizontal, Spacing.card)
        .padding(.bottom, Spacing.card)
    }

    private var emptyState: some View {
        EmptyState(
            systemImage: searchText.isEmpty ? "list.bullet.rectangle" : "magnifyingglass",
            title: searchText.isEmpty ? "No processes to show" : "Nothing matches “\(searchText)”",
            message: searchText.isEmpty
                ? "ServerOS asked \(session.name) for its running processes and got an empty list back, which usually means the agent can't read /proc."
                : "No running process on \(session.name) has that in its name or command line.",
            actionTitle: searchText.isEmpty ? "Try Again" : "Clear Search",
            action: {
                if searchText.isEmpty {
                    request.nonce += 1
                } else {
                    searchText = ""
                }
            }
        )
    }

    // MARK: - Signals

    /// A signal the user has asked for but not yet confirmed.
    private struct PendingSignal: Equatable {
        enum Kind: Equatable { case terminate, forceQuit }

        let kind: Kind
        let pid: Int32
        let processName: String

        var signal: ProcessSignal { kind == .terminate ? .term : .kill }

        var title: String {
            kind == .terminate
                ? "Terminate \(processName) (PID \(pid))?"
                : "Force quit \(processName) (PID \(pid))?"
        }

        var confirmTitle: String { kind == .terminate ? "Terminate" : "Force Quit" }

        var consequence: String {
            switch kind {
            case .terminate:
                return "ServerOS will ask \(processName) to shut down. Most programs save their work and exit; "
                    + "one that is stuck may keep running."
            case .forceQuit:
                return "\(processName) will be stopped immediately and cannot save anything first. "
                    + "Unsaved work in this process is lost, and anything depending on it may fail."
            }
        }
    }

    private func ask(_ kind: PendingSignal.Kind, _ row: ProcessRow) {
        pendingSignal = PendingSignal(kind: kind, pid: row.pid, processName: row.name)
        isConfirmingSignal = true
    }

    private func send(_ pending: PendingSignal) {
        guard let api = session.api else {
            actionError = ServerOSError.sshNotConnected
            return
        }
        Task {
            do {
                try await api.signalProcess(pid: pending.pid, signal: pending.signal)
                actionError = nil
                // The table is the feedback: re-read so the row disappears, or
                // visibly does not.
                await load(showsLoading: false)
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
            pendingSignal = nil
        }
    }

    // MARK: - Loading

    /// What a fetch is for. Changing any field re-asks the server.
    private struct Request: Equatable {
        var sort: ProcessSort = .cpu
        var search: String = ""
        var nonce: Int = 0
        /// True when the change came from typing, which is worth waiting out.
        var isDebounced: Bool = false
    }

    /// One page of the process table, as this screen shows it.
    private struct ProcessPage {
        let rows: [ProcessRow]
        /// How many processes the server has in total, which is usually more
        /// than we asked for.
        let total: Int
    }

    private func runRequest() async {
        if request.isDebounced {
            try? await Task.sleep(for: ProcessesSection.searchDebounce)
            if Task.isCancelled { return }
        }
        await load(showsLoading: true)
    }

    private func pollWhileVisible() async {
        while !Task.isCancelled {
            try? await Task.sleep(for: ProcessesSection.refreshInterval)
            if Task.isCancelled { return }
            await load(showsLoading: false)
        }
    }

    /// - Parameter showsLoading: False for the background refresh, so a table
    ///   the user is reading never flickers back to a skeleton.
    private func load(showsLoading: Bool) async {
        // Order matters: capabilities are `.none` until the agent has answered,
        // so asking about them before there is an API would declare a perfectly
        // capable server incapable.
        guard let api = session.api else {
            if showsLoading { state = .loading }
            return
        }
        guard session.capabilities.processes else {
            state = .unavailable(
                subsystem: "Processes",
                reason: "This server's agent can't read the process table, so ServerOS has nothing to show here."
            )
            return
        }
        if showsLoading, state.value == nil { state = .loading }

        let search = request.search.trimmingCharacters(in: .whitespaces)
        do {
            let list = try await api.processes(
                sort: request.sort,
                limit: ProcessesSection.rowLimit,
                search: search.isEmpty ? nil : search
            )
            let rows = list.items.map { ProcessRow($0) }
            state = rows.isEmpty ? .empty : .loaded(ProcessPage(rows: rows, total: max(list.total, rows.count)))
        } catch let error as ServerOSError {
            // A background refresh that fails must not wipe a good table off the
            // screen; the stale banner in the shell already says we are out of
            // touch with the server.
            if showsLoading || state.value == nil { state = .failed(error) }
        } catch {
            if showsLoading || state.value == nil {
                state = .failed(ServerOSError.transport(error, serverName: session.name))
            }
        }
    }

    // MARK: - Column mapping

    /// Which agent-side ordering a clicked column asks for.
    private static func serverSort(for comparators: [KeyPathComparator<ProcessRow>]) -> ProcessSort {
        // Widened to `AnyKeyPath` so the comparison does not depend on how the
        // SDK spells `KeyPathComparator.keyPath` — it has gained a `Sendable`
        // constraint between releases.
        guard let keyPath = comparators.first.map({ $0.keyPath as AnyKeyPath }) else { return .cpu }
        if keyPath == (\ProcessRow.cpuPercent as AnyKeyPath) { return .cpu }
        if keyPath == (\ProcessRow.memoryBytes as AnyKeyPath) { return .memory }
        if keyPath == (\ProcessRow.memoryPercent as AnyKeyPath) { return .memory }
        if keyPath == (\ProcessRow.pid as AnyKeyPath) { return .pid }
        if keyPath == (\ProcessRow.name as AnyKeyPath) { return .name }
        // Threads, user, state and start time have no server-side ordering. CPU
        // decides which processes are in the page; the column then orders them.
        return .cpu
    }

    private static func sortDescription(for sort: ProcessSort) -> String {
        switch sort {
        case .cpu: return "CPU"
        case .memory: return "memory"
        case .pid: return "PID"
        case .name: return "name"
        }
    }

    private static func tint(forState state: String) -> Color {
        switch state {
        case "running": return Palette.healthy
        case "zombie": return Palette.critical
        case "disk-sleep", "stopped": return Palette.warning
        default: return Palette.inactive
        }
    }
}

// MARK: - Row model

/// One row of the process table.
///
/// A view model rather than the wire type: `Table`'s sortable columns need every
/// sorted value to be `Comparable`, and `ProcessInfo.user` is optional — which
/// `Optional` is not. Flattening that here keeps the awkwardness in one place
/// instead of in eight column declarations.
private struct ProcessRow: Identifiable, Equatable {
    let id: Int32
    let pid: Int32
    let name: String
    let command: String
    let owner: String
    let cpuPercent: Double
    let memoryBytes: Int64
    let memoryPercent: Double
    let threads: Int
    /// The agent's state word, used for tinting.
    let state: String
    /// The same state in the product's vocabulary.
    let stateLabel: String
    /// Unix seconds, or 0 when the agent could not tell — sorts oldest-first,
    /// which is where "unknown" belongs.
    let startedAt: Int64
    let startedLabel: String

    init(_ process: ProcessInfo) {
        self.id = process.pid
        self.pid = process.pid
        self.name = process.name
        self.command = process.command.isEmpty ? process.name : process.command
        self.owner = process.user ?? "uid \(process.uid)"
        self.cpuPercent = process.cpuPercent
        self.memoryBytes = process.memoryBytes
        self.memoryPercent = process.memoryPercent
        self.threads = process.threads
        self.state = process.state
        self.stateLabel = Formatting.processState(process.state)
        self.startedAt = process.startedAt ?? 0
        if let started = process.startedAt, started > 0 {
            self.startedLabel = Formatting.relative(unixSeconds: started)
        } else {
            self.startedLabel = "Unknown"
        }
    }
}

// MARK: - Preview

private struct ProcessesPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        ProcessesSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 980, height: 620)
            .onAppear { session.connect() }
    }
}

#Preview("Processes") {
    ProcessesPreviewHost()
}
