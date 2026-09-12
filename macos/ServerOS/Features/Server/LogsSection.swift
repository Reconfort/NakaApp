//  LogsSection.swift
//  ServerOS
//
//  Reading a server's logs without `journalctl -u nginx -f | grep -i timeout`.
//
//  A log viewer earns its place only if it is genuinely better than tailing a
//  file over SSH. That means four things, and this screen is built around them:
//
//  * **Filtering happens on the server.** `filter:` and `isRegex:` go to the
//    agent, which greps before it sends. The alternative — shipping four
//    gigabytes of syslog across an SSH tunnel so the Mac can search it — is not
//    a feature, it is a denial of service against your own laptop.
//  * **Follow mode behaves like `tail -f` and like a scroll view at once.** It
//    re-reads every two seconds and sticks to the bottom, but the moment you
//    scroll up to read something it stops yanking you away, and offers to take
//    you back when you want.
//  * **Level is never colour alone.** Every line carries a level chip with the
//    word in it and a coloured edge marker, so severity survives both a
//    monochrome display and a colour-blind reader.
//  * **Memory is bounded.** At most 5,000 lines are held, and the screen says so
//    when it has dropped some rather than pretending it showed everything.

import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

/// The log viewer for one server: journal or file, filtered on the server.
public struct LogsSection: View {

    /// The most lines we will ever hold. A window left open on a busy server
    /// must not grow without bound.
    private static let retainedLineLimit = 5_000

    /// How often follow mode re-reads.
    private static let followInterval: Duration = .seconds(2)

    /// Distance from the bottom, in points, within which we consider the reader
    /// "at the end" and safe to auto-scroll.
    private static let bottomTolerance: CGFloat = 48

    private static let scrollSpace = "serveros.logs.scroll"

    private let session: ServerSession
    private let navigation: NavigationModel

    @State private var source: LogSource = .journal
    @State private var unit = ""
    @State private var path = "/var/log/syslog"
    @State private var filter = ""
    @State private var isRegex = false
    @State private var lineCount: Int = 1_000
    @State private var isFollowing = false

    @State private var state: ScreenState<[LogRow]> = .loading
    @State private var wasTruncated = false
    @State private var reloadNonce = 0
    /// Bumped on every successful read, so follow mode can tell "the same 500
    /// lines again" from "500 new lines".
    @State private var revision = 0
    @State private var isPinnedToBottom = true
    @State private var isExporting = false
    /// Built only when the user asks to save. Joining 5,000 lines on every
    /// body evaluation would make scrolling the log cost more than reading it.
    @State private var exportDocument: LogTextDocument?

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            controls
            Divider().overlay(Palette.divider)

            StatefulContent(state, retry: { reloadNonce += 1 }) { rows in
                logBody(rows)
            } empty: {
                emptyState
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .onAppear { if !session.capabilities.journal { source = .file } }
        .task(id: query) { await load(showsLoading: true) }
        .task(id: isFollowing) { await followWhileEnabled() }
        .onChange(of: session.capabilities) { _, capabilities in
            if !capabilities.journal { source = .file }
            reloadNonce += 1
        }
        .onChange(of: session.phase.isReady) { _, isReady in
            if isReady { reloadNonce += 1 }
        }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            Task { await load(showsLoading: false) }
        }
        .fileExporter(
            isPresented: $isExporting,
            document: exportDocument,
            contentType: .plainText,
            defaultFilename: suggestedFilename
        ) { _ in
            // Success and cancellation are both fine; a failure is reported by
            // the system's own sheet, so there is nothing useful to add here.
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Logs")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(statusLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
            }

            Spacer(minLength: Spacing.group)

            Button("Copy All", action: copyAll)
                .buttonStyle(.secondary)
                .disabled(rows.isEmpty)

            Button("Save to File…") {
                exportDocument = LogTextDocument(text: plainText)
                isExporting = true
            }
            .buttonStyle(.secondary)
            .disabled(rows.isEmpty)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.top, Spacing.group)
        .padding(.bottom, Spacing.element)
    }

    private var statusLine: String {
        var parts: [String] = []
        parts.append("\(Formatting.count(rows.count)) line\(rows.count == 1 ? "" : "s")")
        if wasTruncated {
            parts.append("older lines not shown")
        }
        parts.append(source == .journal
            ? (unit.isEmpty ? "System journal" : "journal · \(unit)")
            : path)
        if isFollowing {
            parts.append("Following")
        }
        return parts.joined(separator: "  ·  ")
    }

    // MARK: - Controls

    private var controls: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            HStack(spacing: Spacing.element) {
                Picker("Source", selection: $source) {
                    ForEach(LogSource.allCases, id: \.self) { candidate in
                        Text(candidate.title).tag(candidate)
                    }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
                .fixedSize()
                .disabled(!session.capabilities.journal)
                .help(session.capabilities.journal
                      ? "Choose between the system journal and a log file."
                      : "This server has no systemd journal, so ServerOS reads log files directly.")

                if source == .journal {
                    TextField("All units", text: $unit)
                        .textFieldStyle(.roundedBorder)
                        .font(Typography.code)
                        .frame(maxWidth: 220)
                        .onSubmit { reloadNonce += 1 }
                        .accessibilityLabel("Filter by systemd unit")
                } else {
                    TextField("/var/log/syslog", text: $path)
                        .textFieldStyle(.roundedBorder)
                        .font(Typography.code)
                        .frame(maxWidth: 320)
                        .onSubmit { reloadNonce += 1 }
                        .accessibilityLabel("Log file path")
                }

                Spacer(minLength: Spacing.element)

                Picker("Lines", selection: $lineCount) {
                    Text("200").tag(200)
                    Text("1,000").tag(1_000)
                    Text("5,000").tag(5_000)
                }
                .pickerStyle(.menu)
                .fixedSize()
                .accessibilityLabel("Number of lines to read")

                Toggle("Follow", isOn: $isFollowing)
                    .toggleStyle(.switch)
                    .controlSize(.small)
                    .help("Re-read every two seconds and stay at the newest line.")
            }

            HStack(spacing: Spacing.element) {
                SearchField(text: $filter, prompt: isRegex ? "Regular expression" : "Filter lines")
                    .frame(maxWidth: 320)

                Toggle("Regex", isOn: $isRegex)
                    .toggleStyle(.checkbox)
                    .controlSize(.small)
                    .help("Treat the filter as a regular expression. Matching happens on the server.")

                Text("Filtering runs on \(session.name), so only matching lines cross the connection.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)

                Spacer(minLength: 0)
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.bottom, Spacing.group)
    }

    // MARK: - The log itself

    private func logBody(_ rows: [LogRow]) -> some View {
        GeometryReader { outer in
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(rows) { row in
                            LogLineRow(row: row)
                                .id(row.id)
                        }
                        // A zero-height anchor is a more reliable scroll target
                        // than the last row, which can be taller than the
                        // viewport when a line wraps.
                        Color.clear
                            .frame(height: 1)
                            .id(LogsSection.bottomAnchor)
                    }
                    .padding(.vertical, Spacing.element)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        GeometryReader { inner in
                            Color.clear.preference(
                                key: LogBottomDistanceKey.self,
                                value: inner.frame(in: .named(LogsSection.scrollSpace)).maxY - outer.size.height
                            )
                        }
                    )
                }
                .coordinateSpace(name: LogsSection.scrollSpace)
                .onPreferenceChange(LogBottomDistanceKey.self) { distance in
                    let pinned = distance <= LogsSection.bottomTolerance
                    if pinned != isPinnedToBottom { isPinnedToBottom = pinned }
                }
                .onChange(of: revision) { _, _ in
                    guard isFollowing, isPinnedToBottom else { return }
                    proxy.scrollTo(LogsSection.bottomAnchor, anchor: .bottom)
                }
                .overlay(alignment: .bottom) {
                    if isFollowing && !isPinnedToBottom {
                        jumpToLatest(proxy)
                    }
                }
            }
        }
        .background(Palette.surface)
    }

    private static let bottomAnchor = "serveros.logs.bottom"

    private func jumpToLatest(_ proxy: ScrollViewProxy) -> some View {
        Button {
            withAnimation(Motion.appear) {
                proxy.scrollTo(LogsSection.bottomAnchor, anchor: .bottom)
            }
            isPinnedToBottom = true
        } label: {
            HStack(spacing: Spacing.snug) {
                Image(systemName: "arrow.down")
                    .font(.system(size: 10, weight: .semibold))
                Text("Jump to Latest").font(Typography.secondary.weight(.medium))
            }
            .foregroundStyle(Palette.textOnAccent)
            .padding(.horizontal, Spacing.group)
            .padding(.vertical, Spacing.snug)
            .background(Palette.accent, in: Capsule())
        }
        .buttonStyle(.plain)
        .padding(.bottom, Spacing.card)
        .transition(.move(edge: .bottom).combined(with: .opacity))
        .accessibilityLabel("Jump to the newest log line")
    }

    private var emptyState: some View {
        EmptyState(
            systemImage: filter.isEmpty ? "text.alignleft" : "magnifyingglass",
            title: filter.isEmpty ? "Nothing has been logged here" : "Nothing matches that filter",
            message: filter.isEmpty
                ? (source == .journal
                    ? "The journal on \(session.name) has no entries for this selection. Try removing the unit filter, or read a log file instead."
                    : "\(path) is empty, or the agent can't read it. Check the path, or browse to it in Files.")
                : "No line in the last \(Formatting.count(lineCount)) matches “\(filter)”. Widen the filter, or read more lines.",
            actionTitle: filter.isEmpty ? "Reload" : "Clear Filter",
            action: {
                if filter.isEmpty { reloadNonce += 1 } else { filter = "" }
            },
            secondaryActionTitle: browseTitle,
            secondaryAction: browseAction
        )
    }

    /// Offered only when the likely fix is "look at the file yourself" — a path
    /// that does not exist is a Files problem, not a Logs problem.
    private var browseTitle: String? {
        (filter.isEmpty && source == .file) ? "Open Files" : nil
    }

    private var browseAction: (() -> Void)? {
        guard filter.isEmpty, source == .file else { return nil }
        return {
            navigation.currentFilePath = "/var/log"
            navigation.select(section: .files)
        }
    }

    // MARK: - Data

    /// Everything that changes what we ask the agent for.
    private struct Query: Equatable {
        var source: LogSource
        var unit: String
        var path: String
        var filter: String
        var isRegex: Bool
        var lines: Int
        var nonce: Int
    }

    private var query: Query {
        Query(
            source: source,
            unit: unit.trimmingCharacters(in: .whitespaces),
            path: path.trimmingCharacters(in: .whitespaces),
            filter: filter,
            isRegex: isRegex,
            lines: lineCount,
            nonce: reloadNonce
        )
    }

    private var rows: [LogRow] { state.value ?? [] }

    private func followWhileEnabled() async {
        guard isFollowing else { return }
        while !Task.isCancelled {
            try? await Task.sleep(for: LogsSection.followInterval)
            if Task.isCancelled { return }
            await load(showsLoading: false)
        }
    }

    private func load(showsLoading: Bool) async {
        guard let api = session.api else {
            if showsLoading { state = .loading }
            return
        }
        guard session.capabilities.logs else {
            state = .unavailable(
                subsystem: "Logs",
                reason: "This server's agent can't read logs, so there is nothing for ServerOS to show here."
            )
            return
        }
        if source == .journal && !session.capabilities.journal {
            state = .unavailable(
                subsystem: "The system journal",
                reason: "\(session.name) doesn't run systemd-journald. Read a log file instead."
            )
            return
        }
        if showsLoading, state.value == nil { state = .loading }

        let current = query
        let trimmedFilter = current.filter.trimmingCharacters(in: .whitespaces)
        let serverFilter = trimmedFilter.isEmpty ? nil : trimmedFilter

        do {
            let batch: LogBatch
            if current.source == .journal {
                batch = try await api.journal(
                    unit: current.unit.isEmpty ? nil : current.unit,
                    lines: current.lines,
                    since: nil,
                    filter: serverFilter,
                    isRegex: current.isRegex
                )
            } else {
                batch = try await api.fileLog(
                    path: current.path.isEmpty ? "/var/log/syslog" : current.path,
                    lines: current.lines,
                    since: nil,
                    filter: serverFilter,
                    isRegex: current.isRegex
                )
            }

            // A response for a query the user has since changed is worse than no
            // response: it would show lines the current controls do not describe.
            guard current == query else { return }

            var lines = batch.lines
            var truncated = batch.truncated ?? false
            if lines.count > LogsSection.retainedLineLimit {
                lines = Array(lines.suffix(LogsSection.retainedLineLimit))
                truncated = true
            }
            wasTruncated = truncated

            let built = lines.enumerated().map { LogRow(id: $0.offset, line: $0.element) }
            state = built.isEmpty ? .empty : .loaded(built)
            revision += 1
        } catch let error as ServerOSError {
            guard current == query else { return }
            if error.code == "subsystem_unavailable" {
                state = .unavailable(subsystem: "Logs", reason: error.headline)
            } else if showsLoading || state.value == nil {
                state = .failed(error)
            }
        } catch {
            guard current == query else { return }
            if showsLoading || state.value == nil {
                state = .failed(ServerOSError.transport(error, serverName: session.name))
            }
        }
    }

    // MARK: - Export

    private var plainText: String {
        rows.map { row in
            "\(Formatting.logTime(unixSeconds: row.line.timestamp))  \(row.levelLabel.padding(toLength: 5, withPad: " ", startingAt: 0))  \(row.line.message)"
        }
        .joined(separator: "\n")
    }

    private var suggestedFilename: String {
        let subject: String
        if source == .journal {
            subject = unit.isEmpty ? "journal" : unit.replacingOccurrences(of: ".", with: "-")
        } else {
            subject = (path.split(separator: "/").last.map(String.init) ?? "log")
        }
        return "\(session.name.replacingOccurrences(of: " ", with: "-"))-\(subject).log"
    }

    private func copyAll() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(plainText, forType: .string)
    }
}

// MARK: - Source

/// Where the lines come from.
///
/// File-scoped, like every other helper in this file: sibling screens are being
/// written alongside this one and none of these types carry a decision worth
/// sharing across them.
private enum LogSource: String, CaseIterable, Hashable, Sendable {
    case journal
    case file

    var title: String {
        switch self {
        case .journal: return "System Journal"
        case .file: return "File"
        }
    }
}

// MARK: - One line

/// A log line with a stable identity.
///
/// `LogLine.id` is derived from its timestamp and message, so two identical
/// lines logged in the same second collide — which `ForEach` renders as a
/// flickering, half-missing list. Position is the only honest identity a log
/// line has.
private struct LogRow: Identifiable, Equatable {
    let id: Int
    let line: LogLine

    var levelLabel: String {
        if let level = line.level, !level.isEmpty { return level.uppercased() }
        return line.stream == "stderr" ? "ERR" : "LOG"
    }

    var tint: Color {
        if line.isError { return Palette.critical }
        if line.isWarning { return Palette.warning }
        if line.level == "debug" || line.level == "trace" { return Palette.inactive }
        return Palette.informational
    }

    /// Errors and warnings get a visible edge; everything else does not, so the
    /// marker's presence is itself a signal rather than decoration.
    var showsEdgeMarker: Bool { line.isError || line.isWarning }
}

/// One monospaced row: edge marker, time gutter, level chip, message.
private struct LogLineRow: View {
    let row: LogRow

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.element) {
            Rectangle()
                .fill(row.showsEdgeMarker ? row.tint : Color.clear)
                .frame(width: 3)
                .accessibilityHidden(true)

            Text(Formatting.logTime(unixSeconds: row.line.timestamp))
                .font(Typography.codeSmall)
                .foregroundStyle(Palette.textMuted)
                .frame(width: 66, alignment: .leading)

            // The word, not only the colour — and a fixed slot, so the message
            // column stays aligned however long the level happens to be.
            Chip(row.levelLabel, tint: row.tint)
                .frame(width: 62, alignment: .leading)

            Text(row.line.message)
                .font(Typography.code)
                .foregroundStyle(row.line.isError ? Palette.critical : Palette.textPrimary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.trailing, Spacing.card)
        .padding(.vertical, 1)
        .background(row.showsEdgeMarker ? row.tint.opacity(0.06) : Color.clear)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(row.levelLabel) at \(Formatting.logTime(unixSeconds: row.line.timestamp))")
        .accessibilityValue(row.line.message)
    }
}

// MARK: - Scroll position

/// How far the bottom of the content sits below the bottom of the viewport.
///
/// Zero means the reader is at the end and auto-scroll is welcome; anything
/// larger means they have scrolled up to read something and must not be yanked
/// away from it.
private struct LogBottomDistanceKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

// MARK: - Export document

/// The saved form of what is on screen: plain text, exactly as displayed.
private struct LogTextDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.plainText] }

    let text: String

    init(text: String) { self.text = text }

    init(configuration: ReadConfiguration) throws {
        if let data = configuration.file.regularFileContents {
            text = String(decoding: data, as: UTF8.self)
        } else {
            text = ""
        }
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: Data(text.utf8))
    }
}

// MARK: - Preview

private struct LogsPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        LogsSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 980, height: 620)
            .onAppear { session.connect() }
    }
}

#Preview("Logs") {
    LogsPreviewHost()
}
