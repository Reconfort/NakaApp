//  ContainerLogsView.swift
//  ServerOS
//
//  `docker logs -f estatify-api`, as a window you can read.
//
//  Three decisions shape this sheet, and the first one is the interesting one:
//
//  * **Filtering happens on this Mac, and that is not an oversight.** The Logs
//    screen sends its filter to the agent, which greps before it sends, because
//    a system journal can be gigabytes. Docker's container-log API has no
//    equivalent: there is no server-side grep, only "give me the last N lines".
//    So the two screens genuinely differ, and this one filters what it already
//    has rather than pretending to a capability the daemon does not offer. The
//    tail size is therefore the real control — it decides how much there is to
//    search — which is why it sits next to the search field rather than in a
//    menu somewhere.
//
//  * **Follow behaves like `tail -f` and like a scroll view at the same time.**
//    It re-reads every two seconds and sticks to the newest line, but the moment
//    you scroll up to read something it stops dragging you away, and offers to
//    take you back when you want to go.
//
//  * **Memory is bounded and honest.** At most 5,000 lines are held. When lines
//    have been dropped the header says so, rather than letting the top of the
//    buffer look like the beginning of time.

import AppKit
import SwiftUI
import UniformTypeIdentifiers

/// One container's output, in a sheet.
struct ContainerLogsView: View {

    /// The most lines this sheet will ever hold. A busy container can emit this
    /// many in a minute, and an unbounded buffer in a window left open is a leak.
    private static let retainedLineLimit = 5_000

    /// How often Follow re-reads.
    private static let followInterval: Duration = .seconds(2)

    /// How close to the end counts as "at the end", in points.
    private static let bottomTolerance: CGFloat = 48

    private static let scrollSpace = "serveros.containerLogs.scroll"
    private static let bottomAnchor = "serveros.containerLogs.bottom"

    let containerID: String
    let containerName: String
    let session: ServerSession

    @Environment(\.dismiss) private var dismiss

    @State private var state: ScreenState<[ContainerLogRow]> = .loading
    @State private var filter = ""
    @State private var tail = 200
    @State private var isFollowing = false
    @State private var wasTruncated = false
    @State private var reloadNonce = 0
    /// Bumped on every successful read, so Follow can tell "the same 200 lines
    /// again" from "200 new lines" and only scroll for the second.
    @State private var revision = 0
    @State private var isPinnedToBottom = true
    @State private var isExporting = false
    /// Built only when the user asks to save. Joining 5,000 lines on every body
    /// evaluation would make scrolling the log cost more than reading it.
    @State private var exportDocument: ContainerLogDocument?

    init(containerID: String, containerName: String, session: ServerSession) {
        self.containerID = containerID
        self.containerName = containerName
        self.session = session
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            controls
            Divider().overlay(Palette.divider)

            StatefulContent(displayState, retry: { reloadNonce += 1 }) { rows in
                logBody(rows)
            } empty: {
                emptyState
            }
        }
        .frame(
            minWidth: 720, idealWidth: 840, maxWidth: .infinity,
            minHeight: 440, idealHeight: 560, maxHeight: .infinity
        )
        .background(Palette.background)
        .task(id: loadKey) { await load(showsLoading: true) }
        .task(id: isFollowing) { await followWhileEnabled() }
        .fileExporter(
            isPresented: $isExporting,
            document: exportDocument,
            contentType: .plainText,
            defaultFilename: suggestedFilename
        ) { _ in
            // Saving and cancelling are both fine, and a failure is reported by
            // the system's own sheet — there is nothing useful to add here.
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Logs — \(containerName)")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .accessibilityAddTraits(.isHeader)
                Text(statusLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
            }

            Spacer(minLength: Spacing.group)

            Button("Copy All", action: copyAll)
                .buttonStyle(.secondary)
                .disabled(visibleRows.isEmpty)

            Button("Save to File…") {
                exportDocument = ContainerLogDocument(text: plainText)
                isExporting = true
            }
            .buttonStyle(.secondary)
            .disabled(visibleRows.isEmpty)

            Button("Done") { dismiss() }
                .buttonStyle(.primary)
                .keyboardShortcut(.defaultAction)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.top, Spacing.group)
        .padding(.bottom, Spacing.element)
    }

    private var statusLine: String {
        var parts: [String] = []
        let shown = visibleRows.count
        parts.append("\(Formatting.count(shown)) line\(shown == 1 ? "" : "s")")
        if !filter.trimmingCharacters(in: .whitespaces).isEmpty {
            parts.append("filtered from \(Formatting.count(allRows.count))")
        }
        if wasTruncated {
            parts.append("older lines dropped past \(Formatting.count(ContainerLogsView.retainedLineLimit))")
        }
        if isFollowing {
            parts.append("Following")
        }
        parts.append(session.name)
        return parts.joined(separator: "  ·  ")
    }

    // MARK: - Controls

    private var controls: some View {
        HStack(spacing: Spacing.element) {
            SearchField(text: $filter, prompt: "Filter lines")

            Text("Docker has no server-side search for container logs, so this filters the lines already read.")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .lineLimit(2)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: 280, alignment: .leading)

            Spacer(minLength: Spacing.element)

            Picker("Lines", selection: $tail) {
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
        .padding(.horizontal, Spacing.screen)
        .padding(.bottom, Spacing.group)
    }

    // MARK: - The log

    private func logBody(_ rows: [ContainerLogRow]) -> some View {
        GeometryReader { outer in
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(rows) { row in
                            ContainerLogLineRow(row: row)
                                .id(row.id)
                        }
                        // A zero-height anchor is a more reliable scroll target
                        // than the last row, which can be taller than the
                        // viewport when a long line wraps.
                        Color.clear
                            .frame(height: 1)
                            .id(ContainerLogsView.bottomAnchor)
                    }
                    .padding(.vertical, Spacing.element)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(
                        GeometryReader { inner in
                            Color.clear.preference(
                                key: ContainerLogBottomKey.self,
                                value: inner.frame(in: .named(ContainerLogsView.scrollSpace)).maxY - outer.size.height
                            )
                        }
                    )
                }
                .coordinateSpace(name: ContainerLogsView.scrollSpace)
                .onPreferenceChange(ContainerLogBottomKey.self) { distance in
                    let pinned = distance <= ContainerLogsView.bottomTolerance
                    if pinned != isPinnedToBottom { isPinnedToBottom = pinned }
                }
                .onChange(of: revision) { _, _ in
                    guard isFollowing, isPinnedToBottom else { return }
                    proxy.scrollTo(ContainerLogsView.bottomAnchor, anchor: .bottom)
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

    private func jumpToLatest(_ proxy: ScrollViewProxy) -> some View {
        Button {
            withAnimation(Motion.appear) {
                proxy.scrollTo(ContainerLogsView.bottomAnchor, anchor: .bottom)
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
        .accessibilityLabel("Jump to the newest line")
    }

    private var emptyState: some View {
        let isFiltered = !filter.trimmingCharacters(in: .whitespaces).isEmpty
        return EmptyState(
            systemImage: isFiltered ? "magnifyingglass" : "text.alignleft",
            title: isFiltered ? "Nothing matches that filter" : "This container hasn't logged anything",
            message: isFiltered
                ? "No line in the last \(Formatting.count(allRows.count)) contains “\(filter)”. Widen the filter, or read more lines."
                : "\(containerName) has written nothing to stdout or stderr since it started. A container that logs to a file inside itself won't appear here — browse to the file in Files instead.",
            actionTitle: isFiltered ? "Clear Filter" : "Reload",
            action: {
                if isFiltered { filter = "" } else { reloadNonce += 1 }
            }
        )
    }

    // MARK: - Rows

    private var allRows: [ContainerLogRow] { state.value ?? [] }

    private var visibleRows: [ContainerLogRow] {
        filtered(allRows)
    }

    private func filtered(_ rows: [ContainerLogRow]) -> [ContainerLogRow] {
        let needle = filter.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return rows }
        return rows.filter { $0.line.message.lowercased().contains(needle) }
    }

    /// The filter is applied here rather than inside `load`, so clearing it
    /// restores every line instantly instead of costing a round trip.
    private var displayState: ScreenState<[ContainerLogRow]> {
        switch state {
        case .loaded(let rows):
            let visible = filtered(rows)
            if visible.isEmpty {
                return ScreenState<[ContainerLogRow]>.empty
            }
            return ScreenState<[ContainerLogRow]>.loaded(visible)
        default:
            return state
        }
    }

    // MARK: - Loading

    private struct LogsLoad: Equatable {
        let containerID: String
        let tail: Int
        let nonce: Int
        let isReady: Bool
    }

    private var loadKey: LogsLoad {
        LogsLoad(containerID: containerID, tail: tail, nonce: reloadNonce, isReady: session.phase.isReady)
    }

    private func followWhileEnabled() async {
        guard isFollowing else { return }
        while !Task.isCancelled {
            try? await Task.sleep(for: ContainerLogsView.followInterval)
            if Task.isCancelled { return }
            await load(showsLoading: false)
        }
    }

    /// - Parameter showsLoading: False for the Follow refresh, so a log the user
    ///   is reading never flickers back to a skeleton.
    private func load(showsLoading: Bool) async {
        guard let api = session.api else {
            if showsLoading { state = .loading }
            return
        }
        guard session.capabilities.docker else {
            state = .unavailable(
                subsystem: "Docker",
                reason: "\(session.name) isn't running a Docker daemon that the agent can reach."
            )
            return
        }
        if showsLoading, state.value == nil { state = .loading }

        let requestedTail = tail
        do {
            var lines = try await api.containerLogs(
                id: containerID,
                tail: requestedTail,
                since: nil,
                timestamps: true
            )

            // A response for a tail size the user has since changed would show
            // lines the controls no longer describe.
            guard requestedTail == tail else { return }

            var truncated = false
            if lines.count > ContainerLogsView.retainedLineLimit {
                lines = Array(lines.suffix(ContainerLogsView.retainedLineLimit))
                truncated = true
            }
            wasTruncated = truncated

            // Position is the only honest identity a log line has: two identical
            // lines in the same second share `LogLine.id`, which `ForEach`
            // renders as a flickering, half-missing list.
            let built = lines.enumerated().map { ContainerLogRow(id: $0.offset, line: $0.element) }
            state = built.isEmpty ? .empty : .loaded(built)
            revision += 1
        } catch let error as ServerOSError {
            if showsLoading || state.value == nil { state = .failed(error) }
        } catch {
            if showsLoading || state.value == nil {
                state = .failed(ServerOSError.transport(error, serverName: session.name))
            }
        }
    }

    // MARK: - Export

    /// What is on screen, exactly as it reads — so a filtered view copies the
    /// filtered lines, which is what somebody who just filtered them expects.
    private var plainText: String {
        visibleRows
            .map { "\(Formatting.logTime(unixSeconds: $0.line.timestamp))  \($0.streamTag)  \($0.line.message)" }
            .joined(separator: "\n")
    }

    private var suggestedFilename: String {
        let server = session.name.replacingOccurrences(of: " ", with: "-")
        let container = containerName.replacingOccurrences(of: " ", with: "-")
        return "\(server)-\(container).log"
    }

    private func copyAll() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(plainText, forType: .string)
    }
}

// MARK: - One line

/// A log line with a stable, position-based identity.
private struct ContainerLogRow: Identifiable, Equatable {
    let id: Int
    let line: LogLine

    /// Docker multiplexes stdout and stderr on one connection and tells us
    /// which is which. A crash is almost always on stderr, so this is the
    /// single most useful bit in the whole line.
    var isStandardError: Bool {
        line.stream == "stderr" || line.isError
    }

    var tint: Color {
        if isStandardError { return Palette.critical }
        if line.isWarning { return Palette.warning }
        return Palette.informational
    }

    /// The three-letter tag used in the exported text and read out by VoiceOver.
    var streamTag: String {
        if isStandardError { return "ERR" }
        if line.isWarning { return "WRN" }
        return "OUT"
    }
}

/// Edge marker, time gutter, message.
///
/// The marker matters: tinting stderr red communicates nothing to a reader who
/// cannot distinguish red, and nothing at all on a monochrome display. A 3-point
/// bar down the left of the row is a difference in shape and position, which
/// survives both.
private struct ContainerLogLineRow: View {
    let row: ContainerLogRow

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.element) {
            Rectangle()
                .fill(row.isStandardError || row.line.isWarning ? row.tint : Color.clear)
                .frame(width: 3)
                .accessibilityHidden(true)

            Text(Formatting.logTime(unixSeconds: row.line.timestamp))
                .font(Typography.codeSmall)
                .foregroundStyle(Palette.textMuted)
                .frame(width: 66, alignment: .leading)

            Text(row.line.message)
                .font(Typography.code)
                .foregroundStyle(row.isStandardError ? Palette.critical : Palette.textPrimary)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .padding(.trailing, Spacing.card)
        .padding(.vertical, 1)
        .background(row.isStandardError ? Palette.critical.opacity(0.06) : Color.clear)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(row.streamTag) at \(Formatting.logTime(unixSeconds: row.line.timestamp))")
        .accessibilityValue(row.line.message)
    }
}

// MARK: - Scroll position

/// How far the bottom of the content sits below the bottom of the viewport.
/// Zero means the reader is at the end and auto-scroll is welcome.
private struct ContainerLogBottomKey: PreferenceKey {
    static let defaultValue: CGFloat = 0
    static func reduce(value: inout CGFloat, nextValue: () -> CGFloat) {
        value = nextValue()
    }
}

// MARK: - Export document

/// The saved form of what is on screen: plain text, exactly as displayed.
private struct ContainerLogDocument: FileDocument {
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

private struct ContainerLogsPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var containerID: String?

    var body: some View {
        Group {
            if let containerID {
                ContainerLogsView(
                    containerID: containerID,
                    containerName: "estatify-api",
                    session: session
                )
            } else {
                InlineProgress("Starting the demo server…")
                    .frame(width: 840, height: 560)
            }
        }
        .task {
            session.connect()
            while containerID == nil && !Task.isCancelled {
                try? await Task.sleep(for: .milliseconds(200))
                containerID = session.containers.first?.id
            }
        }
    }
}

#Preview("Container logs") {
    ContainerLogsPreviewHost()
}
