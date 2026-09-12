//  TerminalSection.swift
//  ServerOS
//
//  The escape hatch, and it is deliberately shaped like one.
//
//  ──────────────────────────────────────────────────────────────────────────
//  The brief is unambiguous: the terminal is not this product's identity. It is
//  here for the ten percent ServerOS does not model yet, and for the reassurance
//  of knowing you can always drop a level — the same reason a good abstraction
//  still lets you reach underneath it. So the screen opens closed: an explainer,
//  one button, and a plain statement of what you give up by using it.
//
//  It is also honestly limited. This is NOT a VT100 emulator. It decodes UTF-8,
//  honours carriage return, newline, backspace and tab, and strips ANSI escape
//  sequences it does not implement. Full-screen programs — vim, htop, less, tmux
//  — drive the cursor around the screen with sequences this parser throws away,
//  and they will not render correctly. Writing half an emulator that renders
//  `htop` almost right would be worse than saying so: the UI says it, and so
//  does this comment.
//  ──────────────────────────────────────────────────────────────────────────

import AppKit
import Observation
import SwiftUI

/// An interactive shell on the server, for the things ServerOS cannot do yet.
public struct TerminalSection: View {

    @Environment(AppModel.self) private var model
    @Environment(\.colorScheme) private var scheme

    private let session: ServerSession
    private let navigation: NavigationModel

    @State private var phase: TerminalPhase = .closed
    @State private var buffer = TerminalBuffer()
    @State private var terminal: TerminalSession?
    @State private var outputTask: Task<Void, Never>?
    @State private var input = ""
    @State private var columns = 80
    @State private var rows = 24
    @FocusState private var isInputFocused: Bool

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            switch phase {
            case .closed:
                explainer
            case .connecting:
                connecting
            case .connected, .ended:
                console
            case .failed(let error):
                ErrorState(error: error) { open() }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        // A shell left running behind a screen nobody is looking at is a
        // resource leak on someone else's machine.
        .onDisappear { close() }
    }

    // MARK: - Before connecting

    /// Calm, deliberate, and honest about the trade. The point is that reaching
    /// for this should feel like a decision rather than a shortcut.
    private var explainer: some View {
        VStack(alignment: .leading, spacing: Spacing.card) {
            VStack(alignment: .leading, spacing: Spacing.snug) {
                Text("Terminal")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)

                Text("A shell on \(session.name), for the things ServerOS doesn't do yet.")
                    .font(Typography.body)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            VStack(alignment: .leading, spacing: Spacing.group) {
                point(
                    "arrow.triangle.branch",
                    "Prefer the graphical equivalent where there is one.",
                    "Restarting a container, editing a file, adding a user and reading a log all have screens in ServerOS. Those screens ask the agent to do one specific thing, which is safer than typing it."
                )
                point(
                    "eye.slash",
                    "Work done here isn't recorded in Activity.",
                    "ServerOS audits the operations it performs. Commands you type in a shell bypass that entirely — this app has no idea what they did."
                )
                point(
                    "exclamationmark.triangle",
                    "This is a simple terminal, not a full one.",
                    "Line-based commands work well. Full-screen programs like vim, htop and less won't render correctly — use ssh directly for those."
                )
            }
            .padding(Spacing.card)
            .frame(maxWidth: .infinity, alignment: .leading)
            .cardSurface(scheme: scheme)

            Button("Open Terminal Session") { open() }
                .buttonStyle(.primary)
                .disabled(!canOpen)

            if let reason = unavailableReason {
                InlineBanner(.info, reason)
            }

            Spacer(minLength: 0)
        }
        .readableWidth(720)
        .screenPadding()
    }

    private func point(_ symbol: String, _ title: String, _ detail: String) -> some View {
        HStack(alignment: .top, spacing: Spacing.group) {
            Image(systemName: symbol)
                .font(.system(size: 13))
                .foregroundStyle(Palette.textSecondary)
                .frame(width: 20)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(title)
                    .font(Typography.body.weight(.medium))
                    .foregroundStyle(Palette.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(detail)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// Why the button is disabled, said plainly rather than left to be guessed.
    private var unavailableReason: String? {
        if session.isDemo {
            return "Demo servers don't exist, so there is nothing to open a shell on. Connect a real server to use the terminal."
        }
        if !session.phase.isReady {
            return "ServerOS needs a live connection to \(session.name) before it can open a shell. Reconnect from the menu at the top of this screen."
        }
        return nil
    }

    private var canOpen: Bool { unavailableReason == nil }

    private var connecting: some View {
        VStack(spacing: Spacing.group) {
            ProgressView().controlSize(.large)
            Text("Opening a shell on \(session.name)…")
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.textPrimary)
            Text("ServerOS is reusing this server's existing SSH connection.")
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
        }
        .padding(Spacing.generous)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - The console

    private var console: some View {
        VStack(spacing: 0) {
            consoleToolbar
            Divider().overlay(Palette.divider)
            output
            Divider().overlay(Palette.divider)
            inputBar
            footer
        }
    }

    private var consoleToolbar: some View {
        HStack(spacing: Spacing.element) {
            Text(session.summary.describedEndpoint)
                .font(Typography.code)
                .foregroundStyle(Palette.textSecondary)
                .lineLimit(1)
                .truncationMode(.middle)

            if case .ended = phase {
                Chip(exitLabel, tint: Palette.inactive, systemImage: "stop.fill")
            } else {
                Chip("Connected", tint: Palette.healthy, systemImage: "circle.fill")
            }

            Spacer(minLength: Spacing.element)

            Text("\(columns)×\(rows)")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .monospacedDigit()
                .accessibilityLabel("Terminal size")
                .accessibilityValue("\(columns) columns by \(rows) rows")

            Button("Interrupt") { sendBytes([0x03]) }
                .buttonStyle(.secondary)
                .disabled(!isLive)
                .help("Send Control-C to whatever is running.")

            Button("Copy All", action: copyAll)
                .buttonStyle(.secondary)

            Button(isLive ? "Close" : "Done") { close() }
                .buttonStyle(.secondary)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.element)
    }

    private var exitLabel: String {
        if let status = buffer.exitStatus {
            return status == 0 ? "Shell exited" : "Shell exited with status \(status)"
        }
        return "Shell closed"
    }

    private var output: some View {
        GeometryReader { geo in
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 0) {
                        ForEach(buffer.lines) { line in
                            Text(line.text.isEmpty ? " " : line.text)
                                .font(Typography.code)
                                .foregroundStyle(Palette.textPrimary)
                                .textSelection(.enabled)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .id(line.id)
                        }
                    }
                    .padding(.horizontal, Spacing.group)
                    .padding(.vertical, Spacing.element)
                    .frame(maxWidth: .infinity, alignment: .leading)
                }
                .onChange(of: buffer.revision) { _, _ in
                    // A terminal always follows its output; there is no "read
                    // back" mode to protect, because there is no filter, no
                    // paging and nothing to lose your place in.
                    if let last = buffer.lines.last {
                        proxy.scrollTo(last.id, anchor: .bottom)
                    }
                }
                .onAppear { applySize(geo.size) }
                .onChange(of: geo.size) { _, newSize in applySize(newSize) }
            }
        }
        .background(Palette.surfaceElevated)
        .accessibilityLabel("Terminal output")
    }

    private var inputBar: some View {
        HStack(spacing: Spacing.element) {
            Text("›")
                .font(Typography.code)
                .foregroundStyle(Palette.accent)
                .accessibilityHidden(true)

            TextField("Type a command and press Return", text: $input)
                .textFieldStyle(.plain)
                .font(Typography.code)
                .focused($isInputFocused)
                .disabled(!isLive)
                .onSubmit(submit)
                .accessibilityLabel("Command")

            Button("Send", action: submit)
                .buttonStyle(.secondary)
                .disabled(!isLive || input.isEmpty)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.element)
        .background(Palette.surface)
        .onAppear { isInputFocused = true }
    }

    private var footer: some View {
        Text("This is a simple terminal: it understands plain output, but not full-screen programs. vim, htop, less and tmux won't draw correctly here — run those over ssh directly.")
            .font(Typography.metadata)
            .foregroundStyle(Palette.textMuted)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, Spacing.screen)
            .padding(.vertical, Spacing.element)
            .background(Palette.background)
    }

    private var isLive: Bool {
        if case .connected = phase { return true }
        return false
    }

    // MARK: - Session lifecycle

    private func open() {
        guard canOpen else { return }
        phase = .connecting
        buffer.reset()

        Task {
            // Reuse this server's existing SSH connection rather than opening a
            // second one: the tunnel is already authenticated and already
            // counted against the server's session limits.
            guard let tunnel = model.tunnel(for: session.id),
                  let client = await tunnel.sshClient() else {
                phase = .failed(ServerOSError.sshNotConnected)
                return
            }

            do {
                let opened = try await client.openTerminal(
                    term: "xterm-256color",
                    columns: columns,
                    rows: rows
                )
                terminal = opened
                phase = .connected
                isInputFocused = true

                outputTask = Task {
                    for await chunk in opened.output {
                        buffer.feed(chunk)
                    }
                    // The stream finishing means the shell ended — either the
                    // user typed `exit` or the channel dropped.
                    if case .connected = phase { phase = .ended }
                }
            } catch let error as ServerOSError {
                phase = .failed(error)
            } catch {
                phase = .failed(ServerOSError.sshFailed(
                    "The server wouldn't open a terminal session.",
                    technical: "\(error)"
                ))
            }
        }
    }

    private func close() {
        outputTask?.cancel()
        outputTask = nil
        let closing = terminal
        terminal = nil
        input = ""
        phase = .closed
        Task { await closing?.close() }
    }

    private func submit() {
        guard isLive, !input.isEmpty else { return }
        let line = input
        input = ""
        sendBytes(Array((line + "\n").utf8))
    }

    private func sendBytes(_ bytes: [UInt8]) {
        guard let terminal else { return }
        Task {
            // A keystroke that fails to send means the channel has gone; the
            // output stream finishing will report that in its own right.
            try? await terminal.send(Data(bytes))
        }
    }

    private func copyAll() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(buffer.plainText, forType: .string)
    }

    /// Estimate the character grid from the measured view and the font's own
    /// advance. It is an estimate — SwiftUI will not tell us its glyph metrics —
    /// but for a monospaced face the cell width is exact enough that `ls` lines
    /// up in columns, which is the whole point of telling the server at all.
    private func applySize(_ size: CGSize) {
        let horizontalPadding = Spacing.group * 2
        let verticalPadding = Spacing.element * 2
        let usableWidth = max(size.width - horizontalPadding, TerminalMetrics.advance)
        let usableHeight = max(size.height - verticalPadding, TerminalMetrics.lineHeight)

        let newColumns = max(20, Int(usableWidth / TerminalMetrics.advance))
        let newRows = max(5, Int(usableHeight / TerminalMetrics.lineHeight))
        guard newColumns != columns || newRows != rows else { return }

        columns = newColumns
        rows = newRows
        guard let terminal else { return }
        Task { await terminal.resize(columns: newColumns, rows: newRows) }
    }
}

// MARK: - Phase

/// Where the shell has got to. One value rather than three booleans, so
/// "connected and failed" cannot be expressed.
private enum TerminalPhase {
    case closed
    case connecting
    case connected
    /// The shell exited or the channel dropped. Output stays on screen.
    case ended
    case failed(ServerOSError)
}

// MARK: - Font metrics

/// The cell size of the monospaced face the console draws with.
///
/// `Typography.code` is a 12pt monospaced system font; this is its AppKit twin,
/// used only for measurement.
private enum TerminalMetrics {
    static let font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
    static let advance: CGFloat = max(TerminalMetrics.font.maximumAdvancement.width, 1)
    static let lineHeight: CGFloat = max(
        TerminalMetrics.font.ascender - TerminalMetrics.font.descender + TerminalMetrics.font.leading,
        1
    )
}

// MARK: - Buffer

/// One line of terminal output, with an identity that survives trimming.
private struct TerminalLine: Identifiable, Equatable {
    let id: Int
    var text: String
}

/// What the shell has printed, after parsing.
///
/// An object rather than view state because the parser has to carry position
/// across chunks — a carriage return in one packet overwrites text delivered in
/// the last one, and a UTF-8 character can be split down the middle by TCP.
@MainActor
@Observable
private final class TerminalBuffer {

    /// Scrollback. A window left open on a chatty process must not grow without
    /// bound; this is generous enough that nothing useful is lost in practice.
    private static let maxLines = 2_000

    private(set) var lines: [TerminalLine] = []
    /// Bumped whenever anything arrives, so the view can follow the output
    /// without diffing two thousand strings to find out that it should.
    private(set) var revision = 0
    /// Parsed out of the `[exited N]` line the SSH layer appends when the remote
    /// shell reports its exit status.
    private(set) var exitStatus: Int?

    private var parser = ANSIStream()
    private var nextID = 0

    func reset() {
        parser = ANSIStream()
        lines = []
        exitStatus = nil
        nextID = 0
        revision &+= 1
    }

    func feed(_ data: Data) {
        let result = parser.consume(data)

        for completed in result.completedLines {
            appendCompleted(completed)
        }

        // The line still being typed into is shown live, replacing itself each
        // time rather than accumulating — that is what makes a prompt, a
        // progress bar and a `\r` redraw all behave.
        if let inProgress = result.currentLine {
            if let last = lines.last, last.id == nextID {
                lines[lines.count - 1].text = inProgress
            } else {
                lines.append(TerminalLine(id: nextID, text: inProgress))
            }
        }

        trim()
        revision &+= 1
    }

    private func appendCompleted(_ text: String) {
        if let last = lines.last, last.id == nextID {
            lines[lines.count - 1].text = text
        } else {
            lines.append(TerminalLine(id: nextID, text: text))
        }
        if let status = TerminalBuffer.parseExitStatus(in: text) {
            exitStatus = status
        }
        nextID += 1
    }

    private func trim() {
        guard lines.count > TerminalBuffer.maxLines else { return }
        lines.removeFirst(lines.count - TerminalBuffer.maxLines)
    }

    var plainText: String {
        lines.map(\.text).joined(separator: "\n")
    }

    /// `[exited 0]`, written by `TerminalChannelHandler` when the remote shell
    /// reports its status. Parsed rather than plumbed through because the SSH
    /// layer delivers it in-band, as a terminal does.
    static func parseExitStatus(in line: String) -> Int? {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("[exited "), trimmed.hasSuffix("]") else { return nil }
        let digits = trimmed.dropFirst("[exited ".count).dropLast()
        return Int(digits)
    }
}

// MARK: - The parser

/// A deliberately small terminal parser.
///
/// It handles what line-based output actually uses — UTF-8, `\r`, `\n`, `\b`,
/// `\t`, and erase-in-line — and discards every other escape sequence rather
/// than half-implementing it. See the file comment: full-screen programs will
/// not render correctly, and the UI says so.
private struct ANSIStream {

    struct Output {
        /// Lines finished during this chunk, in order.
        var completedLines: [String] = []
        /// The line currently being written into, if any.
        var currentLine: String?
    }

    private enum Mode {
        case text
        /// Saw ESC; waiting to find out what kind of sequence this is.
        case escape
        /// Inside `ESC [ … final`.
        case csi
        /// Inside `ESC ] … BEL` or `ESC ] … ESC \` — window titles, mostly.
        case osc
    }

    private var mode: Mode = .text
    private var current: [Character] = []
    private var column = 0
    /// Text bytes not yet decoded. Kept across chunks so a multi-byte character
    /// split by the network is not turned into two replacement characters.
    private var pending: [UInt8] = []
    private var csiParameters: [UInt8] = []
    private var oscSawEscape = false

    /// How many columns a tab advances to. The PTY is opened with default modes,
    /// so this matches the usual terminal behaviour.
    private static let tabWidth = 8

    mutating func consume(_ data: Data) -> Output {
        var output = Output()

        for byte in data {
            switch mode {
            case .text:
                handleText(byte, into: &output)
            case .escape:
                handleEscape(byte)
            case .csi:
                handleCSI(byte)
            case .osc:
                handleOSC(byte)
            }
        }

        // At a chunk boundary an incomplete character is kept for next time;
        // mid-chunk, a control byte forces everything pending out.
        flush(keepingIncompleteTail: true)
        output.currentLine = String(current)
        return output
    }

    // MARK: Bytes

    private mutating func handleText(_ byte: UInt8, into output: inout Output) {
        switch byte {
        case 0x1B: // ESC
            flush(keepingIncompleteTail: false)
            mode = .escape
        case 0x0A, 0x0B, 0x0C: // newline, vertical tab, form feed
            flush(keepingIncompleteTail: false)
            output.completedLines.append(String(current))
            current = []
            column = 0
        case 0x0D: // carriage return — go back to the start and overwrite
            flush(keepingIncompleteTail: false)
            column = 0
        case 0x08: // backspace
            flush(keepingIncompleteTail: false)
            if column > 0 { column -= 1 }
        case 0x09: // tab
            flush(keepingIncompleteTail: false)
            let target = ((column / ANSIStream.tabWidth) + 1) * ANSIStream.tabWidth
            write(String(repeating: " ", count: max(1, target - column)))
        case 0x07: // bell — deliberately silent
            break
        case 0x00...0x06, 0x0E...0x1A, 0x1C...0x1F, 0x7F:
            // Remaining C0 controls and DEL: nothing sensible to draw.
            break
        default:
            pending.append(byte)
        }
    }

    private mutating func handleEscape(_ byte: UInt8) {
        switch byte {
        case 0x5B: // '['
            csiParameters = []
            mode = .csi
        case 0x5D: // ']'
            oscSawEscape = false
            mode = .osc
        default:
            // A two-byte escape we do not implement: charset selection, cursor
            // save, keypad mode. Swallow it and carry on.
            mode = .text
        }
    }

    private mutating func handleCSI(_ byte: UInt8) {
        // Parameters and intermediates run 0x20–0x3F; the final byte is 0x40–0x7E.
        guard byte >= 0x40 && byte <= 0x7E else {
            csiParameters.append(byte)
            return
        }
        applyCSI(final: byte)
        mode = .text
    }

    private mutating func applyCSI(final: UInt8) {
        // Only erase-in-line is implemented, because that is the one sequence a
        // shell prompt genuinely needs: without it, redrawing a prompt leaves
        // the old text behind. Colours (SGR), cursor movement and screen
        // addressing are discarded.
        guard final == 0x4B else { return } // 'K'
        let parameter = Int(String(decoding: csiParameters, as: UTF8.self)) ?? 0
        switch parameter {
        case 1: // to the start of the line
            for index in 0..<min(column, current.count) { current[index] = " " }
        case 2: // the whole line
            current = []
            column = 0
        default: // 0 — to the end of the line
            if column < current.count { current.removeSubrange(column...) }
        }
    }

    private mutating func handleOSC(_ byte: UInt8) {
        if byte == 0x07 { // BEL terminates
            mode = .text
            oscSawEscape = false
            return
        }
        if oscSawEscape {
            // ESC \ — the other terminator.
            mode = byte == 0x5C ? .text : .osc
            oscSawEscape = false
            return
        }
        if byte == 0x1B { oscSawEscape = true }
    }

    // MARK: Text

    private mutating func flush(keepingIncompleteTail: Bool) {
        guard !pending.isEmpty else { return }

        let usable = keepingIncompleteTail ? ANSIStream.completeLength(of: pending) : pending.count
        guard usable > 0 else {
            if !keepingIncompleteTail { pending = [] }
            return
        }

        let decodable = Array(pending[0..<usable])
        pending = Array(pending[usable...])
        write(String(decoding: decodable, as: UTF8.self))
    }

    private mutating func write(_ text: String) {
        for character in text {
            if column < current.count {
                current[column] = character
            } else {
                // Writing past the end can only happen right after an erase, but
                // padding keeps the column and the array honest either way.
                while current.count < column { current.append(" ") }
                current.append(character)
            }
            column += 1
        }
    }

    /// The length of the longest prefix that is whole UTF-8.
    ///
    /// TCP will happily split a three-byte character across two reads; decoding
    /// eagerly turns that into two replacement characters that never heal.
    static func completeLength(of bytes: [UInt8]) -> Int {
        guard !bytes.isEmpty else { return 0 }

        // A continuation byte is 10xxxxxx; walk back to the lead byte.
        var index = bytes.count - 1
        var continuations = 0
        while index >= 0 && bytes[index] & 0b1100_0000 == 0b1000_0000 {
            continuations += 1
            index -= 1
            if continuations > 3 { return bytes.count }
        }
        guard index >= 0 else { return bytes.count }

        let lead = bytes[index]
        let expected: Int
        if lead & 0b1000_0000 == 0 { expected = 1 }
        else if lead & 0b1110_0000 == 0b1100_0000 { expected = 2 }
        else if lead & 0b1111_0000 == 0b1110_0000 { expected = 3 }
        else if lead & 0b1111_1000 == 0b1111_0000 { expected = 4 }
        else { return bytes.count } // Not a lead byte at all; let the decoder cope.

        let have = 1 + continuations
        return have >= expected ? bytes.count : index
    }
}

// MARK: - Preview

private struct TerminalPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()
    @State private var model = AppModel(store: ServerStore(container: ServerStore.emptyContainer()))

    var body: some View {
        TerminalSection(session: session, navigation: navigation)
            .environment(model)
            .background(Palette.background)
            .frame(width: 900, height: 620)
    }
}

#Preview("Terminal") {
    TerminalPreviewHost()
}
