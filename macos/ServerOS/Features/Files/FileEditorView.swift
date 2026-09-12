//  FileEditorView.swift
//  ServerOS
//
//  Editing a text file on a server you cannot see.
//
//  This is the most dangerous sheet in the application. Everything else in
//  ServerOS asks the agent to change a state — start this, restart that — and
//  the worst outcome is that it does not happen. Here the user is handing over
//  the *contents* of a file on a production machine, and the failure modes are
//  quiet: an nginx config saved half-empty, an environment file whose last
//  fifty lines vanished. So three guards come before any of the polish:
//
//  1. **Truncation closes the door.** `TextFileContents.truncated` means the
//     agent gave us the beginning of the file and nothing else. Saving that
//     back would destroy the rest. Editing is therefore impossible, not
//     discouraged, and the sheet says exactly why in a sentence about the file
//     rather than a sentence about the app.
//  2. **Read-only is stated, not implied.** `readonly` from the agent, or a
//     `FileEntry` the account cannot write, disables the editor with the
//     reason attached — before the user has typed for ten minutes.
//  3. **A failed save keeps the text.** The sheet stays open with the edits
//     intact and the failure explained inline. Losing someone's work because
//     the tunnel dropped is not an acceptable way to report that the tunnel
//     dropped.
//
//  The line-number gutter is deliberately the simple version: one `Text` of
//  numbers beside a `TextEditor` whose height is derived from the line count,
//  both inside a single `ScrollView`. It is accurate for ordinary source and
//  configuration files and drifts on very long soft-wrapped lines. A real
//  gutter needs an `NSTextView` with a ruler, which is a much larger piece of
//  machinery than this sheet has earned.

import AppKit
import Combine
import SwiftUI

/// A sheet for reading and editing one text file on a server.
struct FileEditorView: View {

    /// Matches the monospaced 12pt body text closely enough that the gutter
    /// lines up with the editor's rows on unwrapped lines.
    private static let lineHeight: CGFloat = 15
    /// `TextEditor` insets its text; the gutter is nudged by the same amount so
    /// line 1 sits beside line 1.
    private static let editorTopInset: CGFloat = 6

    let path: String
    let displayName: String
    let serverName: String
    /// What the directory listing said about writability, which is known before
    /// the file is read. `nil` means the agent did not say.
    let isWritable: Bool?
    let api: any AgentAPI
    /// Called after a successful save, so the browser can re-read the folder
    /// and show the new size and timestamp.
    let onSaved: () -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var contents: TextFileContents?
    @State private var loadError: ServerOSError?
    @State private var isLoading = true

    @State private var text = ""
    @State private var originalText = ""
    @State private var isSaving = false
    @State private var saveError: ServerOSError?
    @State private var isConfirmingClose = false

    @State private var caretLine = 1
    @State private var caretColumn = 1

    init(
        path: String,
        displayName: String,
        serverName: String,
        isWritable: Bool? = nil,
        api: any AgentAPI,
        onSaved: @escaping () -> Void
    ) {
        self.path = path
        self.displayName = displayName
        self.serverName = serverName
        self.isWritable = isWritable
        self.api = api
        self.onSaved = onSaved
    }

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider().overlay(Palette.divider)
            warnings
            editorArea
            failureArea
            Divider().overlay(Palette.divider)
            footer
        }
        .frame(width: 900, height: 640)
        .background(Palette.background)
        .task { await load() }
        // An accidental Escape must not throw away twenty minutes of editing,
        // so the sheet refuses to dismiss itself while there are changes and
        // routes the key through the same guard as the Cancel button.
        .interactiveDismissDisabled(hasChanges)
        .onExitCommand { attemptClose() }
        .onReceive(NotificationCenter.default.publisher(for: NSTextView.didChangeSelectionNotification)) { note in
            updateCaret(from: note)
        }
        // Three outcomes, so this cannot be `confirmDestructive`, which is a
        // two-button confirmation. Discard still carries the destructive role.
        .confirmationDialog(
            "Save your changes to \(displayName)?",
            isPresented: $isConfirmingClose,
            titleVisibility: .visible
        ) {
            Button("Save") { save(thenClose: true) }
            Button("Discard Changes", role: .destructive) { dismiss() }
            Button("Keep Editing", role: .cancel) {}
        } message: {
            Text("\(displayName) on \(serverName) still has the version you opened. Discarding loses what you have typed here.")
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .top, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                HStack(spacing: Spacing.element) {
                    Text(displayName)
                        .font(Typography.pageTitle)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                        .accessibilityAddTraits(.isHeader)

                    if isReadOnly {
                        Chip("Read only", tint: Palette.warning, systemImage: "lock")
                    }
                    if hasChanges {
                        Chip("Edited", tint: Palette.accent, systemImage: "pencil")
                    }
                }

                Text(path)
                    .font(Typography.codeSmall)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)

                Text(factsLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
            }

            Spacer(minLength: Spacing.group)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    /// Size · lines · encoding — the facts that decide whether what is on
    /// screen is the whole file.
    private var factsLine: String {
        guard let contents else { return "Reading from \(serverName)…" }
        var parts: [String] = []
        parts.append(Formatting.bytes(contents.sizeBytes))
        parts.append("\(Formatting.count(contents.lineCount)) line\(contents.lineCount == 1 ? "" : "s")")
        parts.append(contents.encoding.uppercased())
        if let ending = contents.lineEnding {
            parts.append(FileEditorView.describe(lineEnding: ending))
        }
        return parts.joined(separator: "  ·  ")
    }

    // MARK: - Warnings

    @ViewBuilder
    private var warnings: some View {
        VStack(spacing: Spacing.element) {
            if let contents, contents.truncated {
                // The data-loss trap, closed. Never phrase this as a limitation
                // of the editor: the user needs to understand that the file on
                // the server is longer than what they are looking at.
                InlineBanner(
                    .warning,
                    "This file is too large for ServerOS to open completely, so you are seeing the first "
                        + "\(Formatting.count(contents.lineCount)) lines of it. Saving from here would replace the whole file with just this much of it, "
                        + "so editing is switched off. Open it over the terminal to change it."
                )
            } else if isReadOnly {
                InlineBanner(.info, readOnlyReason)
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.top, showsWarning ? Spacing.group : 0)
    }

    private var showsWarning: Bool { isTruncated || isReadOnly }

    private var readOnlyReason: String {
        if agentSaysReadOnly {
            return "The agent opened \(displayName) read-only, so ServerOS won't try to save over it. You can read it and copy from it."
        }
        return "This account can't write to \(displayName) on \(serverName), so ServerOS won't try to save over it."
    }

    // MARK: - Editor

    @ViewBuilder
    private var editorArea: some View {
        if isLoading {
            VStack(spacing: Spacing.group) {
                InlineProgress("Reading \(displayName) from \(serverName)…")
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        } else if let loadError {
            ErrorState(error: loadError) {
                Task { await load() }
            }
        } else {
            editor
        }
    }

    private var editor: some View {
        ScrollView([.vertical, .horizontal]) {
            HStack(alignment: .top, spacing: Spacing.element) {
                Text(gutterText)
                    .font(Typography.code)
                    .monospacedDigit()
                    .foregroundStyle(Palette.textMuted)
                    .multilineTextAlignment(.trailing)
                    .frame(width: gutterWidth, alignment: .trailing)
                    .padding(.top, FileEditorView.editorTopInset)
                    .accessibilityHidden(true)

                TextEditor(text: $text)
                    .font(Typography.code)
                    .foregroundStyle(Palette.textPrimary)
                    .scrollContentBackground(.hidden)
                    .scrollDisabled(true)
                    .disabled(!isEditable)
                    .frame(minWidth: 640, minHeight: editorHeight, alignment: .topLeading)
                    .accessibilityLabel("Contents of \(displayName)")
            }
            .padding(.horizontal, Spacing.card)
            .padding(.vertical, Spacing.element)
        }
        .background(Palette.surface)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    /// One `Text` rather than a row per line: a ten-thousand-line file would
    /// otherwise be ten thousand views for decoration.
    private var gutterText: String {
        let count = max(lineCount, 1)
        return (1...count).map { "\($0)" }.joined(separator: "\n")
    }

    private var gutterWidth: CGFloat {
        let digits = max(2, String(max(lineCount, 1)).count)
        return CGFloat(digits) * 8 + 6
    }

    private var lineCount: Int {
        text.split(separator: "\n", omittingEmptySubsequences: false).count
    }

    private var editorHeight: CGFloat {
        CGFloat(max(lineCount, 1)) * FileEditorView.lineHeight + FileEditorView.editorTopInset * 2
    }

    // MARK: - Failure

    @ViewBuilder
    private var failureArea: some View {
        if let saveError {
            // Bounded: the sheet must still show the text underneath, because
            // that text is the thing at risk.
            ErrorState(error: saveError) { save(thenClose: false) }
                .frame(maxHeight: 200)
                .padding(.horizontal, Spacing.screen)
        }
    }

    // MARK: - Footer

    private var footer: some View {
        HStack(spacing: Spacing.group) {
            Text(positionLabel)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
                .monospacedDigit()
                .accessibilityLabel("Cursor position")
                .accessibilityValue(positionLabel)

            if let contents, let ending = contents.lineEnding {
                Chip(FileEditorView.describe(lineEnding: ending), tint: Palette.inactive)
            }

            if isSaving {
                InlineProgress("Saving to \(serverName)…")
            }

            Spacer(minLength: Spacing.group)

            Button("Cancel") { attemptClose() }
                .buttonStyle(.secondary)
                .keyboardShortcut("w", modifiers: .command)

            Button("Save") { save(thenClose: true) }
                .buttonStyle(.primary)
                .disabled(!canSave)
                .keyboardShortcut("s", modifiers: .command)
                .help(saveHelp)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    private var positionLabel: String {
        "Line \(caretLine), Column \(caretColumn)  ·  \(Formatting.count(lineCount)) lines"
    }

    private var saveHelp: String {
        if !isEditable { return "This file can't be saved from ServerOS." }
        if !hasChanges { return "Nothing has changed yet." }
        return "Write these contents to \(path) on \(serverName)"
    }

    // MARK: - State

    private var isTruncated: Bool { contents?.truncated ?? false }

    /// Unwrapped in two steps: `contents` is optional and so is its `readonly`,
    /// and a nested-optional comparison is the kind of expression that reads
    /// wrong even when it is right.
    private var agentSaysReadOnly: Bool {
        guard let contents else { return false }
        return contents.readonly ?? false
    }

    /// Two independent signals, either of which is enough: the agent's own
    /// `readonly` flag, and what the directory listing said about this
    /// account's write permission.
    private var isReadOnly: Bool {
        if isWritable == false { return true }
        return agentSaysReadOnly
    }

    private var isEditable: Bool {
        contents != nil && !isTruncated && !isReadOnly
    }

    private var hasChanges: Bool { isEditable && text != originalText }

    private var canSave: Bool { hasChanges && !isSaving }

    // MARK: - Loading and saving

    private func load() async {
        isLoading = true
        loadError = nil
        do {
            let loaded = try await api.readTextFile(path: path)
            contents = loaded
            text = loaded.content
            originalText = loaded.content
            caretLine = 1
            caretColumn = 1
        } catch let error as ServerOSError {
            loadError = error
        } catch {
            loadError = ServerOSError.transport(error, serverName: serverName)
        }
        isLoading = false
    }

    private func save(thenClose: Bool) {
        guard canSave else { return }
        isSaving = true
        saveError = nil
        let body = text

        Task {
            do {
                _ = try await api.writeTextFile(path: path, contents: body)
                originalText = body
                isSaving = false
                onSaved()
                if thenClose { dismiss() }
            } catch let error as ServerOSError {
                // The sheet stays open and `text` is untouched: the user's work
                // is the one thing a failed save must not cost them.
                saveError = error
                isSaving = false
            } catch {
                saveError = ServerOSError.transport(error, serverName: serverName)
                isSaving = false
            }
        }
    }

    private func attemptClose() {
        if hasChanges {
            isConfirmingClose = true
        } else {
            dismiss()
        }
    }

    // MARK: - Caret

    /// `TextEditor` on macOS 14 exposes no selection binding — `TextSelection`
    /// arrived a release later — so the position comes from the AppKit text
    /// view underneath it, which posts this notification as the caret moves.
    /// Everything is read from the text view itself rather than from our
    /// binding, so the two can never disagree; if the notification never
    /// arrives the indicator simply stays where it started.
    private func updateCaret(from note: Notification) {
        guard let textView = note.object as? NSTextView else { return }
        // `selectedRanges` rather than `selectedRange`, which AppKit exposes to
        // Swift as a property on `NSText` and as an accessor on `NSTextView`
        // depending on the SDK. The array is unambiguous in both.
        guard let range = textView.selectedRanges.first?.rangeValue else { return }

        let string = textView.string as NSString
        let location = min(max(range.location, 0), string.length)
        // UTF-16 offsets from AppKit, counted as characters for display: the
        // column can be off by one on an emoji, which is an acceptable price
        // for not re-implementing text indexing here.
        let lines = string.substring(to: location).components(separatedBy: "\n")
        caretLine = lines.count
        caretColumn = (lines.last?.count ?? 0) + 1
    }

    // MARK: - Words

    /// The agent reports `lf`, `crlf` or `cr`. Nobody wants to see "lf".
    private static func describe(lineEnding: String) -> String {
        switch lineEnding.lowercased() {
        case "lf": return "Unix (LF)"
        case "crlf": return "Windows (CRLF)"
        case "cr": return "Classic Mac (CR)"
        case "mixed": return "Mixed line endings"
        default: return lineEnding.uppercased()
        }
    }
}

// MARK: - Preview

private struct FileEditorPreviewHost: View {
    @State private var isPresented = true

    private let client = DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
        ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])

    var body: some View {
        Color.clear
            .frame(width: 900, height: 640)
            .sheet(isPresented: $isPresented) {
                FileEditorView(
                    path: "/etc/nginx/nginx.conf",
                    displayName: "nginx.conf",
                    serverName: "Demo Production",
                    isWritable: true,
                    api: client
                ) {}
            }
    }
}

#Preview("File editor") {
    FileEditorPreviewHost()
}
