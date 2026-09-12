//  FilesSection.swift
//  ServerOS
//
//  The remote filesystem, as a file manager rather than as a directory listing.
//
//  This is the section where "no CLI required" is hardest to earn. `ls`, `cd`,
//  `mkdir`, `mv`, `chmod`, `rm`, `scp` and `nano` are eight different tools with
//  eight different mental models; here they have to become one surface that a
//  person can trust with a production server. Four decisions carry most of that:
//
//  * **The path bar is the product's navigation, not a label.** A breadcrumb you
//    can click, a path you can type (⌘L), Back/Forward over a local history, and
//    an Up affordance derived from the agent's own `parent`. Somebody who lives
//    in Finder and somebody who lives in a shell should both find what they
//    expect within a second.
//  * **Sorting and filtering are local, and the UI says so.** The agent has no
//    recursive search endpoint and paginates large directories, so the search
//    field filters the entries that are *loaded* and the column sort orders the
//    same set. Implying we searched the server would be a lie that costs the
//    user real time when they believe an empty result.
//  * **Deletion reports what actually happened.** The agent moves things to the
//    server's trash by default and says so in `FileDeletion`. Announcing
//    "deleted forever" when the agent trashed it — or the reverse — is the kind
//    of error that ends trust in an infrastructure tool permanently, so the
//    result is read back and repeated verbatim.
//  * **A refused path is not an error.** `/etc/shadow`, `/etc/serveros`, `/proc`
//    and private keys come back as `code == "denied"`. That is ServerOS working
//    correctly. It gets a calm explanation, not a red triangle and an apology.

import AppKit
import Combine
import SwiftUI
import UniformTypeIdentifiers

/// The file browser for one server.
public struct FilesSection: View {

    /// How many entries we ask for at a time.
    ///
    /// `/usr/bin` on a busy box is several thousand entries and a Docker
    /// overlay directory can be six figures. Five hundred fills the window
    /// several times over, arrives fast over an SSH tunnel, and makes "Load
    /// More" a deliberate act rather than a surprise.
    private static let pageSize = 500

    /// The largest file ServerOS will push through the agent's upload endpoint
    /// in one request. Beyond this the honest answer is "use another tool",
    /// said before the upload stalls rather than after.
    private static let uploadSizeLimit: Int = 100 * 1024 * 1024

    /// A text file small enough to preview in the inspector without making
    /// selecting a row feel expensive.
    private static let previewSizeLimit: Int64 = 256 * 1024

    private let session: ServerSession
    private let navigation: NavigationModel

    // Location
    @State private var path: String = "/"
    @State private var parentPath: String?
    @State private var backStack: [String] = []
    @State private var forwardStack: [String] = []
    @State private var isEditingPath = false
    @State private var pathDraft = ""
    @FocusState private var isPathFieldFocused: Bool

    // Listing
    @State private var state: ScreenState<[FileRow]> = .loading
    @State private var totalEntries: Int?
    @State private var isTruncated = false
    @State private var isLoadingMore = false
    @State private var showHidden = false
    @State private var filterText = ""
    @State private var reloadNonce = 0
    @State private var sortOrder: [KeyPathComparator<FileRow>] =
        [KeyPathComparator(\FileRow.sortName, order: .forward)]

    /// A path ServerOS refuses to read. Held apart from `state` because it is
    /// not a failure and must not render like one.
    @State private var denied: ServerOSError?

    // Selection and inspector
    @State private var selection: Set<String> = []
    @State private var isInspectorPresented = false
    @State private var preview: PreviewLoad = .idle
    /// How many entries a selected directory holds, when we have asked.
    @State private var selectedDirectoryCount: Int?

    // Sheets, banners and confirmations
    @State private var sheet: FilesSheet?
    @State private var notice: Notice?
    @State private var actionError: ServerOSError?
    @State private var isConfirmingDelete = false
    @State private var pendingDeletion: FileRow?

    // Transfers
    @State private var isImportingUploads = false
    @State private var isDropTargeted = false
    @State private var uploads: [UploadJob] = []
    @State private var uploadTask: Task<Void, Never>?
    @State private var isExportingDownload = false
    @State private var download: DownloadPayload?

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            pathBar
            Divider().overlay(Palette.divider)
            banners
            uploadTray
            content
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .background { dropHighlight }
        // Dragging out of Finder is how most people will put a file on a
        // server; the file importer is the same road for anyone who prefers a
        // dialog or a keyboard.
        .dropDestination(for: URL.self) { urls, _ in
            beginUpload(urls: urls)
            return true
        } isTargeted: { targeted in
            withAnimation(Motion.immediate) { isDropTargeted = targeted }
        }
        .inspector(isPresented: $isInspectorPresented) {
            inspectorPane
                .inspectorColumnWidth(min: 260, ideal: 320, max: 420)
        }
        .task(id: ListingRequest(path: path, showHidden: showHidden, nonce: reloadNonce)) {
            await load(showsLoading: true)
        }
        .onAppear(perform: restoreLocation)
        .onChange(of: selection) { _, newValue in
            if !newValue.isEmpty { isInspectorPresented = true }
            preview = .idle
            selectedDirectoryCount = nil
        }
        .onChange(of: session.capabilities) { _, _ in reloadNonce += 1 }
        .onChange(of: session.phase.isReady) { _, isReady in
            if isReady { reloadNonce += 1 }
        }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            Task { await load(showsLoading: false) }
        }
        .fileImporter(
            isPresented: $isImportingUploads,
            allowedContentTypes: [UTType.data],
            allowsMultipleSelection: true
        ) { (result: Result<[URL], Error>) in
            // Explicitly typed: `fileImporter` has single- and multiple-
            // selection overloads and an un-annotated closure can pick either.
            switch result {
            case .success(let urls):
                beginUpload(urls: urls)
            case .failure(let error):
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
        }
        .fileExporter(
            isPresented: $isExportingDownload,
            document: download.map { FileDownloadDocument(data: $0.data) },
            contentType: .data,
            defaultFilename: download?.name ?? "download"
        ) { _ in
            // Saved or cancelled; the system reports its own failures and there
            // is nothing useful ServerOS can add.
            download = nil
        }
        .sheet(item: $sheet) { presented in
            sheetContent(presented)
        }
        .confirmDestructive(
            isPresented: $isConfirmingDelete,
            title: deleteTitle,
            target: pendingDeletion?.name ?? "",
            consequence: deleteConsequence,
            isReversible: false,
            confirmTitle: "Delete"
        ) {
            if let row = pendingDeletion { performDelete(row) }
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Files")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(statusLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
            }

            Spacer(minLength: Spacing.group)

            SearchField(text: $filterText, prompt: "Filter this folder")

            toolbarControls
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    /// One line that says where we are and how complete the answer is.
    private var statusLine: String {
        if denied != nil {
            return "ServerOS doesn't read this location."
        }
        guard let rows = state.value else {
            return "Reading \(path) on \(session.name)…"
        }
        let loaded = rows.count
        if isTruncated, let total = totalEntries, total > loaded {
            return "Showing \(Formatting.count(loaded)) of \(Formatting.count(total)) items in this folder."
        }
        let noun = loaded == 1 ? "item" : "items"
        let hidden = showHidden ? ", hidden items included" : ""
        return "\(Formatting.count(loaded)) \(noun)\(hidden)."
    }

    /// Ternaries are resolved into plain `String`s before they reach `.help` and
    /// `.accessibilityLabel`, both of which are overloaded across
    /// `LocalizedStringKey`, `Text` and `StringProtocol`.
    private var hiddenToggleHelp: String {
        showHidden ? "Hide dot files" : "Show dot files"
    }

    private var pathEditHelp: String {
        isEditingPath ? "Stop typing a path" : "Type a path (⌘L)"
    }

    private var toolbarControls: some View {
        HStack(spacing: Spacing.element) {
            Menu {
                Button("New Folder…") { sheet = .newFolder }
                Button("New Text File…") { sheet = .newFile }
            } label: {
                Image(systemName: "plus")
                    .font(.system(size: 12, weight: .medium))
            }
            .menuStyle(.borderlessButton)
            .menuIndicator(.hidden)
            .frame(width: 26)
            .help("Create a folder or a text file here")
            .accessibilityLabel("Create")

            Button {
                showHidden.toggle()
            } label: {
                Image(systemName: showHidden ? "eye" : "eye.slash")
                    .font(.system(size: 12))
                    .foregroundStyle(showHidden ? Palette.accent : Palette.textSecondary)
            }
            .buttonStyle(.plain)
            .help(hiddenToggleHelp)
            .accessibilityLabel(hiddenToggleHelp)

            Button {
                Task { await load(showsLoading: false) }
            } label: {
                Image(systemName: "arrow.clockwise")
                    .font(.system(size: 12))
                    .foregroundStyle(Palette.textSecondary)
            }
            .buttonStyle(.plain)
            .help("Read this folder again")
            .accessibilityLabel("Refresh")

            // The one primary action on this screen.
            Button("Upload") { isImportingUploads = true }
                .buttonStyle(.primary)
                .disabled(session.api == nil || denied != nil)
                .help("Copy files from this Mac into \(path)")
        }
    }

    // MARK: - Path bar

    private var pathBar: some View {
        HStack(spacing: Spacing.element) {
            Button {
                goBack()
            } label: {
                Image(systemName: "chevron.left").font(.system(size: 12, weight: .medium))
            }
            .buttonStyle(.plain)
            .disabled(backStack.isEmpty)
            .keyboardShortcut("[", modifiers: .command)
            .foregroundStyle(backStack.isEmpty ? Palette.textMuted : Palette.textSecondary)
            .help("Back")
            .accessibilityLabel("Back")

            Button {
                goForward()
            } label: {
                Image(systemName: "chevron.right").font(.system(size: 12, weight: .medium))
            }
            .buttonStyle(.plain)
            .disabled(forwardStack.isEmpty)
            .keyboardShortcut("]", modifiers: .command)
            .foregroundStyle(forwardStack.isEmpty ? Palette.textMuted : Palette.textSecondary)
            .help("Forward")
            .accessibilityLabel("Forward")

            Button {
                if let parent = upTarget { navigate(to: parent) }
            } label: {
                Image(systemName: "arrow.up").font(.system(size: 12, weight: .medium))
            }
            .buttonStyle(.plain)
            .disabled(upTarget == nil)
            .foregroundStyle(upTarget == nil ? Palette.textMuted : Palette.textSecondary)
            .help(upTarget.map { "Go to \($0)" } ?? "Already at the root")
            .accessibilityLabel("Enclosing folder")

            Divider().frame(height: 16).overlay(Palette.divider)

            if isEditingPath {
                pathField
            } else {
                breadcrumb
            }

            Spacer(minLength: 0)

            Button {
                if isEditingPath { cancelPathEditing() } else { beginPathEditing() }
            } label: {
                Image(systemName: isEditingPath ? "xmark" : "pencil")
                    .font(.system(size: 11))
                    .foregroundStyle(Palette.textSecondary)
            }
            .buttonStyle(.plain)
            .keyboardShortcut("l", modifiers: .command)
            .help(pathEditHelp)
            .accessibilityLabel(pathEditHelp)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.bottom, Spacing.element)
    }

    private var pathField: some View {
        TextField("Type a path, then press Return", text: $pathDraft)
            .textFieldStyle(.plain)
            .font(Typography.code)
            .focused($isPathFieldFocused)
            .onSubmit { commitPathEditing() }
            .onExitCommand { cancelPathEditing() }
            .padding(.horizontal, Spacing.element)
            .padding(.vertical, Spacing.tight)
            .background(
                Palette.surfaceElevated,
                in: RoundedRectangle(cornerRadius: Radius.small, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Radius.small, style: .continuous)
                    .strokeBorder(Palette.accent.opacity(0.6), lineWidth: 1)
            )
            .accessibilityLabel("Path")
    }

    /// Clickable segments, elided in the middle when the path is deep.
    ///
    /// The middle is what gets dropped rather than the head or the tail: the
    /// root anchors you and the last two segments are where you are. The
    /// dropped segments stay reachable through the ellipsis menu, so eliding
    /// never costs a destination.
    private var breadcrumb: some View {
        let segments = FilesSection.segments(of: path)
        let leading = 1
        let trailing = 2
        let isElided = segments.count > leading + trailing + 1

        return HStack(spacing: Spacing.hairline) {
            crumbButton(title: "/", target: "/", isCurrent: path == "/")

            if isElided {
                let head = Array(segments.prefix(leading))
                let hidden = Array(segments.dropFirst(leading).dropLast(trailing))
                let tail = Array(segments.suffix(trailing))

                ForEach(head, id: \.path) { segment in
                    crumbSeparator
                    crumbButton(title: segment.name, target: segment.path, isCurrent: false)
                }

                crumbSeparator
                Menu {
                    ForEach(hidden, id: \.path) { segment in
                        Button(segment.name) { navigate(to: segment.path) }
                    }
                } label: {
                    Text("…")
                        .font(Typography.body)
                        .foregroundStyle(Palette.textSecondary)
                }
                .menuStyle(.borderlessButton)
                .menuIndicator(.hidden)
                .frame(width: 22)
                .help("Folders between here and the root")
                .accessibilityLabel("Skipped folders")

                ForEach(tail, id: \.path) { segment in
                    crumbSeparator
                    crumbButton(
                        title: segment.name,
                        target: segment.path,
                        isCurrent: segment.path == path
                    )
                }
            } else {
                ForEach(segments, id: \.path) { segment in
                    crumbSeparator
                    crumbButton(
                        title: segment.name,
                        target: segment.path,
                        isCurrent: segment.path == path
                    )
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Path: \(path)")
    }

    private var crumbSeparator: some View {
        Text("/")
            .font(Typography.metadata)
            .foregroundStyle(Palette.textMuted)
            .accessibilityHidden(true)
    }

    private func crumbButton(title: String, target: String, isCurrent: Bool) -> some View {
        Button {
            navigate(to: target)
        } label: {
            Text(title)
                .font(Typography.body)
                .foregroundStyle(isCurrent ? Palette.textPrimary : Palette.textSecondary)
                .fontWeight(isCurrent ? .medium : .regular)
                .lineLimit(1)
                .padding(.horizontal, Spacing.tight)
                .padding(.vertical, 1)
        }
        .buttonStyle(.plain)
        .disabled(isCurrent)
        .help(target)
    }

    // MARK: - Banners

    @ViewBuilder
    private var banners: some View {
        VStack(spacing: Spacing.element) {
            if let actionError {
                InlineBanner(.error, actionError.headline, actionTitle: "Dismiss") {
                    self.actionError = nil
                }
            }
            if let notice {
                InlineBanner(
                    notice.kind,
                    notice.message,
                    actionTitle: notice.actionTitle ?? "Dismiss"
                ) {
                    if let perform = notice.action {
                        perform()
                    }
                    self.notice = nil
                }
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.top, (actionError != nil || notice != nil) ? Spacing.element : 0)
        .animation(Motion.appear, value: notice?.id)
    }

    // MARK: - Upload tray

    @ViewBuilder
    private var uploadTray: some View {
        if !uploads.isEmpty {
            VStack(alignment: .leading, spacing: Spacing.element) {
                HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
                    Text(uploadHeadline)
                        .font(Typography.sectionTitle)
                        .foregroundStyle(Palette.textPrimary)
                        .accessibilityAddTraits(.isHeader)
                    Spacer(minLength: Spacing.element)
                    if uploads.contains(where: { $0.isInFlight }) {
                        Button("Cancel", action: cancelUploads)
                            .buttonStyle(.rowAction)
                    } else {
                        Button("Done") { uploads = [] }
                            .buttonStyle(.rowAction)
                    }
                }

                ForEach(uploads) { job in
                    HStack(spacing: Spacing.element) {
                        uploadGlyph(job.status)
                            .frame(width: 16, height: 16)
                        Text(job.destinationName)
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textPrimary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Spacer(minLength: Spacing.element)
                        Text(job.statusLabel)
                            .font(Typography.metadata)
                            .foregroundStyle(job.statusTint)
                            .lineLimit(1)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("\(job.destinationName): \(job.statusLabel)")
                }
            }
            .padding(Spacing.card)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(
                Palette.surface,
                in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                    .strokeBorder(Palette.divider, lineWidth: 0.5)
            )
            .padding(.horizontal, Spacing.screen)
            .padding(.top, Spacing.element)
            .transition(.opacity)
        }
    }

    /// The agent uploads a file in a single request, so there is no byte-level
    /// progress to report inside one file — only which file we are on. Saying
    /// "Uploading…" per file and counting completed files is the honest shape.
    private var uploadHeadline: String {
        let finished = uploads.filter { !$0.isInFlight }.count
        if uploads.contains(where: { $0.isInFlight }) {
            return "Uploading \(min(finished + 1, uploads.count)) of \(uploads.count) to \(FilesSection.lastComponent(of: path))"
        }
        let failed = uploads.filter { $0.didFail }.count
        if failed > 0 {
            return "\(Formatting.count(uploads.count - failed)) uploaded, \(Formatting.count(failed)) didn't"
        }
        return uploads.count == 1 ? "Upload finished" : "\(Formatting.count(uploads.count)) uploads finished"
    }

    @ViewBuilder
    private func uploadGlyph(_ status: UploadJob.Status) -> some View {
        switch status {
        case .waiting:
            Image(systemName: "circle")
                .font(.system(size: 11))
                .foregroundStyle(Palette.textMuted)
        case .uploading:
            ProgressView().controlSize(.small)
        case .finished:
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Palette.healthy)
        case .skipped:
            Image(systemName: "minus.circle")
                .font(.system(size: 12))
                .foregroundStyle(Palette.textMuted)
        case .failed:
            Image(systemName: "xmark.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Palette.critical)
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if let denied {
            deniedNotice(denied)
        } else {
            StatefulContent(state, retry: { reloadNonce += 1 }) { rows in
                loadedContent(rows)
            } empty: {
                emptyFolderState
            }
        }
    }

    @ViewBuilder
    private func loadedContent(_ rows: [FileRow]) -> some View {
        let visible = arrange(rows)
        if visible.isEmpty {
            filteredEmptyState
        } else {
            VStack(spacing: 0) {
                table(visible)
                if isTruncated {
                    loadMoreBar(loaded: rows.count)
                }
            }
        }
    }

    /// Filter, then sort, then float directories to the top.
    ///
    /// Directories first is not a preference — it is how every file manager a
    /// user has ever used behaves, and breaking it makes the table feel wrong
    /// before anyone can say why.
    private func arrange(_ rows: [FileRow]) -> [FileRow] {
        let query = filterText.trimmingCharacters(in: .whitespaces)
        let filtered = query.isEmpty
            ? rows
            : rows.filter { $0.name.localizedCaseInsensitiveContains(query) }
        let sorted = filtered.sorted(using: sortOrder)
        // `filter` preserves the order of `sorted`, so this partitions without
        // disturbing the column the user chose.
        return sorted.filter(\.isDirectory) + sorted.filter { !$0.isDirectory }
    }

    private func table(_ rows: [FileRow]) -> some View {
        Table(rows, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Name", value: \.sortName) { row in
                nameCell(row)
            }
            .width(min: 200, ideal: 320)

            TableColumn("Size", value: \.sizeSort) { row in
                sizeCell(row)
            }
            .width(min: 70, ideal: 88, max: 120)

            TableColumn("Modified", value: \.modifiedAt) { row in
                Text(row.modifiedRelative)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
                    .help(row.modifiedAbsolute)
            }
            .width(min: 100, ideal: 130, max: 190)

            TableColumn("Mode", value: \.modeSort) { row in
                Text(row.modeText)
                    .font(Typography.codeSmall)
                    .foregroundStyle(Palette.textSecondary)
                    .help(row.modeHelp)
            }
            .width(min: 88, ideal: 96, max: 120)

            TableColumn("Owner", value: \.owner) { row in
                Text(row.owner)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
            }
            .width(min: 70, ideal: 92, max: 150)

            TableColumn("Group", value: \.group) { row in
                Text(row.group)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
            }
            .width(min: 70, ideal: 92, max: 150)
        }
        .tableStyle(.inset)
        // `primaryAction` is the double-click, which is the gesture every file
        // manager trains people to use.
        .contextMenu(forSelectionType: String.self) { ids in
            rowMenu(for: ids, in: rows)
        } primaryAction: { ids in
            if let id = ids.first, ids.count == 1, let row = rows.first(where: { $0.id == id }) {
                open(row)
            }
        }
        .padding(.horizontal, Spacing.card)
        .padding(.bottom, Spacing.card)
    }

    /// Blank for a folder, because a directory's own size is four kilobytes of
    /// bookkeeping and showing it invites the wrong conclusion.
    private func sizeCell(_ row: FileRow) -> some View {
        let value: String = row.isDirectory ? "" : Formatting.bytes(row.sizeBytes)
        let label: String = row.isDirectory ? "Folder, size not shown" : "Size"
        return Text(value)
            .font(Typography.metricSmall)
            .foregroundStyle(Palette.textSecondary)
            .accessibilityLabel(label)
            .accessibilityValue(value)
    }

    private func nameCell(_ row: FileRow) -> some View {
        HStack(spacing: Spacing.element) {
            Image(systemName: row.symbolName)
                .font(.system(size: 12))
                .foregroundStyle(row.isDirectory ? Palette.accent : Palette.textSecondary)
                .frame(width: 16)
                .accessibilityHidden(true)

            if row.isSymlink, let target = row.symlinkTarget {
                HStack(spacing: Spacing.tight) {
                    Text(row.name)
                        .font(Typography.body)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                    Image(systemName: "arrow.right")
                        .font(.system(size: 8, weight: .semibold))
                        .foregroundStyle(Palette.textMuted)
                        .accessibilityHidden(true)
                    Text(target)
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(row.name), link to \(target)")
            } else {
                Text(row.name)
                    .font(Typography.body)
                    .foregroundStyle(row.isReadable == false ? Palette.textMuted : Palette.textPrimary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            if row.isReadable == false {
                Chip("No access", tint: Palette.inactive, systemImage: "lock")
                    .accessibilityLabel("This account can't read it")
            }
        }
        .padding(.vertical, 2)
        .help(row.path)
    }

    /// Named `rowMenu` rather than `contextMenu` so it can never be confused
    /// with `View.contextMenu`, which is in scope on `self`.
    @ViewBuilder
    private func rowMenu(for ids: Set<String>, in rows: [FileRow]) -> some View {
        if ids.count == 1, let id = ids.first, let row = rows.first(where: { $0.id == id }) {
            Button(FilesSection.openVerb(for: row)) { open(row) }
            if row.isSymlink, let target = row.symlinkTarget {
                Button("Go to \(Formatting.truncate(target, to: 40))") { navigate(to: target) }
            }
            Divider()
            Button("Copy Path") { copy(row.path) }
            Button("Rename…") { sheet = .rename(row) }
            Button("Change Permissions…") { sheet = .permissions(row) }
            Divider()
            Button("Delete…", role: .destructive) { askDelete(row) }
        } else if ids.count > 1 {
            // Multi-select exists so a person can look at a group, not so they
            // can act on one by accident. Bulk delete is deliberately absent.
            Text("\(Formatting.count(ids.count)) items selected")
            Button("Copy Paths") { copy(ids.sorted().joined(separator: "\n")) }
        }
    }

    private func loadMoreBar(loaded: Int) -> some View {
        HStack(spacing: Spacing.element) {
            if isLoadingMore {
                InlineProgress("Reading more of this folder…")
            } else {
                Text(remainingDescription(loaded: loaded))
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                Spacer(minLength: Spacing.element)
                Button("Load More") {
                    Task { await loadMore(from: loaded) }
                }
                .buttonStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Spacing.card + Spacing.element)
        .padding(.bottom, Spacing.card)
    }

    private func remainingDescription(loaded: Int) -> String {
        guard let total = totalEntries, total > loaded else {
            return "This folder has more items than ServerOS has read so far."
        }
        let remaining = total - loaded
        return "\(Formatting.count(remaining)) more item\(remaining == 1 ? "" : "s") in this folder. "
            + "Sorting and filtering apply to the \(Formatting.count(loaded)) loaded so far."
    }

    // MARK: - Empty, denied and unreachable

    private var emptyFolderState: some View {
        // Built as locals rather than inline ternaries: a ternary whose branches
        // are `nil` and a closure literal is exactly the shape the type-checker
        // struggles with inside a large initialiser call.
        let secondaryTitle: String? = showHidden ? nil : "Show Hidden Items"
        var secondaryAction: (() -> Void)?
        if !showHidden {
            secondaryAction = { self.showHidden = true }
        }

        return EmptyState(
            systemImage: "folder",
            title: "This folder is empty",
            message: showHidden
                ? "There is nothing in \(path) on \(session.name), hidden items included."
                : "There is nothing in \(path) on \(session.name). Some folders only hold dot files — turn on hidden items to check.",
            actionTitle: "Upload a File",
            action: { self.isImportingUploads = true },
            secondaryActionTitle: secondaryTitle,
            secondaryAction: secondaryAction
        )
    }

    private var filteredEmptyState: some View {
        EmptyState(
            systemImage: "line.3.horizontal.decrease.circle",
            title: "Nothing here matches “\(filterText)”",
            // Being explicit about the scope matters: someone who believes this
            // searched the server will conclude the file is gone.
            message: "The filter looks at the items ServerOS has loaded from \(path). "
                + "It doesn't search the rest of \(session.name) — open the folder you expect the file to be in, then filter again.",
            actionTitle: "Clear Filter",
            action: { filterText = "" }
        )
    }

    /// The refusal, said calmly.
    ///
    /// This is the product working as designed, so it gets an explanation and a
    /// way onwards rather than an error's visual weight.
    private func deniedNotice(_ error: ServerOSError) -> some View {
        VStack(spacing: Spacing.group) {
            Image(systemName: "hand.raised")
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)

            VStack(spacing: Spacing.element) {
                Text("ServerOS doesn't open this location")
                    .font(Typography.sectionTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)

                Text(error.headline)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 380)

                Text("The agent protects a short list of paths from this app — the shadow password file, private keys, ServerOS's own configuration and the kernel's /proc tree. "
                    + "Nothing is broken, and nothing on \(session.name) has changed.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .multilineTextAlignment(.center)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: 400)
            }

            HStack(spacing: Spacing.element) {
                Button("Go Back") {
                    if backStack.isEmpty {
                        navigate(to: upTarget ?? "/")
                    } else {
                        goBack()
                    }
                }
                .buttonStyle(.primary)

                Button("Open Terminal") { navigation.select(section: .terminal) }
                    .buttonStyle(.secondary)
            }

            Text("Anything genuinely needed here is still reachable over the terminal, where it is your account's permissions that decide.")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .multilineTextAlignment(.center)
                .frame(maxWidth: 380)
        }
        .padding(Spacing.generous)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .accessibilityElement(children: .contain)
    }

    /// A faint tint while a Finder drag is over the window, so the drop target
    /// is obvious without a dashed rectangle shouting about it.
    @ViewBuilder
    private var dropHighlight: some View {
        if isDropTargeted {
            Palette.accentMuted
        } else {
            Palette.background
        }
    }

    // MARK: - Inspector

    @ViewBuilder
    private var inspectorPane: some View {
        if let row = selectedRow {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.group) {
                    inspectorHeader(row)
                    Divider().overlay(Palette.divider)
                    inspectorActions(row)
                    Divider().overlay(Palette.divider)
                    inspectorFacts(row)
                    if row.isEditable {
                        Divider().overlay(Palette.divider)
                        inspectorPreview(row)
                    }
                }
                .padding(Spacing.card)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
            .task(id: row.id) { await loadInspectorExtras(row) }
        } else {
            EmptyState(
                systemImage: "sidebar.right",
                title: "Nothing selected",
                message: "Select a file or folder to see its size, owner, permissions and what you can do with it."
            )
        }
    }

    private func inspectorHeader(_ row: FileRow) -> some View {
        VStack(alignment: .leading, spacing: Spacing.snug) {
            HStack(spacing: Spacing.element) {
                Image(systemName: row.symbolName)
                    .font(.system(size: 20, weight: .light))
                    .foregroundStyle(row.isDirectory ? Palette.accent : Palette.textSecondary)
                    .accessibilityHidden(true)
                Text(row.name)
                    .font(Typography.sectionTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(2)
                    .textSelection(.enabled)
                    .accessibilityAddTraits(.isHeader)
            }

            HStack(spacing: Spacing.snug) {
                Chip(row.kindLabel, tint: row.isDirectory ? Palette.accent : Palette.inactive)
                if row.isSymlink {
                    Chip("Link", tint: Palette.informational, systemImage: "arrow.up.forward")
                }
                if row.isWritable == false {
                    Chip("Read only", tint: Palette.warning, systemImage: "lock")
                }
            }
        }
    }

    private func inspectorActions(_ row: FileRow) -> some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            HStack(spacing: Spacing.element) {
                Button(FilesSection.openVerb(for: row)) { open(row) }
                    .buttonStyle(.secondary)
                Button("Download") { requestDownload() }
                    .buttonStyle(.secondary)
                    .disabled(row.isDirectory || row.isReadable == false)
            }
            HStack(spacing: Spacing.element) {
                Button("Rename…") { sheet = .rename(row) }
                    .buttonStyle(.secondary)
                Button("Permissions…") { sheet = .permissions(row) }
                    .buttonStyle(.secondary)
            }
            Button("Delete…") { askDelete(row) }
                .buttonStyle(.destructive)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Every field the agent gives us, because the brief is explicit that the
    /// technical depth must be available once you have asked for it.
    ///
    /// Split into three groups because a `ViewBuilder` block takes at most ten
    /// children — and because identity, permissions and access are three
    /// different questions anyway.
    private func inspectorFacts(_ row: FileRow) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader("Details")
                .padding(.bottom, Spacing.tight)
            identityFacts(row)
            permissionFacts(row)
            accessFacts(row)
        }
    }

    @ViewBuilder
    private func identityFacts(_ row: FileRow) -> some View {
        KeyValueRow("Name", row.name)
        KeyValueRow("Path", row.path, monospaced: true, selectable: true)
        KeyValueRow("Kind", row.kindLabel)
        if row.isDirectory {
            KeyValueRow("Items", selectedDirectoryCount.map { Formatting.count($0) })
        } else {
            KeyValueRow("Size", Formatting.bytes(row.sizeBytes))
        }
        KeyValueRow("Modified", row.modifiedAbsolute)
    }

    @ViewBuilder
    private func permissionFacts(_ row: FileRow) -> some View {
        KeyValueRow("Permissions", row.modeText, monospaced: true)
        KeyValueRow("Octal", Formatting.fileMode(row.modeOctal), monospaced: true)
        KeyValueRow("Reported mode", row.modeRaw, monospaced: true)
        KeyValueRow("Owner", row.ownerDetail)
        KeyValueRow("Group", row.groupDetail)
    }

    @ViewBuilder
    private func accessFacts(_ row: FileRow) -> some View {
        KeyValueRow("Symbolic link", row.isSymlink ? "Yes" : "No")
        if row.isSymlink {
            KeyValueRow("Link target", row.symlinkTarget, monospaced: true)
        }
        KeyValueRow("Readable", FilesSection.describe(row.isReadable))
        KeyValueRow("Writable", FilesSection.describe(row.isWritable))
        KeyValueRow("Extension", row.ext)
        KeyValueRow("Text file", FilesSection.describe(row.isText))
    }

    @ViewBuilder
    private func inspectorPreview(_ row: FileRow) -> some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            SectionHeader("Preview")

            switch preview {
            case .idle, .loading:
                InlineProgress("Reading the first lines…")
            case .tooLarge:
                Text("This file is larger than \(Formatting.bytes(FilesSection.previewSizeLimit)), so ServerOS doesn't preview it here. Open it in the editor to read it.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .failed(let message):
                Text(message)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .loaded(let text):
                ScrollView {
                    Text(text)
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textSecondary)
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(Spacing.element)
                }
                .frame(maxHeight: 220)
                .background(
                    Palette.surfaceElevated,
                    in: RoundedRectangle(cornerRadius: Radius.small, style: .continuous)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: Radius.small, style: .continuous)
                        .strokeBorder(Palette.divider, lineWidth: 0.5)
                )
            }
        }
    }

    private var selectedRow: FileRow? {
        guard selection.count == 1, let id = selection.first else { return nil }
        return state.value?.first { $0.id == id }
    }

    // MARK: - Sheets

    @ViewBuilder
    private func sheetContent(_ which: FilesSheet) -> some View {
        switch which {
        case .newFolder:
            NameSheet(
                title: "New Folder",
                explanation: "The folder is created inside \(path) on \(session.name).",
                confirmTitle: "Create Folder",
                initialName: "",
                existingNames: existingNames
            ) { name in
                createDirectory(named: name)
            }

        case .newFile:
            NameSheet(
                title: "New Text File",
                explanation: "ServerOS creates an empty text file in \(path) and opens it for editing.",
                confirmTitle: "Create File",
                initialName: "",
                existingNames: existingNames
            ) { name in
                createTextFile(named: name)
            }

        case .rename(let row):
            NameSheet(
                title: "Rename \(row.name)",
                explanation: row.isDirectory
                    ? "The folder keeps everything inside it. Anything referring to it by its old path — a service file, a symlink, a script — will need updating."
                    : "Anything referring to this file by its old name, such as a service or a script, will need updating.",
                confirmTitle: "Rename",
                initialName: row.name,
                existingNames: existingNames.subtracting([row.name])
            ) { name in
                rename(row, to: name)
            }

        case .permissions(let row):
            PermissionsSheet(
                target: row.name,
                isDirectory: row.isDirectory,
                initialMode: row.modeOctal ?? (row.isDirectory ? 0o755 : 0o644)
            ) { mode in
                changeMode(row, to: mode)
            }

        case .edit(let row):
            if let api = session.api {
                FileEditorView(
                    path: row.path,
                    displayName: row.name,
                    serverName: session.name,
                    isWritable: row.isWritable,
                    api: api
                ) {
                    Task { await load(showsLoading: false) }
                }
            } else {
                disconnectedSheet
            }

        case .conflict(let job):
            UploadConflictSheet(
                fileName: job.destinationName,
                folder: path,
                keepBothName: FilesSection.keepBothName(for: job.destinationName)
            ) { resolution in
                resolveConflict(jobID: job.id, resolution: resolution)
            }
        }
    }

    private var disconnectedSheet: some View {
        VStack(spacing: Spacing.group) {
            ErrorState(error: ServerOSError.sshNotConnected) { session.reconnect() }
            Button("Close") { sheet = nil }
                .buttonStyle(.secondary)
                .padding(.bottom, Spacing.card)
        }
        .frame(width: 460, height: 360)
        .background(Palette.background)
    }

    private var existingNames: Set<String> {
        Set((state.value ?? []).map(\.name))
    }

    // MARK: - Navigation

    private func restoreLocation() {
        // The persisted location is the whole point of `currentFilePath`:
        // leaving for Docker and coming back should land where you were.
        let stored = navigation.currentFilePath
        let restored = stored.isEmpty ? "/" : stored
        if restored != path {
            path = restored
        }
        pathDraft = restored
    }

    private var upTarget: String? {
        if let parentPath, !parentPath.isEmpty { return parentPath }
        return FilesSection.parentPath(of: path)
    }

    private func navigate(to newPath: String) {
        let cleaned = FilesSection.normalise(newPath)
        guard cleaned != path else { return }
        backStack.append(path)
        if backStack.count > 64 { backStack.removeFirst() }
        forwardStack.removeAll()
        move(to: cleaned)
    }

    private func goBack() {
        guard let previous = backStack.popLast() else { return }
        forwardStack.append(path)
        move(to: previous)
    }

    private func goForward() {
        guard let next = forwardStack.popLast() else { return }
        backStack.append(path)
        move(to: next)
    }

    /// The one place the current location changes, so nothing can navigate
    /// without the persisted path, the selection and the filter following.
    private func move(to newPath: String) {
        path = newPath
        navigation.currentFilePath = newPath
        pathDraft = newPath
        selection = []
        filterText = ""
        denied = nil
        isEditingPath = false
    }

    private func beginPathEditing() {
        pathDraft = path
        isEditingPath = true
        isPathFieldFocused = true
    }

    private func cancelPathEditing() {
        isEditingPath = false
        pathDraft = path
        isPathFieldFocused = false
    }

    private func commitPathEditing() {
        let typed = pathDraft.trimmingCharacters(in: .whitespaces)
        isEditingPath = false
        isPathFieldFocused = false
        guard !typed.isEmpty else {
            pathDraft = path
            return
        }
        navigate(to: typed)
    }

    // MARK: - Opening

    private func open(_ row: FileRow) {
        if row.isDirectory {
            navigate(to: row.path)
        } else if row.isEditable {
            sheet = .edit(row)
        } else if row.isReadable == false {
            notice = Notice(
                kind: .info,
                message: "This account can't read \(row.name) on \(session.name), so there is nothing to open or download."
            )
        } else {
            // Not text, or the agent can't tell. Downloading is the honest
            // offer: opening a binary in a text editor would corrupt it on save.
            requestDownload(for: row)
        }
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    // MARK: - Loading

    /// The key that decides when the listing must be re-read.
    private struct ListingRequest: Equatable {
        let path: String
        let showHidden: Bool
        let nonce: Int
    }

    /// - Parameter showsLoading: False for a refresh behind a table the user is
    ///   already reading, so it never flickers back to a skeleton.
    private func load(showsLoading: Bool) async {
        guard let api = session.api else {
            // No connection. A listing already on screen stays there — the
            // shell's stale banner is what says it is not live — and only a
            // screen that has never had one drops to a skeleton.
            if showsLoading, state.value == nil { state = .loading }
            return
        }
        guard session.capabilities.files else {
            state = .unavailable(
                subsystem: "Files",
                reason: "This server's agent was built without file access, so ServerOS can't browse \(session.name)'s filesystem. The terminal still works."
            )
            return
        }
        if showsLoading, state.value == nil { state = .loading }

        do {
            let listing = try await api.listDirectory(
                path: path,
                showHidden: showHidden,
                sort: .name,
                limit: FilesSection.pageSize,
                offset: 0
            )
            apply(listing, replacing: true)
        } catch let error as ServerOSError {
            handle(listingFailure: error, showsLoading: showsLoading)
        } catch {
            handle(
                listingFailure: ServerOSError.transport(error, serverName: session.name),
                showsLoading: showsLoading
            )
        }
    }

    private func loadMore(from offset: Int) async {
        guard let api = session.api, !isLoadingMore else { return }
        isLoadingMore = true
        defer { isLoadingMore = false }

        do {
            let listing = try await api.listDirectory(
                path: path,
                showHidden: showHidden,
                sort: .name,
                limit: FilesSection.pageSize,
                offset: offset
            )
            apply(listing, replacing: false)
        } catch let error as ServerOSError {
            actionError = error
        } catch {
            actionError = ServerOSError.transport(error, serverName: session.name)
        }
    }

    private func apply(_ listing: DirectoryListing, replacing: Bool) {
        denied = nil
        parentPath = listing.parent
        totalEntries = listing.total

        let incoming = listing.entries.map(FileRow.init)
        let combined: [FileRow]
        if replacing {
            combined = incoming
        } else {
            // De-duplicate by path: a directory changing under us while we page
            // through it can otherwise hand back the same entry twice, and a
            // Table with duplicate ids misbehaves badly.
            var seen = Set((state.value ?? []).map(\.id))
            let fresh = incoming.filter { seen.insert($0.id).inserted }
            combined = (state.value ?? []) + fresh
        }

        let more = listing.truncated ?? false
        let hasUnread = (listing.total ?? combined.count) > combined.count
        isTruncated = more || hasUnread

        state = combined.isEmpty ? .empty : .loaded(combined)
    }

    private func handle(listingFailure error: ServerOSError, showsLoading: Bool) {
        if error.code == "denied" {
            // Not a failure. The section shows the explanation instead.
            denied = error
            state = .empty
            return
        }
        if showsLoading || state.value == nil {
            state = .failed(error)
        } else {
            actionError = error
        }
    }

    /// Whatever the inspector needs beyond the row itself: a preview for a
    /// small text file, an item count for a folder — both only once a row is
    /// actually selected, so browsing costs nothing.
    private func loadInspectorExtras(_ row: FileRow) async {
        guard let api = session.api else { return }

        if row.isDirectory {
            let listing = try? await api.listDirectory(
                path: row.path,
                showHidden: true,
                sort: .name,
                limit: 1,
                offset: 0
            )
            selectedDirectoryCount = listing?.total
            return
        }

        guard row.isEditable else { return }
        if let size = row.sizeBytes, size > FilesSection.previewSizeLimit {
            preview = .tooLarge
            return
        }
        preview = .loading
        do {
            let contents = try await api.readTextFile(path: row.path)
            let head = contents.content
                .split(separator: "\n", omittingEmptySubsequences: false)
                .prefix(40)
                .joined(separator: "\n")
            preview = .loaded(head.isEmpty ? "This file is empty." : head)
        } catch let error as ServerOSError {
            preview = .failed(error.headline)
        } catch {
            preview = .failed("ServerOS couldn't read this file just now.")
        }
    }

    // MARK: - Create, rename, chmod

    private func createDirectory(named name: String) {
        guard let api = session.api else { actionError = .sshNotConnected; return }
        let destination = FilesSection.join(path, name)
        Task {
            do {
                _ = try await api.createDirectory(path: destination)
                notice = Notice(kind: .success, message: "Created \(name) in \(path).")
                await load(showsLoading: false)
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
        }
    }

    private func createTextFile(named name: String) {
        guard let api = session.api else { actionError = .sshNotConnected; return }
        let destination = FilesSection.join(path, name)
        Task {
            do {
                let entry = try await api.writeTextFile(path: destination, contents: "")
                notice = Notice(kind: .success, message: "Created \(name) in \(path).")
                await load(showsLoading: false)
                selection = [entry.path]
                sheet = .edit(FileRow(entry))
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
        }
    }

    private func rename(_ row: FileRow, to name: String) {
        guard let api = session.api else { actionError = .sshNotConnected; return }
        let destination = FilesSection.join(path, name)
        Task {
            do {
                _ = try await api.move(from: row.path, to: destination)
                notice = Notice(kind: .success, message: "Renamed \(row.name) to \(name).")
                selection = [destination]
                await load(showsLoading: false)
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
        }
    }

    private func changeMode(_ row: FileRow, to mode: UInt32) {
        guard let api = session.api else { actionError = .sshNotConnected; return }
        let octal = Formatting.fileMode(mode)
        Task {
            do {
                _ = try await api.changeMode(path: row.path, mode: octal)
                notice = Notice(kind: .success, message: "\(row.name) is now \(octal).")
                await load(showsLoading: false)
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
        }
    }

    // MARK: - Delete

    private func askDelete(_ row: FileRow) {
        pendingDeletion = row
        isConfirmingDelete = true
    }

    private var deleteTitle: String {
        guard let row = pendingDeletion else { return "Delete this item?" }
        return row.isDirectory ? "Delete the folder \(row.name)?" : "Delete \(row.name)?"
    }

    /// Written so the sentence `confirmDestructive` appends — "This cannot be
    /// undone." — is true as stated. It cannot be undone *from ServerOS*. What
    /// the agent does on its side is reported afterwards, from `FileDeletion`,
    /// rather than guessed at here.
    private var deleteConsequence: String {
        guard let row = pendingDeletion else { return "" }
        if row.isDirectory {
            let contents: String
            if let count = selectedDirectoryCount, count > 0 {
                contents = " and the \(Formatting.count(count)) item\(count == 1 ? "" : "s") inside it"
            } else if selectedDirectoryCount == 0 {
                contents = ", which is empty"
            } else {
                contents = " and everything inside it"
            }
            return "ServerOS will remove \(row.path)\(contents) from \(session.name). "
                + "The agent normally moves deleted items to the server's trash and ServerOS will tell you exactly where it put this one — but ServerOS can't put it back for you."
        }
        return "ServerOS will remove \(row.path) from \(session.name). "
            + "The agent normally moves deleted items to the server's trash and ServerOS will tell you exactly where it put this one — but ServerOS can't put it back for you."
    }

    private func performDelete(_ row: FileRow) {
        guard let api = session.api else { actionError = .sshNotConnected; return }
        Task {
            do {
                let result = try await api.deleteFile(path: row.path, recursive: row.isDirectory)
                notice = Notice(kind: .success, message: FilesSection.describe(deletion: result, name: row.name))
                selection = []
                await load(showsLoading: false)
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
            pendingDeletion = nil
        }
    }

    /// Repeat the agent's own account of what happened, in words.
    ///
    /// "Deleted forever" when the agent trashed it, or "moved to Trash" when it
    /// unlinked it, are both lies a person would act on.
    private static func describe(deletion: FileDeletion, name: String) -> String {
        if deletion.trashed {
            if let restore = deletion.restorePath {
                return "Moved \(name) to the server's trash. It is at \(restore) until the server clears it."
            }
            return "Moved \(name) to the server's trash."
        }
        var sentence = "Permanently removed \(name) from the server."
        let files = deletion.filesDeleted ?? 0
        let directories = deletion.directoriesDeleted ?? 0
        if files + directories > 1 {
            sentence += " \(Formatting.count(files)) file\(files == 1 ? "" : "s")"
            if directories > 0 {
                sentence += " and \(Formatting.count(directories)) folder\(directories == 1 ? "" : "s")"
            }
            sentence += " removed."
        }
        if let freed = deletion.bytesFreed, freed > 0 {
            sentence += " \(Formatting.bytes(freed)) freed."
        }
        return sentence
    }

    // MARK: - Download

    private func requestDownload() {
        guard let row = selectedRow else { return }
        requestDownload(for: row)
    }

    private func requestDownload(for row: FileRow) {
        // The agent serves one file per request and has no archiving endpoint,
        // so a folder cannot be fetched in one go. Saying that, and offering the
        // route that does work, is better than a disabled button.
        guard !row.isDirectory else {
            notice = Notice(
                kind: .info,
                message: "ServerOS downloads files one at a time, so it can't fetch the whole \(row.name) folder in one go. Open it and choose the files you want.",
                actionTitle: "Open \(Formatting.truncate(row.name, to: 24))",
                action: { navigate(to: row.path) }
            )
            return
        }
        guard row.isReadable != false else {
            notice = Notice(
                kind: .info,
                message: "This account can't read \(row.name) on \(session.name), so there is nothing to download."
            )
            return
        }
        guard let api = session.api else { actionError = .sshNotConnected; return }

        Task {
            do {
                let data = try await api.downloadFile(path: row.path)
                download = DownloadPayload(name: row.name, data: data)
                isExportingDownload = true
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
        }
    }

    // MARK: - Upload

    private func beginUpload(urls: [URL]) {
        guard session.api != nil else { actionError = .sshNotConnected; return }
        guard denied == nil else { return }

        let jobs = urls.map { url in
            UploadJob(
                id: UUID(),
                url: url,
                destinationName: url.lastPathComponent,
                status: .waiting
            )
        }
        guard !jobs.isEmpty else { return }

        // A second drop while the first is running appends rather than
        // restarting: the tray is a queue, not a single transfer.
        uploads.append(contentsOf: jobs)
        if uploadTask == nil { processNextUpload() }
    }

    private func cancelUploads() {
        uploadTask?.cancel()
        uploadTask = nil
        for index in uploads.indices where uploads[index].isInFlight {
            uploads[index].status = .skipped
        }
        notice = Notice(kind: .info, message: "Upload cancelled. Files already copied are still on the server.")
    }

    /// The queue is a state machine on the main actor rather than one long
    /// task, because the conflict prompt has to interrupt it and wait for an
    /// answer — and suspending a task on a SwiftUI decision is far more moving
    /// parts than stepping a queue forward one file at a time.
    private func processNextUpload() {
        uploadTask = nil
        guard let index = uploads.firstIndex(where: { $0.status == .waiting }) else {
            if uploads.contains(where: { $0.didSucceed }) {
                Task { await load(showsLoading: false) }
            }
            return
        }
        guard let api = session.api else {
            uploads[index].status = .failed("ServerOS isn't connected to this server.")
            processNextUpload()
            return
        }

        let job = uploads[index]
        let destination = FilesSection.join(path, job.destinationName)

        uploadTask = Task {
            // `stat` throwing is how we learn the path is free. Uploading with
            // `overwrite: false` and reading the failure would work too, but it
            // would mean sending the whole file before discovering the clash.
            let exists = (try? await api.stat(path: destination)) != nil
            if Task.isCancelled { return }
            if exists {
                sheet = .conflict(job)
                uploadTask = nil
            } else {
                await perform(jobID: job.id, destinationName: job.destinationName, overwrite: false)
            }
        }
    }

    private func resolveConflict(jobID: UUID, resolution: UploadConflictSheet.Resolution) {
        sheet = nil
        guard let index = uploads.firstIndex(where: { $0.id == jobID }) else {
            processNextUpload()
            return
        }
        switch resolution {
        case .skip:
            uploads[index].status = .skipped
            processNextUpload()
        case .replace:
            let name = uploads[index].destinationName
            uploadTask = Task { await perform(jobID: jobID, destinationName: name, overwrite: true) }
        case .keepBoth:
            let name = FilesSection.keepBothName(for: uploads[index].destinationName)
            uploads[index].destinationName = name
            uploadTask = Task { await perform(jobID: jobID, destinationName: name, overwrite: false) }
        }
    }

    private func perform(jobID: UUID, destinationName: String, overwrite: Bool) async {
        guard let api = session.api else { return }
        guard let index = uploads.firstIndex(where: { $0.id == jobID }) else { return }
        let url = uploads[index].url
        uploads[index].status = .uploading

        // A file chosen through `fileImporter` in a sandboxed app arrives
        // security-scoped; without this the read fails with a permission error
        // that has nothing to do with the server.
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }

        let data: Data
        do {
            data = try Data(contentsOf: url)
        } catch {
            setStatus(.failed("ServerOS couldn't read this file on your Mac."), for: jobID)
            processNextUpload()
            return
        }

        guard data.count <= FilesSection.uploadSizeLimit else {
            setStatus(
                .failed("Too large — ServerOS uploads files up to \(Formatting.bytes(Int64(FilesSection.uploadSizeLimit)))."),
                for: jobID
            )
            processNextUpload()
            return
        }

        do {
            _ = try await api.uploadFile(
                path: FilesSection.join(path, destinationName),
                contents: data,
                overwrite: overwrite
            )
            if Task.isCancelled { return }
            setStatus(.finished, for: jobID)
        } catch let error as ServerOSError {
            setStatus(.failed(error.headline), for: jobID)
        } catch {
            setStatus(.failed(ServerOSError.transport(error, serverName: session.name).headline), for: jobID)
        }
        processNextUpload()
    }

    private func setStatus(_ status: UploadJob.Status, for jobID: UUID) {
        guard let index = uploads.firstIndex(where: { $0.id == jobID }) else { return }
        uploads[index].status = status
    }

    // MARK: - Path helpers

    private static func normalise(_ raw: String) -> String {
        var value = raw.trimmingCharacters(in: .whitespaces)
        if value.isEmpty { return "/" }
        if !value.hasPrefix("/") { value = "/" + value }
        while value.count > 1 && value.hasSuffix("/") { value.removeLast() }
        return value
    }

    private static func join(_ directory: String, _ name: String) -> String {
        directory == "/" ? "/\(name)" : "\(directory)/\(name)"
    }

    private static func parentPath(of path: String) -> String? {
        guard path != "/" else { return nil }
        var components = path.split(separator: "/").map(String.init)
        guard !components.isEmpty else { return nil }
        components.removeLast()
        return components.isEmpty ? "/" : "/" + components.joined(separator: "/")
    }

    private static func lastComponent(of path: String) -> String {
        path.split(separator: "/").map(String.init).last ?? "/"
    }

    /// One crumb: a display name and the path clicking it goes to.
    fileprivate struct Segment {
        let name: String
        let path: String
    }

    private static func segments(of path: String) -> [Segment] {
        var built: [Segment] = []
        var accumulated = ""
        for component in path.split(separator: "/").map(String.init) {
            accumulated += "/" + component
            built.append(Segment(name: component, path: accumulated))
        }
        return built
    }

    /// "report.txt" → "report 2.txt"; "Dockerfile" → "Dockerfile 2".
    ///
    /// The space-then-number form is what Finder does, and this is a Mac app.
    fileprivate static func keepBothName(for name: String) -> String {
        let url = URL(fileURLWithPath: name)
        let ext = url.pathExtension
        let stem = url.deletingPathExtension().lastPathComponent
        guard !stem.isEmpty else { return name + " 2" }
        return ext.isEmpty ? "\(stem) 2" : "\(stem) 2.\(ext)"
    }

    /// What double-clicking this row will actually do, said on the button that
    /// does it. "Open" on a binary that ServerOS can only download would be a
    /// promise the next click breaks.
    private static func openVerb(for row: FileRow) -> String {
        if row.isDirectory { return "Open Folder" }
        if row.isEditable { return "Open in Editor" }
        return "Download…"
    }

    private static func describe(_ flag: Bool?) -> String {
        switch flag {
        case .some(true): return "Yes"
        case .some(false): return "No"
        case .none: return "The agent didn't say"
        }
    }
}

// MARK: - Row model

/// One row of the file table.
///
/// A flattened view model rather than the wire type, for the same reason the
/// process table has one: `Table`'s sortable columns need every sorted value to
/// be `Comparable`, and half of `FileEntry` is optional. Doing that flattening
/// once here keeps six column declarations clean, and gives the inspector a
/// single place to read every field from.
private struct FileRow: Identifiable, Equatable {
    let id: String
    let name: String
    let sortName: String
    let path: String
    let kind: String
    let kindLabel: String
    let isDirectory: Bool
    let isRegularFile: Bool
    let isEditable: Bool
    let isSymlink: Bool
    let symlinkTarget: String?
    let isReadable: Bool?
    let isWritable: Bool?
    let isText: Bool?
    let ext: String?
    let sizeBytes: Int64?
    /// Directories sort as -1 so they never interleave with files by size.
    let sizeSort: Int64
    let modifiedAt: Int64
    let modifiedRelative: String
    let modifiedAbsolute: String
    let modeOctal: UInt32?
    let modeSort: UInt32
    let modeText: String
    let modeHelp: String
    let modeRaw: String?
    let owner: String
    let ownerDetail: String
    let group: String
    let groupDetail: String
    /// Named `symbolName` rather than `symbol` so it does not shadow the
    /// file-scope `symbol(for:)` inside this type's own initialiser.
    let symbolName: String

    init(_ entry: FileEntry) {
        self.id = entry.path
        self.name = entry.name
        self.sortName = entry.name.lowercased()
        self.path = entry.path
        self.kind = entry.kind
        self.isDirectory = entry.isDirectory
        self.isRegularFile = entry.isRegularFile
        self.isEditable = entry.isEditable
        self.isSymlink = entry.isSymlink
        self.symlinkTarget = entry.symlinkTarget
        self.isReadable = entry.isReadable
        self.isWritable = entry.isWritable
        self.isText = entry.isText
        self.ext = entry.`extension`
        self.sizeBytes = entry.sizeBytes
        self.sizeSort = entry.isDirectory ? -1 : (entry.sizeBytes ?? -1)
        self.modifiedAt = entry.modifiedAt ?? 0
        if let modified = entry.modifiedAt, modified > 0 {
            self.modifiedRelative = Formatting.relative(unixSeconds: modified)
            self.modifiedAbsolute = Formatting.timestamp(unixSeconds: modified)
        } else {
            self.modifiedRelative = "Unknown"
            self.modifiedAbsolute = "The agent didn't report a modification time"
        }
        self.modeOctal = entry.modeOctal
        self.modeSort = entry.modeOctal ?? 0
        self.modeText = Formatting.modeString(
            entry.modeOctal,
            isDirectory: entry.isDirectory,
            isSymlink: entry.isSymlink
        )
        self.modeHelp = "Octal \(Formatting.fileMode(entry.modeOctal))"
        self.modeRaw = entry.mode
        self.owner = entry.owner ?? "—"
        self.ownerDetail = FileRow.describeAccount(name: entry.owner, id: entry.uid)
        self.group = entry.group ?? "—"
        self.groupDetail = FileRow.describeAccount(name: entry.group, id: entry.gid)
        self.symbolName = symbol(for: entry)

        var label = "File"
        if entry.isDirectory { label = "Folder" }
        else if entry.kind == "symlink" { label = "Link" }
        else if !entry.isRegularFile { label = entry.kind.capitalizingFirstLetter() }
        self.kindLabel = label
    }

    /// "deploy (1000)" — the name people read plus the number the system uses.
    private static func describeAccount(name: String?, id: UInt32?) -> String {
        switch (name, id) {
        case let (.some(name), .some(id)): return "\(name) (\(id))"
        case let (.some(name), .none): return name
        case let (.none, .some(id)): return "uid \(id)"
        default: return "—"
        }
    }
}

/// The glyph for one entry.
///
/// Kept deliberately small and boring: one SF Symbol family, mapped from the
/// extension the agent reports, so a directory of source files reads as a set
/// rather than as a parade of different icon styles.
private func symbol(for entry: FileEntry) -> String {
    if entry.isDirectory { return "folder" }
    if entry.isSymlink { return "arrow.up.forward.square" }
    if entry.kind == "socket" || entry.kind == "fifo" { return "point.3.connected.trianglepath.dotted" }
    if entry.kind == "device" || entry.kind == "block-device" || entry.kind == "char-device" {
        return "externaldrive"
    }

    switch (entry.`extension` ?? "").lowercased() {
    case "swift", "rs", "go", "py", "rb", "php", "java", "kt", "js", "mjs", "cjs",
         "ts", "tsx", "jsx", "c", "h", "hpp", "cc", "cpp", "cs", "m", "scala", "ex", "exs":
        return "curlybraces"
    case "sh", "bash", "zsh", "fish", "ksh", "command":
        return "terminal"
    case "json", "yml", "yaml", "toml", "ini", "conf", "cfg", "env", "properties", "plist", "service":
        return "gearshape"
    case "md", "markdown", "txt", "rst", "log", "csv", "tsv":
        return "doc.text"
    case "pdf", "rtf", "doc", "docx":
        return "doc.richtext"
    case "png", "jpg", "jpeg", "gif", "svg", "webp", "heic", "bmp", "ico", "tiff":
        return "photo"
    case "zip", "gz", "tgz", "bz2", "xz", "zst", "tar", "7z", "rar", "deb", "rpm":
        return "archivebox"
    case "pem", "key", "crt", "cer", "p12", "pfx", "asc", "gpg", "pub", "kbx":
        return "lock"
    case "sql", "db", "sqlite", "sqlite3", "dump":
        return "cylinder"
    default:
        break
    }

    // No extension but an execute bit: almost always a script or a binary.
    if let mode = entry.modeOctal, mode & 0o111 != 0 { return "terminal" }
    if entry.isText == true { return "doc.text" }
    return "doc"
}

// MARK: - Supporting state

/// Which sheet is up. One piece of state rather than six booleans, because only
/// one sheet can ever be presented and six booleans can disagree about that.
private enum FilesSheet: Identifiable {
    case newFolder
    case newFile
    case rename(FileRow)
    case permissions(FileRow)
    case edit(FileRow)
    case conflict(UploadJob)

    var id: String {
        switch self {
        case .newFolder: return "new-folder"
        case .newFile: return "new-file"
        case .rename(let row): return "rename:\(row.id)"
        case .permissions(let row): return "chmod:\(row.id)"
        case .edit(let row): return "edit:\(row.id)"
        case .conflict(let job): return "conflict:\(job.id.uuidString)"
        }
    }
}

/// A transient message under the header. Carries its own action so a notice can
/// offer the way forward it is describing.
private struct Notice: Identifiable {
    let id = UUID()
    let kind: BannerKind
    let message: String
    /// Defaulted so the common `Notice(kind:message:)` call compiles: Swift's
    /// memberwise initialiser only supplies defaults for `var`s that have one.
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil
}

/// One queued upload.
private struct UploadJob: Identifiable, Equatable {
    enum Status: Equatable {
        case waiting
        case uploading
        case finished
        case skipped
        case failed(String)
    }

    let id: UUID
    let url: URL
    var destinationName: String
    var status: Status

    var isInFlight: Bool { status == .waiting || status == .uploading }
    var didSucceed: Bool { status == .finished }
    var didFail: Bool {
        if case .failed = status { return true }
        return false
    }

    var statusLabel: String {
        switch status {
        case .waiting: return "Waiting"
        case .uploading: return "Uploading…"
        case .finished: return "Uploaded"
        case .skipped: return "Skipped"
        case .failed(let reason): return reason
        }
    }

    var statusTint: Color {
        switch status {
        case .waiting, .uploading: return Palette.textSecondary
        case .finished: return Palette.healthy
        case .skipped: return Palette.textMuted
        case .failed: return Palette.critical
        }
    }
}

/// A file fetched from the server and waiting for the save panel.
private struct DownloadPayload {
    let name: String
    let data: Data
}

/// The inspector's text preview.
private enum PreviewLoad: Equatable {
    case idle
    case loading
    case loaded(String)
    case tooLarge
    case failed(String)
}

/// The saved form of a downloaded file: exactly the bytes the agent sent.
private struct FileDownloadDocument: FileDocument {
    static var readableContentTypes: [UTType] { [.data] }

    let data: Data

    init(data: Data) { self.data = data }

    init(configuration: ReadConfiguration) throws {
        data = configuration.file.regularFileContents ?? Data()
    }

    func fileWrapper(configuration: WriteConfiguration) throws -> FileWrapper {
        FileWrapper(regularFileWithContents: data)
    }
}

// MARK: - Name sheet

/// New Folder, New File and Rename are the same sheet with different words.
///
/// The validation is the point: a name with a slash in it, an empty name or
/// `..` all fail on the server with a message about paths, which is not a
/// sentence anyone should have to read to learn they typed a slash.
private struct NameSheet: View {
    let title: String
    let explanation: String
    let confirmTitle: String
    let initialName: String
    let existingNames: Set<String>
    let onConfirm: (String) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @FocusState private var isFieldFocused: Bool

    /// Written out rather than left to the memberwise initialiser, which a
    /// private `@State` property would otherwise make private too — the same
    /// reason `RenameServerSheet` spells its own out.
    init(
        title: String,
        explanation: String,
        confirmTitle: String,
        initialName: String,
        existingNames: Set<String>,
        onConfirm: @escaping (String) -> Void
    ) {
        self.title = title
        self.explanation = explanation
        self.confirmTitle = confirmTitle
        self.initialName = initialName
        self.existingNames = existingNames
        self.onConfirm = onConfirm
        _name = State(initialValue: initialName)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(title)
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                    .accessibilityAddTraits(.isHeader)
                Text(explanation)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            TextField("Name", text: $name)
                .textFieldStyle(.roundedBorder)
                .font(Typography.body)
                .focused($isFieldFocused)
                .onSubmit { if problem == nil { confirm() } }
                .accessibilityLabel("Name")

            // Written out rather than with the `if let x` shorthand: these are
            // computed properties, and the long form leaves no doubt.
            if let problem = problem {
                InlineBanner(.error, problem)
            } else if let caution = caution {
                InlineBanner(.warning, caution)
            }

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Button(confirmTitle) { confirm() }
                    .buttonStyle(.primary)
                    .disabled(problem != nil)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(Spacing.screen)
        .frame(width: 440)
        .background(Palette.background)
        .onAppear { isFieldFocused = true }
    }

    /// Blocking problems, in the order a person hits them.
    private var problem: String? {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "Give it a name." }
        if trimmed.contains("/") {
            return "A name can't contain a slash — that would put it in another folder."
        }
        if trimmed == "." || trimmed == ".." {
            return "“\(trimmed)” is reserved by the filesystem for this folder and its parent."
        }
        if trimmed.utf8.count > 255 {
            return "Linux limits a name to 255 bytes. This one is \(trimmed.utf8.count)."
        }
        if trimmed != initialName, existingNames.contains(trimmed) {
            return "Something called “\(trimmed)” is already in this folder."
        }
        return nil
    }

    /// Worth saying, not worth blocking.
    private var caution: String? {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard trimmed.hasPrefix("."), trimmed != initialName else { return nil }
        return "Names starting with a dot are hidden. Turn on hidden items to see it afterwards."
    }

    private func confirm() {
        let trimmed = name.trimmingCharacters(in: .whitespaces)
        guard problem == nil else { return }
        onConfirm(trimmed)
        dismiss()
    }
}

// MARK: - Permissions sheet

/// The familiar owner/group/other × read/write/execute grid.
///
/// setuid, setgid and the sticky bit are deliberately absent: the agent refuses
/// to set them, and a checkbox that always fails is worse than no checkbox. The
/// sheet says so rather than leaving a gap someone has to discover.
private struct PermissionsSheet: View {
    let target: String
    let isDirectory: Bool
    let initialMode: UInt32
    let onApply: (UInt32) -> Void

    @Environment(\.dismiss) private var dismiss

    @State private var ownerRead = false
    @State private var ownerWrite = false
    @State private var ownerExecute = false
    @State private var groupRead = false
    @State private var groupWrite = false
    @State private var groupExecute = false
    @State private var otherRead = false
    @State private var otherWrite = false
    @State private var otherExecute = false

    init(
        target: String,
        isDirectory: Bool,
        initialMode: UInt32,
        onApply: @escaping (UInt32) -> Void
    ) {
        self.target = target
        self.isDirectory = isDirectory
        self.initialMode = initialMode
        self.onApply = onApply
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Permissions for \(target)")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                    .accessibilityAddTraits(.isHeader)
                Text(isDirectory
                     ? "On a folder, execute means “can enter it”. Applies to this folder only, not to what is inside."
                     : "Who on the server can read this file, change it, and run it.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            grid

            HStack(alignment: .firstTextBaseline, spacing: Spacing.element) {
                Text("Result")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                Text(Formatting.fileMode(mode))
                    .font(Typography.metric)
                    .foregroundStyle(Palette.textPrimary)
                    .contentTransition(.numericText())
                Text(Formatting.modeString(mode, isDirectory: isDirectory, isSymlink: false))
                    .font(Typography.code)
                    .foregroundStyle(Palette.textMuted)
                Spacer(minLength: 0)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Resulting mode \(Formatting.fileMode(mode))")

            InlineBanner(
                .info,
                "ServerOS doesn't offer setuid, setgid or the sticky bit. The agent refuses to set them, because a mistake there is a privilege-escalation bug rather than a permissions mistake."
            )

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Button("Apply") {
                    onApply(mode)
                    dismiss()
                }
                .buttonStyle(.primary)
                .disabled(mode == (initialMode & 0o777))
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(Spacing.screen)
        .frame(width: 480)
        .background(Palette.background)
        .onAppear(perform: seed)
    }

    private var grid: some View {
        Grid(alignment: .leading, horizontalSpacing: Spacing.section, verticalSpacing: Spacing.element) {
            GridRow {
                Text("")
                Text("Read").font(Typography.metadata).foregroundStyle(Palette.textSecondary)
                Text("Write").font(Typography.metadata).foregroundStyle(Palette.textSecondary)
                Text("Execute").font(Typography.metadata).foregroundStyle(Palette.textSecondary)
            }
            row("Owner", read: $ownerRead, write: $ownerWrite, execute: $ownerExecute)
            row("Group", read: $groupRead, write: $groupWrite, execute: $groupExecute)
            row("Everyone", read: $otherRead, write: $otherWrite, execute: $otherExecute)
        }
    }

    private func row(
        _ label: String,
        read: Binding<Bool>,
        write: Binding<Bool>,
        execute: Binding<Bool>
    ) -> some View {
        GridRow {
            Text(label)
                .font(Typography.body)
                .foregroundStyle(Palette.textPrimary)
            Toggle("", isOn: read)
                .labelsHidden()
                .accessibilityLabel("\(label) can read")
            Toggle("", isOn: write)
                .labelsHidden()
                .accessibilityLabel("\(label) can write")
            Toggle("", isOn: execute)
                .labelsHidden()
                .accessibilityLabel("\(label) can execute")
        }
    }

    private var mode: UInt32 {
        var value: UInt32 = 0
        if ownerRead { value |= 0o400 }
        if ownerWrite { value |= 0o200 }
        if ownerExecute { value |= 0o100 }
        if groupRead { value |= 0o040 }
        if groupWrite { value |= 0o020 }
        if groupExecute { value |= 0o010 }
        if otherRead { value |= 0o004 }
        if otherWrite { value |= 0o002 }
        if otherExecute { value |= 0o001 }
        return value
    }

    private func seed() {
        let bits = initialMode & 0o777
        ownerRead = bits & 0o400 != 0
        ownerWrite = bits & 0o200 != 0
        ownerExecute = bits & 0o100 != 0
        groupRead = bits & 0o040 != 0
        groupWrite = bits & 0o020 != 0
        groupExecute = bits & 0o010 != 0
        otherRead = bits & 0o004 != 0
        otherWrite = bits & 0o002 != 0
        otherExecute = bits & 0o001 != 0
    }
}

// MARK: - Upload conflict sheet

/// Replace, Keep Both or Skip.
///
/// Not `confirmDestructive`, which is a two-button confirmation and cannot
/// offer the third choice — and the third choice is the one that makes this
/// safe. Replace still carries the destructive styling and names what it
/// overwrites, which is what the rule is actually for.
private struct UploadConflictSheet: View {
    enum Resolution { case replace, keepBoth, skip }

    let fileName: String
    let folder: String
    let keepBothName: String
    let onResolve: (Resolution) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("“\(fileName)” is already in this folder")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(2)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityAddTraits(.isHeader)
                Text(folder)
                    .font(Typography.code)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            VStack(alignment: .leading, spacing: Spacing.snug) {
                Text("Replacing it overwrites the copy on the server, and ServerOS can't put the old one back.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("Keeping both uploads yours as “\(keepBothName)”.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            HStack(spacing: Spacing.element) {
                Button("Skip") { onResolve(.skip) }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Spacer(minLength: Spacing.element)
                Button("Keep Both") { onResolve(.keepBoth) }
                    .buttonStyle(.secondary)
                Button("Replace") { onResolve(.replace) }
                    .buttonStyle(.destructive)
            }
        }
        .padding(Spacing.screen)
        .frame(width: 460)
        .background(Palette.background)
    }
}

// MARK: - Preview

private struct FilesPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        FilesSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 1040, height: 660)
            .onAppear { session.connect() }
    }
}

#Preview("Files") {
    FilesPreviewHost()
}
