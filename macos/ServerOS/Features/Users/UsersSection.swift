//  UsersSection.swift
//  ServerOS
//
//  Who can get into this server, and what can they do once they are in?
//
//  A Linux box answers that badly. `cat /etc/passwd` on a stock Ubuntu install
//  returns about thirty accounts, of which three belong to people and the rest
//  belong to packages. So the single most important decision on this screen is
//  the split: **People** first, **System accounts** collapsed underneath. If
//  twenty-four daemons bury the three humans, the screen has failed at the one
//  job it has.
//
//  Two other decisions are worth knowing about:
//
//  * **Nil is "Unknown", never false.** `locked`, `hasPassword` and
//    `sshKeyCount` are optional on the wire, and the agent sends nothing when it
//    cannot read `/etc/shadow` — which is the normal case for an agent that is
//    not running as root. Rendering that as "Unlocked" would be a security lie:
//    someone would read "unlocked, no password" and conclude an account is open
//    when in fact we simply could not see. So nil renders as a muted "Unknown"
//    and the inspector says so in words.
//  * **Deleting a person is the most dangerous thing here**, and it is the only
//    action offered twice — with and without the home directory — because those
//    are genuinely different decisions and hiding one behind a checkbox inside a
//    confirmation makes it too easy to get wrong. root, system accounts and
//    anything below uid 1000 are refused outright, with a sentence explaining
//    why rather than a disabled button that just sits there.

import Combine
import SwiftUI

/// The local accounts on one server: people, system accounts, keys and access.
public struct UsersSection: View {

    private let session: ServerSession
    private let navigation: NavigationModel

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var state: ScreenState<UserDirectory> = .loading
    /// The server's groups, used by the editor so group membership is a choice
    /// from what exists rather than a free-text field that can invent a group.
    @State private var serverGroups: [LinuxGroup] = []
    @State private var searchText = ""
    /// System accounts start closed. That is the whole point of the screen.
    @State private var isShowingSystemAccounts = false
    @State private var selectedUser: String?
    @State private var reloadNonce = 0
    @State private var isAddingUser = false
    @State private var notice: String?

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            header

            if let notice {
                InlineBanner(.success, notice, actionTitle: "Dismiss") {
                    self.notice = nil
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.bottom, Spacing.element)
            }

            Divider().overlay(Palette.divider)

            content
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .animation(Motion.honouring(reduceMotion, Motion.appear), value: notice)
        .task(id: loadKey) { await load() }
        .onAppear { honourRequestedSelection() }
        .onChange(of: navigation.selectedUserName) { _, _ in honourRequestedSelection() }
        // The request usually arrives before the accounts do, so the list
        // landing is the other moment worth checking.
        .onChange(of: allUsernames) { _, _ in honourRequestedSelection() }
        .onChange(of: session.capabilities) { _, _ in reloadNonce += 1 }
        .onChange(of: session.phase.isReady) { _, isReady in
            if isReady { reloadNonce += 1 }
        }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            reloadNonce += 1
        }
        .sheet(isPresented: $isAddingUser) {
            AddUserSheet(
                session: session,
                existingUsernames: allUsernames,
                availableGroups: serverGroups.map(\.name),
                administratorGroup: administratorGroup
            ) { createdUsername in
                notice = "\(createdUsername) can now sign in to \(session.name)."
                selectedUser = createdUsername
                reloadNonce += 1
            }
        }
        .inspector(isPresented: inspectorBinding) {
            inspectorContent
                .inspectorColumnWidth(min: 320, ideal: 380, max: 520)
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Users")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(countLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Spacer(minLength: Spacing.group)

            if session.capabilities.users {
                SearchField(text: $searchText, prompt: "Search accounts")

                // The one primary action on this screen.
                Button("Add User") { isAddingUser = true }
                    .buttonStyle(.primary)
                    .disabled(session.api == nil)
                    .help(session.api == nil ? "ServerOS isn't connected to this server." : "Create a local account")
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    private var countLine: String {
        guard session.capabilities.users else {
            return "Account management isn't available on \(session.name)."
        }
        guard let directory = state.value else {
            return "Reading the accounts on \(session.name)…"
        }
        let people = directory.people.count
        let system = directory.system.count
        return "\(Formatting.count(people)) \(people == 1 ? "person" : "people") · "
            + "\(Formatting.count(system)) system account\(system == 1 ? "" : "s")"
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        StatefulContent(state, retry: { reloadNonce += 1 }) { directory in
            directoryList(directory)
        } empty: {
            EmptyState(
                systemImage: "person.2",
                title: "No accounts reported",
                message: "\(session.name) returned an empty account list, which is unusual — "
                    + "every Linux server has at least root. The agent may not be able to read /etc/passwd.",
                actionTitle: "Try Again",
                action: { reloadNonce += 1 }
            )
        }
    }

    private func directoryList(_ directory: UserDirectory) -> some View {
        let people = filtered(directory.people)
        let system = filtered(directory.system)

        return ScrollView {
            LazyVStack(alignment: .leading, spacing: 0, pinnedViews: []) {
                SectionHeader("People", count: people.count)
                    .padding(.horizontal, Spacing.group)
                    .padding(.top, Spacing.group)
                    .padding(.bottom, Spacing.element)

                if people.isEmpty {
                    inlineEmpty(
                        searchText.isEmpty
                            ? "No account on \(session.name) can log in interactively."
                            : "No person matches “\(searchText)”."
                    )
                } else {
                    ForEach(people) { user in
                        row(user)
                    }
                }

                systemSection(system)
            }
            .padding(.horizontal, Spacing.card)
            .padding(.bottom, Spacing.card)
        }
    }

    @ViewBuilder
    private func systemSection(_ system: [LinuxUser]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(Motion.honouring(reduceMotion, Motion.appear)) {
                    isShowingSystemAccounts.toggle()
                }
            } label: {
                HStack(spacing: Spacing.snug) {
                    Image(systemName: isShowingSystemAccounts ? "chevron.down" : "chevron.right")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(Palette.textMuted)
                        .accessibilityHidden(true)
                    Text("System accounts")
                        .font(Typography.sectionTitle)
                        .foregroundStyle(Palette.textPrimary)
                    Text(Formatting.count(system.count))
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                        .accessibilityHidden(true)
                    Spacer(minLength: 0)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityLabel("System accounts, \(system.count) items")
            .accessibilityValue(isShowingSystemAccounts ? "Expanded" : "Collapsed")
            .accessibilityAddTraits(.isHeader)

            Text("Accounts owned by installed software. They exist so daemons can run without root, "
                 + "and they are not meant to be signed into.")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, Spacing.tight)

            if isShowingSystemAccounts {
                if system.isEmpty {
                    inlineEmpty(
                        searchText.isEmpty
                            ? "This server reported no system accounts."
                            : "No system account matches “\(searchText)”."
                    )
                } else {
                    ForEach(system) { user in
                        row(user)
                    }
                }
            }
        }
        .padding(.horizontal, Spacing.group)
        .padding(.top, Spacing.section)
    }

    private func row(_ user: LinuxUser) -> some View {
        UserRow(
            user: user,
            isSelected: selectedUser == user.username,
            onSelect: { selectedUser = user.username }
        )
    }

    private func inlineEmpty(_ message: String) -> some View {
        Text(message)
            .font(Typography.secondary)
            .foregroundStyle(Palette.textSecondary)
            .fixedSize(horizontal: false, vertical: true)
            .padding(.vertical, Spacing.group)
            .padding(.horizontal, Spacing.group)
    }

    // MARK: - Inspector

    @ViewBuilder
    private var inspectorContent: some View {
        // `account` rather than `user`, so the binding cannot be confused with
        // the `user(named:)` lookup it comes from.
        if let username = selectedUser, let account = user(named: username) {
            UserInspector(
                session: session,
                user: account,
                serverGroups: serverGroups,
                administratorGroup: administratorGroup,
                onChanged: { message in
                    notice = message
                    reloadNonce += 1
                },
                onDeleted: { message in
                    notice = message
                    selectedUser = nil
                    reloadNonce += 1
                }
            )
            // A fresh editor per account: without this the draft from the
            // previously selected user would survive into the next one.
            .id(username)
        } else {
            EmptyState(
                systemImage: "person.crop.circle",
                title: "No account selected",
                message: "Choose an account to see its groups, its SSH keys and what it is allowed to do."
            )
        }
    }

    private var inspectorBinding: Binding<Bool> {
        Binding(
            get: { selectedUser != nil },
            set: { isPresented in
                if !isPresented { selectedUser = nil }
            }
        )
    }

    // MARK: - Derived

    private func filtered(_ users: [LinuxUser]) -> [LinuxUser] {
        let needle = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        guard !needle.isEmpty else { return users }
        return users.filter { user in
            user.username.lowercased().contains(needle)
                || (user.fullName?.lowercased().contains(needle) ?? false)
        }
    }

    private func user(named name: String) -> LinuxUser? {
        state.value?.all.first { $0.username == name }
    }

    private var allUsernames: [String] {
        state.value?.all.map(\.username) ?? []
    }

    /// Which group grants sudo on this server.
    ///
    /// Debian and Ubuntu use `sudo`; RHEL, Fedora and their relatives use
    /// `wheel`. Asking the server rather than guessing is the difference between
    /// "Administrator" meaning something and it silently doing nothing.
    private var administratorGroup: String {
        let names = Set(serverGroups.map(\.name))
        if names.contains("sudo") { return "sudo" }
        if names.contains("wheel") { return "wheel" }
        return "sudo"
    }

    private func honourRequestedSelection() {
        guard let requested = navigation.selectedUserName else { return }
        // Wait for the list: clearing the request before the accounts arrive
        // would silently drop what ⌘K asked for.
        guard let directory = state.value else { return }
        if directory.all.contains(where: { $0.username == requested }) {
            selectedUser = requested
            searchText = ""
            if directory.system.contains(where: { $0.username == requested }) {
                isShowingSystemAccounts = true
            }
        }
        navigation.selectedUserName = nil
    }

    // MARK: - Loading

    private struct LoadKey: Equatable {
        var serverID: String
        var nonce: Int
    }

    private var loadKey: LoadKey {
        LoadKey(serverID: session.id, nonce: reloadNonce)
    }

    private func load() async {
        guard let api = session.api else {
            if state.value == nil { state = .loading }
            return
        }
        guard session.capabilities.users else {
            state = .unavailable(
                subsystem: "Users",
                reason: "This server's agent can't read the account database, so ServerOS has nothing to show here. "
                    + "The agent needs to be able to read /etc/passwd."
            )
            return
        }

        do {
            let list = try await api.users(includeSystem: true)
            let directory = UserDirectory(list.items)
            state = directory.all.isEmpty ? .empty : .loaded(directory)
            // Groups are a supporting detail: a failure here must not take the
            // account list down with it, so it is fetched separately and its
            // failure only costs the editor its group picker.
            if let fetched = try? await api.groups() {
                serverGroups = fetched
            }
        } catch let error as ServerOSError {
            if state.value == nil { state = .failed(error) }
        } catch {
            if state.value == nil {
                state = .failed(ServerOSError.transport(error, serverName: session.name))
            }
        }
    }
}

// MARK: - Directory

/// The account list, split the way the screen shows it.
private struct UserDirectory {
    let people: [LinuxUser]
    let system: [LinuxUser]

    var all: [LinuxUser] { people + system }

    init(_ users: [LinuxUser]) {
        // `isLoginUser` is the agent's own rule: not a system account, and not
        // pointed at nologin or false. That is the line a person would draw.
        let sorted = users.sorted { $0.username.localizedCaseInsensitiveCompare($1.username) == .orderedAscending }
        people = sorted.filter(\.isLoginUser)
        system = sorted.filter { !$0.isLoginUser }
    }
}

// MARK: - Row

/// One account in the list.
private struct UserRow: View {
    let user: LinuxUser
    let isSelected: Bool
    let onSelect: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.group) {
            Image(systemName: user.isLoginUser ? "person.crop.circle" : "gearshape")
                .font(.system(size: 15, weight: .regular))
                .foregroundStyle(Palette.textMuted)
                .frame(width: 20)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.tight) {
                HStack(spacing: Spacing.snug) {
                    Text(user.username)
                        .font(Typography.body.weight(.medium))
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)

                    if let fullName = user.fullName, !fullName.isEmpty {
                        Text(fullName)
                            .font(Typography.secondary)
                            .foregroundStyle(Palette.textSecondary)
                            .lineLimit(1)
                    }
                }

                // Scan surface, not a record: the row shows what is notable and
                // the inspector states every value precisely, including the ones
                // the agent could not read.
                HStack(spacing: Spacing.tight) {
                    if user.canSudo {
                        Chip("Administrator", tint: Palette.informational, systemImage: "key.fill")
                    }
                    UserSecurityChips(user: user, isCompact: true)
                }

                Text("\(user.home)  ·  \(user.shell)")
                    .font(Typography.codeSmall)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
                    .truncationMode(.middle)
            }

            Spacer(minLength: Spacing.element)

            Text("uid \(Formatting.count(Int(user.uid)))")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .monospacedDigit()
        }
        .padding(.horizontal, Spacing.group)
        .padding(.vertical, Spacing.element)
        .contentShape(Rectangle())
        .hoverHighlight(isSelected: isSelected)
        .onTapGesture(perform: onSelect)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(accessibilitySummary)
        .accessibilityAction(named: Text("Show details"), onSelect)
    }

    /// Not named `accessibilityLabel`: a property with the same name as the
    /// modifier it feeds is a trap for whoever reads this next.
    private var accessibilitySummary: String {
        var parts: [String] = [user.username]
        if let fullName = user.fullName, !fullName.isEmpty { parts.append(fullName) }
        if user.canSudo { parts.append("administrator") }
        parts.append(UserSecurityChips.lockDescription(user.locked))
        return parts.joined(separator: ", ")
    }
}

// MARK: - Security chips

/// The lock / password / key chips, shared by the row and the inspector.
///
/// Every one of these three fields is optional on the wire and nil means "the
/// agent could not tell" — usually because `/etc/shadow` is unreadable to a
/// non-root agent. Claiming an account is unlocked when we cannot see would be
/// a security lie, so nil is always "Unknown" and never a confident negative.
private struct UserSecurityChips: View {
    let user: LinuxUser
    /// Rows show only what is notable; the inspector shows every value.
    let isCompact: Bool

    var body: some View {
        HStack(spacing: Spacing.tight) {
            switch user.locked {
            case .some(true):
                Chip("Locked", tint: Palette.warning, systemImage: "lock.fill")
            case .none:
                Chip("Lock state unknown", tint: Palette.inactive, systemImage: "questionmark")
            case .some(false):
                // Unlocked is the ordinary state; saying so on every row would
                // be noise, and the inspector states it explicitly anyway.
                EmptyView()
            }

            switch user.hasPassword {
            case .some(false):
                Chip("No password", tint: Palette.warning, systemImage: "exclamationmark.shield")
            case .none:
                if !isCompact || user.locked != nil {
                    // In a row, one "unknown" chip is information and two are
                    // noise — when the lock chip already says we cannot read the
                    // shadow file, this would be saying it twice.
                    Chip("Password unknown", tint: Palette.inactive, systemImage: "questionmark")
                }
            case .some(true):
                if !isCompact {
                    Chip("Password set", tint: Palette.inactive, systemImage: "checkmark")
                }
            }

            if let count = user.sshKeyCount, count > 0 {
                Chip("\(Formatting.count(count)) SSH key\(count == 1 ? "" : "s")", tint: Palette.inactive, systemImage: "key")
            } else if user.sshKeyCount == nil, !isCompact {
                Chip("SSH keys unknown", tint: Palette.inactive, systemImage: "questionmark")
            }
        }
    }

    /// The lock state as a sentence, for VoiceOver and for the fact list.
    static func lockDescription(_ locked: Bool?) -> String {
        switch locked {
        case .some(true): return "Locked"
        case .some(false): return "Unlocked"
        case .none: return "Unknown"
        }
    }

    static func passwordDescription(_ hasPassword: Bool?) -> String {
        switch hasPassword {
        case .some(true): return "Set"
        case .some(false): return "Not set"
        case .none: return "Unknown"
        }
    }
}

// MARK: - Inspector

/// One account in full: its facts, its groups, its keys, and the two ways to
/// change it — edit, or delete.
private struct UserInspector: View {
    let session: ServerSession
    let user: LinuxUser
    let serverGroups: [LinuxGroup]
    let administratorGroup: String
    let onChanged: (String) -> Void
    let onDeleted: (String) -> Void

    @State private var draft: UserDraft
    @State private var keys: ScreenState<[SSHKeyEntry]> = .loading
    @State private var keysNonce = 0
    @State private var isWorking = false
    @State private var error: ServerOSError?

    @State private var isAddingKey = false
    @State private var pendingKeyRemoval: SSHKeyEntry?
    @State private var isConfirmingKeyRemoval = false
    @State private var isConfirmingSudo = false
    @State private var isConfirmingLock = false
    @State private var isConfirmingDelete = false
    @State private var isConfirmingDeleteWithHome = false

    init(
        session: ServerSession,
        user: LinuxUser,
        serverGroups: [LinuxGroup],
        administratorGroup: String,
        onChanged: @escaping (String) -> Void,
        onDeleted: @escaping (String) -> Void
    ) {
        self.session = session
        self.user = user
        self.serverGroups = serverGroups
        self.administratorGroup = administratorGroup
        self.onChanged = onChanged
        self.onDeleted = onDeleted
        _draft = State(initialValue: UserDraft(user: user, administratorGroup: administratorGroup))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.between) {
                headline

                if let error {
                    InlineBanner(.error, error.headline, actionTitle: "Dismiss") {
                        self.error = nil
                    }
                }

                facts
                editor
                keysSection
                dangerZone
            }
            .padding(Spacing.card)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Palette.background)
        .task(id: keysNonce) { await loadKeys() }
        .sheet(isPresented: $isAddingKey) {
            AddSSHKeySheet(username: user.username) { publicKey in
                Task { await addKey(publicKey) }
            }
        }
    }

    // MARK: Headline

    private var headline: some View {
        VStack(alignment: .leading, spacing: Spacing.snug) {
            Text(user.username)
                .font(Typography.pageTitle)
                .foregroundStyle(Palette.textPrimary)
                .accessibilityAddTraits(.isHeader)

            if let fullName = user.fullName, !fullName.isEmpty {
                Text(fullName)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
            }

            HStack(spacing: Spacing.tight) {
                if user.canSudo {
                    Chip("Administrator", tint: Palette.informational, systemImage: "key.fill")
                }
                UserSecurityChips(user: user, isCompact: false)
            }

            if isWorking {
                InlineProgress("Applying your change…")
            }
        }
    }

    // MARK: Facts

    // Split into three small groups rather than one long list: a `ViewBuilder`
    // takes at most ten children, and these read as three ideas anyway —
    // who the account is, what it can sign in with, and what it belongs to.
    private var facts: some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader("Account")
                .padding(.bottom, Spacing.snug)

            identityRows
            securityRows
            shadowExplanation
            groupsBlock
        }
    }

    private var identityRows: some View {
        VStack(alignment: .leading, spacing: 0) {
            KeyValueRow("User ID", Formatting.count(Int(user.uid)))
            KeyValueRow("Group ID", Formatting.count(Int(user.gid)))
            KeyValueRow("Home", user.home, monospaced: true, selectable: true)
            KeyValueRow("Shell", user.shell, monospaced: true, selectable: true)
            KeyValueRow("Last login", lastLoginDescription, placeholder: "Unknown")
        }
    }

    private var securityRows: some View {
        VStack(alignment: .leading, spacing: 0) {
            KeyValueRow("Password login", UserSecurityChips.lockDescription(user.locked))
            KeyValueRow("Password", UserSecurityChips.passwordDescription(user.hasPassword))
            KeyValueRow("SSH keys", user.sshKeyCount.map { Formatting.count($0) }, placeholder: "Unknown")
        }
    }

    @ViewBuilder
    private var shadowExplanation: some View {
        if user.locked == nil || user.hasPassword == nil {
            Text("ServerOS couldn't read /etc/shadow on this server, so it can't tell you whether this "
                 + "account is locked or has a password. That usually means the agent isn't running as root.")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.top, Spacing.snug)
        }
    }

    @ViewBuilder
    private var groupsBlock: some View {
        if !user.groups.isEmpty {
            VStack(alignment: .leading, spacing: Spacing.tight) {
                Text("Groups")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)

                ChipFlow(items: user.groups) { group in
                    Chip(
                        group,
                        tint: group == administratorGroup ? Palette.informational : Palette.inactive
                    )
                }
            }
            .padding(.top, Spacing.group)
        }
    }

    private var lastLoginDescription: String? {
        guard let last = user.lastLogin, last > 0 else { return nil }
        return Formatting.relative(unixSeconds: last)
    }

    // MARK: Editor

    private var editor: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            SectionHeader("Edit")

            LabelledField("Full name") {
                TextField("", text: $draft.fullName, prompt: Text("Not set"))
                    .textFieldStyle(.roundedBorder)
                    .font(Typography.body)
            }

            LabelledField("Shell") {
                ShellPicker(shell: $draft.shell, customShell: $draft.customShell)
            }

            if !editableGroups.isEmpty {
                LabelledField("Groups") {
                    ChipFlow(items: editableGroups) { group in
                        GroupToggleChip(
                            name: group,
                            isMember: draft.groups.contains(group),
                            isAdministrator: group == administratorGroup
                        ) {
                            toggleGroup(group)
                        }
                    }
                }
            }

            Toggle(isOn: $draft.isAdministrator) {
                Text("Administrator")
                    .font(Typography.body)
            }
            .toggleStyle(.switch)
            .controlSize(.small)

            Text("An administrator can run any command as root with sudo — install software, read any file, "
                 + "and change every other account on \(session.name).")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .fixedSize(horizontal: false, vertical: true)

            HStack(spacing: Spacing.element) {
                Button("Save Changes") { attemptSave() }
                    .buttonStyle(.primary)
                    .disabled(!hasEdits || isWorking || session.api == nil)

                Button("Revert") { draft = UserDraft(user: user, administratorGroup: administratorGroup) }
                    .buttonStyle(.secondary)
                    .disabled(!hasEdits || isWorking)
            }
            // Granting sudo is not an edit like any other, so it gets its own
            // confirmation rather than riding along with a shell change.
            .confirmDestructive(
                isPresented: $isConfirmingSudo,
                title: "Give \(user.username) administrator access?",
                target: user.username,
                consequence: "\(user.username) will be added to the \(administratorGroup) group, which lets them run "
                    + "any command as root on \(session.name) — including changing or deleting every other account.",
                isReversible: true,
                confirmTitle: "Grant Administrator"
            ) {
                Task { await save() }
            }

            lockControls
        }
    }

    /// Lock and unlock are buttons rather than a toggle on purpose: a toggle has
    /// to be either on or off, and when `locked` is nil we do not know which it
    /// is. A switch would have to pick a position, and picking one would be a
    /// lie about a security property.
    @ViewBuilder
    private var lockControls: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Divider().overlay(Palette.divider)

            HStack(spacing: Spacing.element) {
                Text("Password login: \(UserSecurityChips.lockDescription(user.locked))")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)

                Spacer(minLength: Spacing.element)

                if user.locked == true {
                    Button("Unlock") { Task { await setLocked(false) } }
                        .buttonStyle(.secondary)
                        .disabled(isWorking || session.api == nil)
                } else {
                    Button("Lock Account") { isConfirmingLock = true }
                        .buttonStyle(.secondary)
                        .disabled(isWorking || session.api == nil)
                        .confirmDestructive(
                            isPresented: $isConfirmingLock,
                            title: "Lock \(user.username)?",
                            target: user.username,
                            consequence: "\(user.username) will not be able to sign in with a password. "
                                + "Any SSH key they have still works, and anything already running as them keeps running.",
                            isReversible: true,
                            confirmTitle: "Lock Account"
                        ) {
                            Task { await setLocked(true) }
                        }
                }
            }
        }
    }

    // MARK: SSH keys

    private var keysSection: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            SectionHeader("SSH keys") {
                Button("Add Key") { isAddingKey = true }
                    .buttonStyle(.rowAction)
                    .disabled(session.api == nil)
            }

            StatefulContent(keys, retry: { keysNonce += 1 }) { entries in
                VStack(alignment: .leading, spacing: Spacing.snug) {
                    ForEach(entries) { entry in
                        keyRow(entry)
                    }
                }
            } empty: {
                Text("\(user.username) has no authorised keys, so they can only sign in with a password.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .confirmDestructive(
            isPresented: $isConfirmingKeyRemoval,
            title: "Remove this SSH key?",
            target: pendingKeyRemoval?.fingerprint ?? "",
            consequence: "The key \(pendingKeyRemoval?.fingerprint ?? "") will be removed from "
                + "\(user.username)'s authorised keys on \(session.name). Whoever holds that key loses access "
                + "immediately, and if it is the only way they sign in, they are locked out.",
            isReversible: false,
            confirmTitle: "Remove Key"
        ) {
            if let entry = pendingKeyRemoval {
                Task { await removeKey(entry) }
            }
        }
    }

    private func keyRow(_ entry: SSHKeyEntry) -> some View {
        HStack(alignment: .top, spacing: Spacing.element) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(entry.comment ?? "No comment")
                    .font(Typography.secondary)
                    .foregroundStyle(entry.comment == nil ? Palette.textMuted : Palette.textPrimary)
                    .lineLimit(1)
                Text(entry.fingerprint)
                    .font(Typography.codeSmall)
                    .foregroundStyle(Palette.textSecondary)
                    .textSelection(.enabled)
                    .lineLimit(1)
                    .truncationMode(.middle)
                Chip(entry.type, tint: Palette.inactive)
            }

            Spacer(minLength: Spacing.element)

            Button("Remove") {
                pendingKeyRemoval = entry
                isConfirmingKeyRemoval = true
            }
            .buttonStyle(RowActionButtonStyle(tint: Palette.critical))
            .disabled(session.api == nil)
            .accessibilityLabel("Remove key \(entry.fingerprint)")
        }
        .padding(.vertical, Spacing.tight)
    }

    // MARK: Danger zone

    private var dangerZone: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            SectionHeader("Delete")

            if let refusal = deletionRefusal {
                // A disabled button with no explanation teaches nobody anything.
                // Say why, in one sentence, and offer nothing to press.
                Text(refusal)
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Text("Deleting \(user.username) removes the account. Their home directory — \(user.home) — holds "
                     + "their files, their SSH keys and anything they were working on, so it is a separate choice.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)

                HStack(spacing: Spacing.element) {
                    Button("Delete User") { isConfirmingDelete = true }
                        .buttonStyle(.destructive)
                        .disabled(isWorking || session.api == nil)
                        .confirmDestructive(
                            isPresented: $isConfirmingDelete,
                            title: "Delete \(user.username)?",
                            target: user.username,
                            consequence: "The account is removed from \(session.name) and \(user.username) can no "
                                + "longer sign in. Their home directory \(user.home) is left on disk, owned by a user "
                                + "ID that no longer exists.",
                            isReversible: false,
                            confirmTitle: "Delete User"
                        ) {
                            Task { await delete(removeHome: false) }
                        }

                    Button("Delete User and Home Directory") { isConfirmingDeleteWithHome = true }
                        .buttonStyle(.destructive)
                        .disabled(isWorking || session.api == nil)
                        .confirmDestructive(
                            isPresented: $isConfirmingDeleteWithHome,
                            title: "Delete \(user.username) and everything in \(user.home)?",
                            target: user.username,
                            consequence: "The account is removed and \(user.home) is deleted with it — every file "
                                + "\(user.username) owns there, their SSH keys, and anything stored under it. "
                                + "ServerOS has no copy.",
                            isReversible: false,
                            confirmTitle: "Delete User and Files"
                        ) {
                            Task { await delete(removeHome: true) }
                        }
                }
            }
        }
    }

    /// Why this account cannot be deleted from here, if it cannot.
    private var deletionRefusal: String? {
        if user.username == "root" {
            return "ServerOS won't delete root. The server needs it to boot, to run systemd and to let you back in "
                + "if anything else breaks. If you want to stop root logging in, lock the account instead."
        }
        if user.isSystem {
            return "\(user.username) is a system account. It belongs to software installed on this server, which "
                + "will stop working — often silently — if the account it runs as disappears. Remove the package "
                + "instead, and its account goes with it."
        }
        if user.uid < 1000 {
            return "\(user.username) has user ID \(user.uid). Anything below 1000 is reserved for the system on "
                + "Linux, so ServerOS treats it as part of the operating system rather than as a person."
        }
        return nil
    }

    // MARK: Draft

    private var editableGroups: [String] {
        // The account's own primary group is not a choice, and neither is the
        // administrator group — that is what the Administrator switch is for.
        serverGroups
            .map(\.name)
            .filter { $0 != user.username && $0 != administratorGroup }
            .sorted()
    }

    private var hasEdits: Bool { changes(from: draft) != nil }

    private func toggleGroup(_ group: String) {
        if draft.groups.contains(group) {
            draft.groups.remove(group)
        } else {
            draft.groups.insert(group)
        }
    }

    /// The PATCH body, or nil when nothing would change.
    private func changes(from draft: UserDraft) -> UserChanges? {
        var desiredGroups = draft.groups
        if draft.isAdministrator {
            desiredGroups.insert(administratorGroup)
        } else {
            desiredGroups.remove(administratorGroup)
        }

        let trimmedName = draft.fullName.trimmingCharacters(in: .whitespaces)
        let resolvedShell = draft.resolvedShell

        let nameChanged = trimmedName != (user.fullName ?? "")
        let shellChanged = !resolvedShell.isEmpty && resolvedShell != user.shell
        let groupsChanged = desiredGroups != Set(user.groups)

        guard nameChanged || shellChanged || groupsChanged else { return nil }

        let changes = UserChanges(
            fullName: nameChanged ? trimmedName : nil,
            shell: shellChanged ? resolvedShell : nil,
            // The agent takes the complete supplementary group list, not a delta.
            groups: groupsChanged ? desiredGroups.sorted() : nil,
            locked: nil,
            password: nil
        )
        return changes.isEmpty ? nil : changes
    }

    private func attemptSave() {
        let grantsAdministrator = draft.isAdministrator && !user.canSudo
        if grantsAdministrator {
            isConfirmingSudo = true
        } else {
            Task { await save() }
        }
    }

    // MARK: Calls

    private func save() async {
        guard let api = session.api, let body = changes(from: draft) else { return }
        isWorking = true
        error = nil
        do {
            _ = try await api.updateUser(named: user.username, changes: body)
            onChanged("Updated \(user.username).")
        } catch let failure as ServerOSError {
            error = failure
        } catch {
            self.error = ServerOSError.transport(error, serverName: session.name)
        }
        isWorking = false
    }

    private func setLocked(_ locked: Bool) async {
        guard let api = session.api else { return }
        isWorking = true
        error = nil
        do {
            _ = try await api.updateUser(named: user.username, changes: UserChanges(locked: locked))
            onChanged(locked ? "Locked \(user.username)." : "Unlocked \(user.username).")
        } catch let failure as ServerOSError {
            error = failure
        } catch {
            self.error = ServerOSError.transport(error, serverName: session.name)
        }
        isWorking = false
    }

    private func delete(removeHome: Bool) async {
        guard let api = session.api else { return }
        isWorking = true
        error = nil
        do {
            try await api.deleteUser(named: user.username, removeHome: removeHome)
            onDeleted(
                removeHome
                    ? "Deleted \(user.username) and their home directory."
                    : "Deleted \(user.username). Their home directory is still on disk."
            )
        } catch let failure as ServerOSError {
            error = failure
        } catch {
            self.error = ServerOSError.transport(error, serverName: session.name)
        }
        isWorking = false
    }

    private func loadKeys() async {
        guard let api = session.api else {
            keys = .failed(ServerOSError.sshNotConnected)
            return
        }
        do {
            let entries = try await api.sshKeys(forUser: user.username)
            keys = entries.isEmpty ? .empty : .loaded(entries)
        } catch let failure as ServerOSError {
            keys = .failed(failure)
        } catch {
            keys = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }

    private func addKey(_ publicKey: String) async {
        guard let api = session.api else { return }
        isWorking = true
        error = nil
        do {
            try await api.addSSHKey(forUser: user.username, publicKey: publicKey)
            keysNonce += 1
            onChanged("Added an SSH key for \(user.username).")
        } catch let failure as ServerOSError {
            error = failure
        } catch {
            self.error = ServerOSError.transport(error, serverName: session.name)
        }
        isWorking = false
    }

    private func removeKey(_ entry: SSHKeyEntry) async {
        guard let api = session.api else { return }
        isWorking = true
        error = nil
        do {
            try await api.removeSSHKey(forUser: user.username, fingerprint: entry.fingerprint)
            keysNonce += 1
            onChanged("Removed an SSH key from \(user.username).")
        } catch let failure as ServerOSError {
            error = failure
        } catch {
            self.error = ServerOSError.transport(error, serverName: session.name)
        }
        isWorking = false
        pendingKeyRemoval = nil
    }
}

// MARK: - Draft

/// The editable half of an account.
private struct UserDraft {
    var fullName: String
    /// One of the known shells, or `UserDraft.customShellToken`.
    var shell: String
    var customShell: String
    var groups: Set<String>
    var isAdministrator: Bool

    static let customShellToken = "__custom__"

    static let commonShells = ["/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/fish", "/usr/sbin/nologin", "/bin/false"]

    init(user: LinuxUser, administratorGroup: String) {
        fullName = user.fullName ?? ""
        if UserDraft.commonShells.contains(user.shell) {
            shell = user.shell
            customShell = ""
        } else {
            shell = UserDraft.customShellToken
            customShell = user.shell
        }
        groups = Set(user.groups)
        isAdministrator = user.canSudo || user.groups.contains(administratorGroup)
    }

    var resolvedShell: String {
        shell == UserDraft.customShellToken
            ? customShell.trimmingCharacters(in: .whitespaces)
            : shell
    }
}

// MARK: - Add user

/// Creating an account, with every field validated before the button lights up.
private struct AddUserSheet: View {
    @Environment(\.dismiss) private var dismiss

    let session: ServerSession
    let existingUsernames: [String]
    let availableGroups: [String]
    let administratorGroup: String
    let onCreated: (String) -> Void

    // Explicit, because a struct with private stored properties — every `@State`
    // below is one — gets a private memberwise initialiser.
    init(
        session: ServerSession,
        existingUsernames: [String],
        availableGroups: [String],
        administratorGroup: String,
        onCreated: @escaping (String) -> Void
    ) {
        self.session = session
        self.existingUsernames = existingUsernames
        self.availableGroups = availableGroups
        self.administratorGroup = administratorGroup
        self.onCreated = onCreated
    }

    /// How the new account will be able to sign in. One or the other — an
    /// account with neither cannot log in at all, and silently creating one is
    /// a support ticket waiting to happen.
    private enum Credential: String, CaseIterable {
        case sshKey, password

        var title: String {
            switch self {
            case .sshKey: return "SSH key"
            case .password: return "Password"
            }
        }
    }

    @State private var username = ""
    @State private var fullName = ""
    @State private var shell = "/bin/bash"
    @State private var customShell = ""
    @State private var createsHome = true
    @State private var isAdministrator = false
    @State private var credential: Credential = .sshKey
    @State private var publicKey = ""
    @State private var password = ""
    @State private var isWorking = false
    @State private var error: ServerOSError?
    @State private var partialFailure: String?

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            Text("Add User")
                .font(Typography.pageTitle)
                .foregroundStyle(Palette.textPrimary)
                .accessibilityAddTraits(.isHeader)

            Text("Creates a local account on \(session.name).")
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)

            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.group) {
                    identityFields
                    Divider().overlay(Palette.divider)
                    accessFields
                }
                .padding(.vertical, Spacing.tight)
            }
            .frame(maxHeight: 400)

            if let partialFailure {
                InlineBanner(.warning, partialFailure)
            }

            if let error {
                InlineBanner(.error, error.headline)
            }

            HStack(spacing: Spacing.element) {
                if isWorking {
                    InlineProgress("Creating \(username)…")
                }
                Spacer(minLength: Spacing.element)
                Button("Cancel") { dismiss() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Button("Create User") { Task { await create() } }
                    .buttonStyle(.primary)
                    .disabled(!isValid || isWorking)
            }
        }
        .padding(Spacing.screen)
        .frame(width: 460)
        .background(Palette.background)
    }

    // MARK: Fields

    private var identityFields: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            LabelledField("Username") {
                TextField("", text: $username, prompt: Text("jordan"))
                    .textFieldStyle(.roundedBorder)
                    .font(Typography.code)
            }

            if let message = usernameProblem, !username.isEmpty {
                FieldMessage(message, kind: .error)
            } else if !username.isEmpty {
                FieldMessage("Home directory will be /home/\(username).", kind: .hint)
            } else {
                FieldMessage("Lowercase letters, digits, underscore and hyphen; must start with a letter or underscore.", kind: .hint)
            }

            LabelledField("Full name") {
                TextField("", text: $fullName, prompt: Text("Optional"))
                    .textFieldStyle(.roundedBorder)
                    .font(Typography.body)
            }

            LabelledField("Shell") {
                ShellPicker(shell: $shell, customShell: $customShell)
            }

            Toggle(isOn: $createsHome) {
                Text("Create a home directory").font(Typography.body)
            }
            .toggleStyle(.switch)
            .controlSize(.small)
        }
    }

    private var accessFields: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            Toggle(isOn: $isAdministrator) {
                Text("Administrator").font(Typography.body)
            }
            .toggleStyle(.switch)
            .controlSize(.small)

            if isAdministrator {
                InlineBanner(
                    .warning,
                    "Adds \(username.isEmpty ? "this account" : username) to the \(administratorGroup) group. "
                        + "They will be able to run any command as root on \(session.name), read any file on it, "
                        + "and change or delete any other account."
                )
            }

            Picker("Sign in with", selection: $credential) {
                ForEach(Credential.allCases, id: \.self) { option in
                    Text(option.title).tag(option)
                }
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            switch credential {
            case .sshKey:
                keyField
            case .password:
                passwordField
            }
        }
    }

    private var keyField: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Text("Public key")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)

            TextEditor(text: $publicKey)
                .font(Typography.codeSmall)
                .frame(height: 72)
                .padding(Spacing.tight)
                .background(Palette.surfaceElevated, in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                        .strokeBorder(Palette.divider, lineWidth: 0.5)
                )
                .accessibilityLabel("SSH public key")

            if let problem = PublicKeyValidation.problem(with: publicKey) {
                FieldMessage(problem, kind: .error)
            } else if publicKey.isEmpty {
                FieldMessage("Paste the contents of a .pub file — the one that starts ssh-ed25519 or ssh-rsa.", kind: .hint)
            } else {
                FieldMessage("Looks like a valid OpenSSH public key.", kind: .success)
            }
        }
    }

    private var passwordField: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Text("Password")
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)

            // A secure field, and the value is never rendered back anywhere —
            // not in a hint, not in the confirmation, not in the activity feed.
            SecureField("", text: $password, prompt: Text("Required"))
                .textFieldStyle(.roundedBorder)
                .font(Typography.body)
                .accessibilityLabel("Password")

            if password.isEmpty {
                FieldMessage("Set once, sent straight to the server, and never stored by ServerOS.", kind: .hint)
            } else {
                let strength = PasswordStrength.of(password)
                FieldMessage(strength.advice, kind: strength.messageKind)
            }
        }
    }

    // MARK: Validation

    private var usernameProblem: String? {
        UsernameValidation.problem(with: username, existing: existingUsernames)
    }

    private var isValid: Bool {
        guard !username.isEmpty, usernameProblem == nil else { return false }
        switch credential {
        case .sshKey:
            return !publicKey.isEmpty && PublicKeyValidation.problem(with: publicKey) == nil
        case .password:
            return password.count >= 8
        }
    }

    // MARK: Creation

    private func create() async {
        guard let api = session.api else {
            error = ServerOSError.sshNotConnected
            return
        }
        isWorking = true
        error = nil
        partialFailure = nil

        var groups: [String] = []
        if isAdministrator { groups.append(administratorGroup) }

        let resolvedShell = shell == UserDraft.customShellToken
            ? customShell.trimmingCharacters(in: .whitespaces)
            : shell

        let request = NewUser(
            username: username,
            fullName: fullName.isEmpty ? nil : fullName,
            shell: resolvedShell.isEmpty ? nil : resolvedShell,
            groups: groups.isEmpty ? nil : groups,
            createHome: createsHome,
            password: credential == .password ? password : nil
        )

        do {
            _ = try await api.createUser(request)

            // The agent has no "create with key" call, so the key is a second
            // request. If it fails we say so precisely rather than reporting a
            // failure that would suggest the account was not created.
            if credential == .sshKey {
                do {
                    try await api.addSSHKey(forUser: username, publicKey: publicKey.trimmingCharacters(in: .whitespacesAndNewlines))
                } catch {
                    partialFailure = "\(username) was created, but the SSH key wasn't added. "
                        + "Open the account and add the key again."
                    isWorking = false
                    onCreated(username)
                    return
                }
            }

            isWorking = false
            onCreated(username)
            dismiss()
        } catch let failure as ServerOSError {
            error = failure
            isWorking = false
        } catch {
            self.error = ServerOSError.transport(error, serverName: session.name)
            isWorking = false
        }
    }
}

// MARK: - Add key

/// Adding one public key to an existing account.
private struct AddSSHKeySheet: View {
    @Environment(\.dismiss) private var dismiss

    let username: String
    let onAdd: (String) -> Void

    @State private var publicKey = ""

    init(username: String, onAdd: @escaping (String) -> Void) {
        self.username = username
        self.onAdd = onAdd
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            Text("Add SSH Key")
                .font(Typography.pageTitle)
                .foregroundStyle(Palette.textPrimary)
                .accessibilityAddTraits(.isHeader)

            Text("Authorises a key for \(username). Anyone holding the matching private key can sign in as them.")
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            TextEditor(text: $publicKey)
                .font(Typography.codeSmall)
                .frame(height: 96)
                .padding(Spacing.tight)
                .background(Palette.surfaceElevated, in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
                .overlay(
                    RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                        .strokeBorder(Palette.divider, lineWidth: 0.5)
                )
                .accessibilityLabel("SSH public key")

            if let problem = PublicKeyValidation.problem(with: publicKey) {
                FieldMessage(problem, kind: .error)
            } else if publicKey.isEmpty {
                FieldMessage("Paste the contents of a .pub file.", kind: .hint)
            } else {
                FieldMessage("Looks like a valid OpenSSH public key.", kind: .success)
            }

            HStack {
                Spacer(minLength: Spacing.element)
                Button("Cancel") { dismiss() }
                    .buttonStyle(.secondary)
                    .keyboardShortcut(.cancelAction)
                Button("Add Key") {
                    onAdd(publicKey.trimmingCharacters(in: .whitespacesAndNewlines))
                    dismiss()
                }
                .buttonStyle(.primary)
                .disabled(publicKey.isEmpty || PublicKeyValidation.problem(with: publicKey) != nil)
            }
        }
        .padding(Spacing.screen)
        .frame(width: 460)
        .background(Palette.background)
    }
}

// MARK: - Validation

/// `^[a-z_][a-z0-9_-]{0,31}$`, checked by hand so each failure can say exactly
/// what is wrong rather than "invalid username".
private enum UsernameValidation {

    static func problem(with username: String, existing: [String]) -> String? {
        guard !username.isEmpty else { return "A username is required." }
        guard username.count <= 32 else {
            return "Usernames can be at most 32 characters. This one is \(username.count)."
        }

        let first = username[username.startIndex]
        guard first.isLowercaseLetter || first == "_" else {
            if first.isUppercase {
                return "Usernames must be lowercase. Try “\(username.lowercased())”."
            }
            return "Usernames must start with a lowercase letter or an underscore."
        }

        let invalid = Set(username.filter { !$0.isAllowedInUsername })
        if !invalid.isEmpty {
            let list = invalid.sorted().map { "“\($0)”" }.joined(separator: ", ")
            return "Usernames can't contain \(list). Use lowercase letters, digits, underscore or hyphen."
        }

        if existing.contains(username) {
            return "There is already an account called \(username) on this server."
        }
        return nil
    }
}

extension Character {
    fileprivate var isLowercaseLetter: Bool { isLetter && isLowercase }

    fileprivate var isAllowedInUsername: Bool {
        (isLetter && isLowercase) || isNumber || self == "_" || self == "-"
    }
}

/// What an OpenSSH public key looks like, and — much more importantly — what a
/// private key looks like.
private enum PublicKeyValidation {

    private static let knownPrefixes = [
        "ssh-ed25519",
        "ssh-rsa",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
        "sk-ssh-ed25519@openssh.com",
        "sk-ecdsa-sha2-nistp256@openssh.com",
    ]

    /// Nil when the text is a plausible public key.
    static func problem(with text: String) -> String? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }  // "empty" is not yet "wrong"

        // This is the mistake that actually happens, and it is serious: someone
        // opens ~/.ssh/id_ed25519 instead of ~/.ssh/id_ed25519.pub and pastes
        // their private key into a text field. Say so loudly.
        if trimmed.hasPrefix("-----BEGIN") || trimmed.contains("PRIVATE KEY") {
            return "That is a private key — do not paste it here, or anywhere else. "
                + "A private key is the secret half; anyone who has it can sign in as you. "
                + "Use the matching .pub file instead, and if this key has left your Mac, replace it."
        }

        if trimmed.hasPrefix("PuTTY-User-Key-File") {
            return "That is a PuTTY key file. Export it as an OpenSSH public key first."
        }

        let fields = trimmed.split(separator: " ", omittingEmptySubsequences: true)
        guard let algorithm = fields.first.map(String.init) else {
            return "That doesn't look like an SSH public key."
        }

        guard knownPrefixes.contains(where: { algorithm == $0 || algorithm.hasPrefix("ecdsa-sha2-") }) else {
            return "“\(Formatting.truncate(algorithm, to: 24))” isn't an SSH key type ServerOS recognises. "
                + "A public key starts with ssh-ed25519, ecdsa-sha2-… or ssh-rsa."
        }

        guard fields.count >= 2 else {
            return "This key is missing its body. A public key is one line: the type, the key itself, then a comment."
        }

        let body = String(fields[1])
        guard body.count >= 32, body.hasPrefix("AAAA") else {
            return "The key body doesn't look like base64 — it should be a long run of letters and digits starting AAAA."
        }

        if trimmed.contains("\n") {
            return "A public key is a single line. This has line breaks in it, which usually means part of a file "
                + "was copied rather than the key itself."
        }
        return nil
    }
}

/// A deliberately blunt strength read: length first, because length is what
/// actually matters, then whether there is more than one kind of character.
private enum PasswordStrength {
    case tooShort, weak, fair, strong

    static func of(_ password: String) -> PasswordStrength {
        guard password.count >= 8 else { return .tooShort }
        var classes = 0
        if password.contains(where: { $0.isLowercase }) { classes += 1 }
        if password.contains(where: { $0.isUppercase }) { classes += 1 }
        if password.contains(where: { $0.isNumber }) { classes += 1 }
        if password.contains(where: { !$0.isLetter && !$0.isNumber }) { classes += 1 }

        if password.count >= 16 || (password.count >= 12 && classes >= 3) { return .strong }
        if password.count >= 12 || classes >= 3 { return .fair }
        return .weak
    }

    var advice: String {
        switch self {
        case .tooShort: return "Too short — use at least 8 characters, and preferably more than 12."
        case .weak: return "Weak. A longer passphrase is stronger than a short password with symbols in it."
        case .fair: return "Reasonable. Longer is still better than more symbols."
        case .strong: return "Strong."
        }
    }

    var messageKind: FieldMessage.Kind {
        switch self {
        case .tooShort, .weak: return .error
        case .fair: return .hint
        case .strong: return .success
        }
    }
}

// MARK: - Small shared controls

/// A label above a control, which is the form layout used throughout the app.
private struct LabelledField<Content: View>: View {
    private let label: String
    private let content: Content

    init(_ label: String, @ViewBuilder content: () -> Content) {
        self.label = label
        self.content = content()
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Text(label)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)
            content
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel(label)
    }
}

/// The one-line message under a field: a hint, a problem, or a confirmation.
private struct FieldMessage: View {
    enum Kind { case hint, error, success }

    private let message: String
    private let kind: Kind

    init(_ message: String, kind: Kind) {
        self.message = message
        self.kind = kind
    }

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.tight) {
            Image(systemName: symbol)
                .font(.system(size: 9, weight: .semibold))
                .foregroundStyle(tint)
                .accessibilityHidden(true)
            Text(message)
                .font(Typography.metadata)
                .foregroundStyle(kind == .hint ? Palette.textMuted : tint)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .combine)
    }

    private var tint: Color {
        switch kind {
        case .hint: return Palette.textMuted
        case .error: return Palette.critical
        case .success: return Palette.healthy
        }
    }

    private var symbol: String {
        switch kind {
        case .hint: return "info.circle"
        case .error: return "exclamationmark.circle.fill"
        case .success: return "checkmark.circle.fill"
        }
    }
}

/// The shell picker, with an escape hatch for the shells we did not list.
private struct ShellPicker: View {
    @Binding var shell: String
    @Binding var customShell: String

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.tight) {
            Picker("", selection: $shell) {
                ForEach(UserDraft.commonShells, id: \.self) { option in
                    Text(option).tag(option)
                }
                Text("Other…").tag(UserDraft.customShellToken)
            }
            .labelsHidden()
            .font(Typography.body)
            .accessibilityLabel("Login shell")

            if shell == UserDraft.customShellToken {
                TextField("", text: $customShell, prompt: Text("/usr/local/bin/somesh"))
                    .textFieldStyle(.roundedBorder)
                    .font(Typography.code)
                    .accessibilityLabel("Custom shell path")
            }
        }
    }
}

/// A group chip that can be switched on and off.
private struct GroupToggleChip: View {
    let name: String
    let isMember: Bool
    let isAdministrator: Bool
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Chip(
                name,
                tint: isMember ? (isAdministrator ? Palette.informational : Palette.accent) : Palette.inactive,
                systemImage: isMember ? "checkmark" : nil
            )
            .opacity(isMember ? 1 : 0.6)
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Group \(name)")
        .accessibilityValue(isMember ? "Member" : "Not a member")
        .accessibilityAddTraits(isMember ? [.isButton, .isSelected] : .isButton)
    }
}

/// Chips that wrap onto as many lines as they need.
///
/// `LazyVGrid` with adaptive columns is the only wrapping layout available
/// without a custom `Layout`, and a custom `Layout` for eight group names would
/// be more machinery than the problem deserves.
private struct ChipFlow<Item: Hashable, Content: View>: View {
    let items: [Item]
    let content: (Item) -> Content

    init(items: [Item], @ViewBuilder content: @escaping (Item) -> Content) {
        self.items = items
        self.content = content
    }

    var body: some View {
        LazyVGrid(
            columns: [GridItem(.adaptive(minimum: 84, maximum: 200), spacing: Spacing.tight, alignment: .leading)],
            alignment: .leading,
            spacing: Spacing.tight
        ) {
            ForEach(items, id: \.self) { item in
                content(item)
            }
        }
    }
}

// MARK: - Preview

private struct UsersPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        UsersSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 1000, height: 640)
            .onAppear { session.connect() }
    }
}

#Preview("Users") {
    UsersPreviewHost()
}
