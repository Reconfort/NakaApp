//  ServicesSection.swift
//  ServerOS
//
//  "What is running on this machine, and what has fallen over?"
//
//  This screen exists to replace `systemctl list-units --failed`, and the order
//  of everything on it follows from that. Three decisions are worth knowing
//  about before reading the code:
//
//  * **Failed comes first, and looks it.** A failed unit is the single most
//    actionable thing a server can tell you, so it leads the summary strip, it
//    is the only tile that is ever filled with colour, and it is a filter rather
//    than a statistic — one click and the list is exactly the problem.
//  * **The list is read from the live stream, not re-fetched.** `session.services`
//    is kept current by the services channel that `ServerDetailScreen` subscribes
//    to for this section. Polling it as well would double the traffic down the
//    SSH tunnel and still be slower to notice a change.
//  * **Actions are optimistic, and the stream is the source of truth.** Clicking
//    Restart flips the row into a transitional state immediately, calls the
//    agent, and then gets out of the way: the next frame from the services
//    channel carries the real state. We never write into the list ourselves, so
//    "reverting" a failed action is simply forgetting that we were hopeful.
//
//  Everything destructive — restart, stop, and both boot-time changes — passes
//  through a confirmation that names the unit and says what breaks. Start does
//  not: starting a stopped service is the one action here with no victim.

import Combine
import SwiftUI

/// The systemd units on one server: summary, filter, list, detail.
public struct ServicesSection: View {

    private let session: ServerSession
    private let navigation: NavigationModel

    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    @State private var searchText = ""
    @State private var filter: ServiceFilter = .all
    @State private var hoveredUnit: String?

    /// The unit whose inspector is open, by systemd unit name.
    @State private var selectedUnit: String?
    @State private var detail: ScreenState<ServiceUnitDetail> = .loading
    /// Bumped to re-read the open unit's detail without changing which unit it is.
    @State private var detailNonce = 0

    /// Units with an action in flight, and which action. This is the whole of
    /// our optimism: the list itself is never mutated.
    @State private var pendingActions: [String: ServiceAction] = [:]
    @State private var actionError: ServerOSError?

    @State private var confirmation: PendingServiceAction?
    @State private var isConfirming = false

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            header

            if session.capabilities.services {
                summaryStrip
            }

            if let actionError {
                InlineBanner(.error, actionError.headline, actionTitle: "Dismiss") {
                    self.actionError = nil
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.bottom, Spacing.element)
                .transition(.opacity)
            }

            Divider().overlay(Palette.divider)

            content
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .animation(Motion.honouring(reduceMotion, Motion.appear), value: actionError)
        // ⌘K and the health card ask this screen to open a specific unit by
        // putting its name in the navigation model. Honour it once the list has
        // arrived, then clear it so returning here later opens nothing.
        .onAppear { honourRequestedSelection() }
        .onChange(of: navigation.selectedServiceUnit) { _, _ in honourRequestedSelection() }
        .onChange(of: session.services.count) { _, _ in honourRequestedSelection() }
        .task(id: detailRequest) { await loadDetail() }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            Task {
                await session.refreshAll()
                detailNonce += 1
            }
        }
        .inspector(isPresented: inspectorBinding) {
            ServiceInspector(
                serverName: session.name,
                unitName: selectedUnit ?? "",
                displayName: selectedService?.displayName ?? selectedUnit ?? "",
                state: detail,
                isConnected: session.api != nil,
                isEnabledAtBoot: selectedService?.isEnabledAtBoot ?? false,
                pendingAction: selectedUnit.flatMap { pendingActions[$0] },
                capabilities: selectedService.map { ServiceCapabilities($0) } ?? ServiceCapabilities(),
                onAction: { action in
                    guard let unit = selectedService else { return }
                    request(action, on: unit)
                },
                onViewLogs: {
                    if let unit = selectedUnit { openLogs(unit: unit) }
                },
                onRetry: { detailNonce += 1 }
            )
            .inspectorColumnWidth(min: 300, ideal: 360, max: 480)
        }
        .confirmDestructive(
            isPresented: $isConfirming,
            title: confirmation?.title ?? "Change this service?",
            target: confirmation?.displayName ?? "",
            consequence: confirmation?.consequence ?? "",
            isReversible: confirmation?.isReversible ?? false,
            confirmTitle: confirmation?.confirmTitle ?? "Continue"
        ) {
            if let pending = confirmation {
                perform(pending.action, unitName: pending.unit, displayName: pending.displayName)
            }
            confirmation = nil
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Services")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(countLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Spacer(minLength: Spacing.group)

            if session.capabilities.services {
                SearchField(text: $searchText, prompt: "Search services")
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.vertical, Spacing.group)
    }

    private var countLine: String {
        guard session.capabilities.services else {
            return "Service management isn't available on \(session.name)."
        }
        let units = session.services
        guard !units.isEmpty else {
            return "Reading the unit list on \(session.name)…"
        }
        let failed = units.filter(\.hasFailed).count
        let running = units.filter(\.isRunning).count
        var line = "\(Formatting.count(units.count)) unit\(units.count == 1 ? "" : "s") · \(running) running"
        if failed > 0 {
            line += " · \(failed) failed"
        }
        return line
    }

    // MARK: - Summary strip

    /// Three counts that are also the filters.
    ///
    /// Failed is first and is the only tile that is ever filled, because a
    /// screen full of equally-weighted numbers makes the reader do the triage
    /// that the product is supposed to do for them.
    private var summaryStrip: some View {
        let units = session.services
        let failed = units.filter(\.hasFailed).count
        let running = units.filter(\.isRunning).count
        let stopped = units.count - failed - running

        return HStack(spacing: Spacing.element) {
            ServiceFilterTile(
                title: "Failed",
                count: failed,
                tint: Palette.critical,
                systemImage: "exclamationmark.triangle.fill",
                isLoud: failed > 0,
                isActive: filter == .failed
            ) { toggle(.failed) }

            ServiceFilterTile(
                title: "Running",
                count: running,
                tint: Palette.healthy,
                systemImage: "circle.fill",
                isLoud: false,
                isActive: filter == .running
            ) { toggle(.running) }

            ServiceFilterTile(
                title: "Stopped",
                count: max(0, stopped),
                tint: Palette.inactive,
                systemImage: "stop.fill",
                isLoud: false,
                isActive: filter == .stopped
            ) { toggle(.stopped) }

            Spacer(minLength: Spacing.element)

            if filter != .all {
                Button("Show All") { withAnimation(Motion.immediate) { filter = .all } }
                    .buttonStyle(.rowAction)
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.bottom, Spacing.group)
    }

    private func toggle(_ candidate: ServiceFilter) {
        withAnimation(Motion.honouring(reduceMotion, Motion.immediate)) {
            filter = (filter == candidate) ? .all : candidate
        }
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if !hasHeardFromAgent {
            // The agent answers `health()` a beat after the connection is ready,
            // so capabilities are briefly all-false on a perfectly capable
            // server. A skeleton is honest here; "not available" would not be.
            LoadingList()
        } else if !session.capabilities.services {
            UnavailableState(subsystem: "Services", reason: unavailableReason)
        } else if session.services.isEmpty {
            EmptyState(
                systemImage: "gearshape.2",
                title: "No services reported",
                message: "\(session.name) says systemd is running, but it returned no units. "
                    + "That usually means the agent can't talk to systemd over D-Bus.",
                actionTitle: "Try Again",
                action: { Task { await session.refreshAll() } }
            )
        } else if filteredServices.isEmpty {
            emptyFilterState
        } else {
            list(filteredServices)
        }
    }

    private var emptyFilterState: some View {
        EmptyState(
            systemImage: searchText.isEmpty ? "checkmark.circle" : "magnifyingglass",
            title: emptyFilterTitle,
            message: emptyFilterMessage,
            actionTitle: searchText.isEmpty ? "Show All Services" : "Clear Search",
            action: {
                if searchText.isEmpty {
                    filter = .all
                } else {
                    searchText = ""
                }
            }
        )
    }

    private var emptyFilterTitle: String {
        if !searchText.isEmpty { return "Nothing matches “\(searchText)”" }
        switch filter {
        case .failed: return "Nothing has failed"
        case .running: return "Nothing is running"
        case .stopped: return "Nothing is stopped"
        case .all: return "No services to show"
        }
    }

    private var emptyFilterMessage: String {
        if !searchText.isEmpty {
            return "No unit on \(session.name) has that in its name or description."
        }
        switch filter {
        case .failed: return "Every unit on \(session.name) is in the state systemd expects."
        case .running: return "No unit on \(session.name) is currently active."
        case .stopped: return "Every unit on \(session.name) is either running or failed."
        case .all: return "\(session.name) reported no units."
        }
    }

    private func list(_ units: [ServiceUnit]) -> some View {
        ScrollView {
            LazyVStack(spacing: 0) {
                ForEach(units) { unit in
                    ServiceRow(
                        unit: unit,
                        runState: runState(for: unit),
                        pendingAction: pendingActions[unit.name],
                        isSelected: selectedUnit == unit.name,
                        isHovered: hoveredUnit == unit.name,
                        isConnected: session.api != nil,
                        onSelect: { select(unit) },
                        onAction: { request($0, on: unit) },
                        onViewLogs: {
                            select(unit)
                            openLogs(unit: unit.name)
                        }
                    )
                    .onHover { hovering in
                        if hovering {
                            hoveredUnit = unit.name
                        } else if hoveredUnit == unit.name {
                            hoveredUnit = nil
                        }
                    }

                    Divider().overlay(Palette.divider)
                }
            }
            .padding(.horizontal, Spacing.card)
            .padding(.bottom, Spacing.card)
        }
    }

    // MARK: - Derived state

    /// True once the agent has told us what it can do. `capabilities` starts
    /// all-false, so this is what stops a capable server flashing "unavailable".
    private var hasHeardFromAgent: Bool {
        session.agentVersion != nil || !session.services.isEmpty || session.system != nil
    }

    private var unavailableReason: String {
        if let backend = session.capabilities.serviceBackend,
           !backend.isEmpty,
           backend != "systemd" {
            return "\(session.name) is managed by \(backend) rather than systemd, and ServerOS speaks systemd. "
                + "Processes, Docker and Logs still work here."
        }
        return "systemd is not this host's init system — or the agent can't reach it over D-Bus — "
            + "so there are no units for ServerOS to manage. Processes, Docker and Logs still work here."
    }

    private var filteredServices: [ServiceUnit] {
        let needle = searchText.trimmingCharacters(in: .whitespaces).lowercased()

        return session.services.filter { unit in
            let matchesFilter: Bool
            switch filter {
            case .all: matchesFilter = true
            case .failed: matchesFilter = unit.hasFailed
            case .running: matchesFilter = unit.isRunning
            case .stopped: matchesFilter = !unit.isRunning && !unit.hasFailed
            }
            guard matchesFilter else { return false }
            guard !needle.isEmpty else { return true }
            return unit.displayName.lowercased().contains(needle)
                || unit.name.lowercased().contains(needle)
                || unit.description.lowercased().contains(needle)
        }
        // Failed units float to the top of whatever the user is looking at: the
        // one thing that needs a decision should never be below the fold.
        .sorted { lhs, rhs in
            if lhs.hasFailed != rhs.hasFailed { return lhs.hasFailed }
            return lhs.displayName.localizedCaseInsensitiveCompare(rhs.displayName) == .orderedAscending
        }
    }

    private var selectedService: ServiceUnit? {
        guard let selectedUnit else { return nil }
        return session.services.first { $0.name == selectedUnit }
    }

    /// The pill a row should show, allowing for an action we have not heard back
    /// about yet.
    ///
    /// The pill's transitional state is worded "Restarting", which is right for
    /// a start or a restart and wrong for a stop — so a stop keeps its current
    /// pill and the row says "Stopping…" beside it instead. Either way the row
    /// carries the precise verb, so nothing is ambiguous.
    private func runState(for unit: ServiceUnit) -> RunPill.RunState {
        // Spelled `.some(...)` rather than relying on an optional pattern
        // shorthand: the dictionary lookup is an Optional and being explicit
        // about that costs nothing.
        switch pendingActions[unit.name] {
        case .some(.start), .some(.restart), .some(.reload):
            return .restarting
        default:
            return RunPill.RunState.fromService(unit.state)
        }
    }

    // MARK: - Selection

    private func select(_ unit: ServiceUnit) {
        withAnimation(Motion.honouring(reduceMotion, Motion.immediate)) {
            selectedUnit = unit.name
        }
    }

    private var inspectorBinding: Binding<Bool> {
        Binding(
            get: { selectedUnit != nil },
            set: { isPresented in
                if !isPresented { selectedUnit = nil }
            }
        )
    }

    /// Open whatever ⌘K, a health action or a deep link asked for.
    ///
    /// The request is only cleared once the unit list has arrived, because at
    /// `onAppear` the stream has usually not delivered anything yet and
    /// discarding the request then would silently lose the user's intent.
    private func honourRequestedSelection() {
        guard let requested = navigation.selectedServiceUnit else { return }
        guard !session.services.isEmpty else { return }

        if let match = session.services.first(where: { $0.name == requested || $0.displayName == requested }) {
            selectedUnit = match.name
            // Make sure the unit is actually on screen: arriving at a filtered
            // list that excludes the thing you asked for reads as a bug.
            filter = .all
            searchText = ""
        }
        navigation.selectedServiceUnit = nil
    }

    /// Hand a unit to the Logs section.
    ///
    /// The unit name is passed in rather than read back out of `selectedUnit`,
    /// because a caller may have set the selection a line earlier and `@State`
    /// is not guaranteed to read back within the same event.
    private func openLogs(unit: String) {
        // The Logs section reads the same navigation slot, so this hands the
        // unit over rather than inventing a second channel for it.
        navigation.selectedServiceUnit = unit
        navigation.select(section: .logs)
    }

    // MARK: - Actions

    /// Ask for an action — confirming first when it interrupts something.
    private func request(_ action: ServiceAction, on unit: ServiceUnit) {
        let pending = PendingServiceAction(
            action: action,
            unit: unit.name,
            displayName: unit.displayName
        )

        if pending.needsConfirmation {
            confirmation = pending
            isConfirming = true
        } else {
            perform(action, unitName: unit.name, displayName: unit.displayName)
        }
    }

    /// Optimism, then the truth.
    ///
    /// We mark the unit pending so the row reacts to the click immediately, call
    /// the agent, and then drop the mark. We deliberately do **not** write a new
    /// state into the list: the services channel is the only thing allowed to
    /// say what a unit is doing, so a failed action reverts by itself the moment
    /// we stop pretending.
    private func perform(_ action: ServiceAction, unitName: String, displayName: String) {
        guard let api = session.api else {
            actionError = ServerOSError.sshNotConnected
            return
        }

        withAnimation(Motion.honouring(reduceMotion, Motion.status)) {
            pendingActions[unitName] = action
        }
        actionError = nil

        Task {
            do {
                try await api.performServiceAction(action, unit: unitName)
                // Ask for a fresh unit list rather than waiting for the next
                // scheduled frame, so the row settles while the user is still
                // looking at it.
                await session.refreshAll()
                if selectedUnit == unitName { detailNonce += 1 }
            } catch let error as ServerOSError {
                actionError = error
            } catch {
                actionError = ServerOSError.transport(error, serverName: session.name)
            }
            withAnimation(Motion.honouring(reduceMotion, Motion.status)) {
                pendingActions[unitName] = nil
            }
        }
    }

    // MARK: - Detail loading

    /// What the inspector is currently asking for.
    private struct DetailRequest: Equatable {
        var unit: String?
        var nonce: Int
    }

    private var detailRequest: DetailRequest {
        DetailRequest(unit: selectedUnit, nonce: detailNonce)
    }

    private func loadDetail() async {
        guard let unit = selectedUnit else { return }
        guard let api = session.api else {
            detail = .failed(ServerOSError.sshNotConnected)
            return
        }
        // A different unit starts from a skeleton; a re-read of the same unit
        // keeps what is on screen so ⌘R does not blank the panel you are
        // reading.
        if detail.value?.name != unit { detail = .loading }

        do {
            let value = try await api.service(unit: unit)
            guard selectedUnit == unit else { return }  // the user moved on
            detail = .loaded(value)
        } catch let error as ServerOSError {
            if selectedUnit == unit { detail = .failed(error) }
        } catch {
            if selectedUnit == unit {
                detail = .failed(ServerOSError.transport(error, serverName: session.name))
            }
        }
    }
}

// MARK: - Filter

/// The summary strip's three tiles, plus the unfiltered state.
private enum ServiceFilter: Equatable {
    case all, failed, running, stopped
}

// MARK: - What a unit will let you do

/// The three `can_*` flags, lifted off the wire type so the inspector can be
/// rendered from a detail response that does not carry them.
private struct ServiceCapabilities {
    var canStart = false
    var canStop = false
    var canRestart = false

    init() {}

    init(_ unit: ServiceUnit) {
        canStart = unit.canStart
        canStop = unit.canStop
        canRestart = unit.canRestart
    }
}

// MARK: - Pending action

/// An action the user has asked for, with the words shown before it happens.
private struct PendingServiceAction: Equatable {
    let action: ServiceAction
    /// The systemd unit name, which is what the agent is given.
    let unit: String
    /// What the user calls it, which is what the confirmation says.
    let displayName: String

    /// Start is the one action with no victim. Everything else interrupts
    /// something, now or at the next boot, so everything else is confirmed.
    var needsConfirmation: Bool { action != .start }

    var title: String {
        switch action {
        case .stop: return "Stop \(displayName)?"
        case .restart: return "Restart \(displayName)?"
        case .reload: return "Reload \(displayName)?"
        case .enable: return "Start \(displayName) at every boot?"
        case .disable: return "Stop starting \(displayName) at boot?"
        case .start: return "Start \(displayName)?"
        }
    }

    var confirmTitle: String {
        switch action {
        case .stop: return "Stop Service"
        case .restart: return "Restart"
        case .reload: return "Reload"
        case .enable: return "Enable at Boot"
        case .disable: return "Disable at Boot"
        case .start: return "Start"
        }
    }

    var consequence: String {
        switch action {
        case .restart:
            return "\(displayName) will stop and start again. Anything depending on it — the sites it serves, "
                + "the connections it is holding, the work it is in the middle of — is interrupted until it is back. "
                + "Whether it starts at boot does not change."
        case .stop:
            // Stopping is the harder of the two, and the copy says so: a restart
            // ends with the service running, a stop does not.
            return "\(displayName) will stop and stay stopped. Anything depending on it fails until someone starts "
                + "it again, and it will not come back on its own before this server next reboots."
        case .reload:
            return "\(displayName) will re-read its configuration without restarting. A unit with a bad configuration "
                + "file can fail the reload and stop."
        case .enable:
            return "\(displayName) will start automatically every time this server boots. "
                + "Nothing changes right now — this only takes effect at the next boot."
        case .disable:
            return "\(displayName) will not start when this server boots. It keeps running right now; "
                + "the change only takes effect at the next boot."
        case .start:
            return "\(displayName) will start now."
        }
    }

    /// Boot-time changes are a switch you can flip back; a restart or a stop has
    /// already interrupted whatever it interrupted.
    var isReversible: Bool { action == .enable || action == .disable }
}

// MARK: - Filter tile

/// One count in the summary strip, which is also a filter.
private struct ServiceFilterTile: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    let title: String
    let count: Int
    let tint: Color
    let systemImage: String
    /// True only for a failed count above zero — the one thing on this screen
    /// allowed to shout.
    let isLoud: Bool
    let isActive: Bool
    let action: () -> Void

    @State private var isHovered = false

    // Written out rather than left to the memberwise initialiser: a struct with
    // a private stored property gets a private memberwise init, which the
    // enclosing screen could not call.
    init(
        title: String,
        count: Int,
        tint: Color,
        systemImage: String,
        isLoud: Bool,
        isActive: Bool,
        action: @escaping () -> Void
    ) {
        self.title = title
        self.count = count
        self.tint = tint
        self.systemImage = systemImage
        self.isLoud = isLoud
        self.isActive = isActive
        self.action = action
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: Spacing.element) {
                Image(systemName: systemImage)
                    .font(.system(size: isLoud ? 12 : 10, weight: .semibold))
                    .foregroundStyle(isLoud ? tint : Palette.textMuted)
                    .accessibilityHidden(true)

                VStack(alignment: .leading, spacing: 0) {
                    Text(Formatting.count(count))
                        .font(isLoud ? Typography.metric : Typography.metricSmall)
                        .foregroundStyle(isLoud ? tint : Palette.textPrimary)
                        .contentTransition(.numericText())
                        .animation(Motion.honouring(reduceMotion, Motion.value), value: count)
                    Text(title)
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textSecondary)
                }
            }
            .padding(.horizontal, Spacing.group)
            .padding(.vertical, Spacing.element)
            .frame(minWidth: 108, alignment: .leading)
            .background(background, in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
            .overlay(
                RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                    .strokeBorder(isActive ? tint.opacity(0.55) : Palette.divider, lineWidth: isActive ? 1.5 : 0.5)
            )
            .contentShape(RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering in withAnimation(Motion.immediate) { isHovered = hovering } }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title) services")
        .accessibilityValue(Formatting.count(count))
        .accessibilityHint(isActive ? "Showing only these. Activate to show all." : "Activate to show only these.")
        .accessibilityAddTraits(isActive ? [.isButton, .isSelected] : .isButton)
    }

    private var background: Color {
        if isActive { return tint.opacity(0.16) }
        if isLoud { return tint.opacity(0.09) }
        return isHovered ? Palette.hoverFill.opacity(0.5) : Palette.surface
    }
}

// MARK: - Row

/// One unit in the list.
private struct ServiceRow: View {
    let unit: ServiceUnit
    let runState: RunPill.RunState
    let pendingAction: ServiceAction?
    let isSelected: Bool
    let isHovered: Bool
    let isConnected: Bool
    let onSelect: () -> Void
    let onAction: (ServiceAction) -> Void
    let onViewLogs: () -> Void

    var body: some View {
        HStack(spacing: Spacing.group) {
            RunPill(runState)
                .frame(width: 88, alignment: .leading)

            VStack(alignment: .leading, spacing: Spacing.hairline) {
                HStack(spacing: Spacing.snug) {
                    Text(unit.displayName)
                        .font(Typography.body.weight(.medium))
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)

                    if unit.isEnabledAtBoot {
                        Chip("Enabled at boot", tint: Palette.informational, systemImage: "power")
                    }
                }

                Text(unit.description.isEmpty ? unit.name : unit.description)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }

            Spacer(minLength: Spacing.element)

            trailing
        }
        .padding(.horizontal, Spacing.group)
        .padding(.vertical, Spacing.element)
        .frame(minHeight: Layout.comfortableRowHeight)
        .contentShape(Rectangle())
        .hoverHighlight(isSelected: isSelected)
        .onTapGesture(perform: onSelect)
        .contextMenu { menu }
        .help(unit.name)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(unit.displayName), \(accessibilityState)")
        .accessibilityAction(named: Text("Show details"), onSelect)
    }

    // MARK: Trailing controls

    @ViewBuilder
    private var trailing: some View {
        if let pendingAction {
            InlineProgress(pendingAction.inProgressLabel)
        } else if isHovered || isSelected {
            // Revealed on hover so a list of forty units stays calm, but the
            // context menu carries the same actions for anyone not using a
            // pointer — hover must never be the only way to do something.
            HStack(spacing: Spacing.snug) {
                if unit.canStart && !unit.isRunning {
                    Button("Start") { onAction(.start) }
                        .buttonStyle(RowActionButtonStyle(tint: Palette.healthy))
                        .accessibilityLabel("Start \(unit.displayName)")
                }
                if unit.canRestart && unit.isRunning {
                    Button("Restart") { onAction(.restart) }
                        .buttonStyle(.rowAction)
                        .accessibilityLabel("Restart \(unit.displayName)")
                }
                if unit.canStop && unit.isRunning {
                    Button("Stop") { onAction(.stop) }
                        .buttonStyle(RowActionButtonStyle(tint: Palette.critical))
                        .accessibilityLabel("Stop \(unit.displayName)")
                }
            }
            .disabled(!isConnected)
            .transition(.opacity)
        } else if unit.hasFailed {
            // A failed unit says so even when the pointer is elsewhere.
            Text("Needs attention")
                .font(Typography.metadata)
                .foregroundStyle(Palette.critical)
        }
    }

    @ViewBuilder
    private var menu: some View {
        Button("Show Details", action: onSelect)
        Button("View Logs", action: onViewLogs)
        Divider()
        if unit.canStart && !unit.isRunning {
            Button("Start") { onAction(.start) }
        }
        if unit.canRestart {
            Button("Restart…") { onAction(.restart) }
        }
        if unit.canStop && unit.isRunning {
            Button("Stop…", role: .destructive) { onAction(.stop) }
        }
        Divider()
        if unit.isEnabledAtBoot {
            Button("Disable at Boot…") { onAction(.disable) }
        } else {
            Button("Enable at Boot…") { onAction(.enable) }
        }
    }

    private var accessibilityState: String {
        if let pendingAction { return pendingAction.inProgressLabel }
        var parts = [runState.accessibilityWord]
        if unit.isEnabledAtBoot { parts.append("enabled at boot") }
        return parts.joined(separator: ", ")
    }
}

// MARK: - Inspector

/// Everything systemd knows about one unit, plus the two things you can do
/// about it: change its state, or go and read its logs.
private struct ServiceInspector: View {
    let serverName: String
    let unitName: String
    let displayName: String
    let state: ScreenState<ServiceUnitDetail>
    let isConnected: Bool
    let isEnabledAtBoot: Bool
    let pendingAction: ServiceAction?
    let capabilities: ServiceCapabilities
    let onAction: (ServiceAction) -> Void
    let onViewLogs: () -> Void
    let onRetry: () -> Void

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.between) {
                StatefulContent(state, retry: onRetry) { detail in
                    loaded(detail)
                } empty: {
                    EmptyState(
                        systemImage: "gearshape.2",
                        title: "No detail for \(displayName)",
                        message: "\(serverName) knows about this unit but returned nothing to show."
                    )
                }
            }
            .padding(Spacing.card)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .background(Palette.background)
    }

    @ViewBuilder
    private func loaded(_ detail: ServiceUnitDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.between) {
            headline(detail)
            actions
            facts(detail)
            if let documentation = detail.documentation, !documentation.isEmpty {
                documentationSection(documentation)
            }
        }
    }

    private func headline(_ detail: ServiceUnitDetail) -> some View {
        VStack(alignment: .leading, spacing: Spacing.snug) {
            Text(detail.displayName)
                .font(Typography.pageTitle)
                .foregroundStyle(Palette.textPrimary)
                .accessibilityAddTraits(.isHeader)

            HStack(spacing: Spacing.element) {
                RunPill(RunPill.RunState.fromService(detail.state))
                if isEnabledAtBoot {
                    Chip("Enabled at boot", tint: Palette.informational, systemImage: "power")
                } else {
                    Chip("Not started at boot", tint: Palette.inactive, systemImage: "power")
                }
            }

            Text(detail.description.isEmpty ? detail.name : detail.description)
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)
                .fixedSize(horizontal: false, vertical: true)

            Text(detail.name)
                .font(Typography.codeSmall)
                .foregroundStyle(Palette.textMuted)
                .textSelection(.enabled)
        }
    }

    @ViewBuilder
    private var actions: some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            if let pendingAction {
                InlineProgress(pendingAction.inProgressLabel)
            } else {
                HStack(spacing: Spacing.element) {
                    if capabilities.canRestart {
                        Button("Restart") { onAction(.restart) }
                            .buttonStyle(.secondary)
                    }
                    if capabilities.canStop {
                        Button("Stop") { onAction(.stop) }
                            .buttonStyle(.secondary)
                    }
                    if capabilities.canStart {
                        Button("Start") { onAction(.start) }
                            .buttonStyle(.primary)
                    }
                }
                .disabled(!isConnected)

                HStack(spacing: Spacing.element) {
                    if isEnabledAtBoot {
                        Button("Disable at Boot") { onAction(.disable) }
                            .buttonStyle(.secondary)
                    } else {
                        Button("Enable at Boot") { onAction(.enable) }
                            .buttonStyle(.secondary)
                    }

                    Button("View Logs", action: onViewLogs)
                        .buttonStyle(.secondary)
                }
                .disabled(!isConnected)
            }

            if !isConnected {
                Text("ServerOS isn't connected to \(serverName) right now, so these are unavailable.")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    // Two groups rather than one list of eleven rows: a `ViewBuilder` takes at
    // most ten children, and these divide naturally into what the unit is doing
    // now and what has happened to it.
    private func facts(_ detail: ServiceUnitDetail) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            SectionHeader("Unit")
                .padding(.bottom, Spacing.snug)

            runtimeRows(detail)
            lifecycleRows(detail)
        }
    }

    private func runtimeRows(_ detail: ServiceUnitDetail) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            KeyValueRow("State", "\(detail.activeState) (\(detail.subState))")
            KeyValueRow("Main PID", detail.mainPID.map { Formatting.count(Int($0)) }, placeholder: "Not running")
            KeyValueRow("Memory", detail.memoryBytes.map { Formatting.bytes($0) }, placeholder: "—")
            KeyValueRow("CPU time", ServiceInspector.cpuTime(detail.cpuUsageNsec), placeholder: "—")
            KeyValueRow("Tasks", ServiceInspector.tasks(current: detail.tasksCurrent, max: detail.tasksMax), placeholder: "—")
        }
    }

    private func lifecycleRows(_ detail: ServiceUnitDetail) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            KeyValueRow("Restarts", detail.restartCount.map { Formatting.count($0) }, placeholder: "Unknown")
            KeyValueRow("Active since", ServiceInspector.activeSince(detail.activeSince), placeholder: "Not active")
            KeyValueRow("Result", ServiceInspector.result(detail.result), placeholder: "Unknown")
            KeyValueRow("Exit status", ServiceInspector.exitStatus(detail.execMainStatus), placeholder: "Unknown")
            KeyValueRow("Unit file", detail.fragmentPath, placeholder: "Unknown", monospaced: true)
        }
    }

    private func documentationSection(_ documentation: [String]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.snug) {
            SectionHeader("Documentation")

            ForEach(documentation, id: \.self) { entry in
                if let url = ServiceInspector.webURL(entry) {
                    Link(destination: url) {
                        HStack(spacing: Spacing.tight) {
                            Image(systemName: "arrow.up.right.square")
                                .font(.system(size: 10))
                                .accessibilityHidden(true)
                            Text(entry)
                                .font(Typography.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    }
                    .foregroundStyle(Palette.accent)
                } else {
                    // `man:nginx(8)` and `info:` entries are real documentation
                    // but not something a browser can open, so they stay as
                    // selectable text rather than pretending to be links.
                    Text(entry)
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textSecondary)
                        .textSelection(.enabled)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
            }
        }
    }

    // MARK: Value formatting

    private static func cpuTime(_ nanoseconds: Int64?) -> String? {
        guard let nanoseconds, nanoseconds >= 0 else { return nil }
        let seconds = nanoseconds / 1_000_000_000
        if seconds < 1 { return "Less than a second" }
        return Formatting.duration(seconds: seconds)
    }

    private static func tasks(current: Int64?, max maximum: Int64?) -> String? {
        guard let current else { return nil }
        guard let maximum, maximum > 0 else { return Formatting.count(current) }
        return "\(Formatting.count(current)) of \(Formatting.count(maximum))"
    }

    private static func activeSince(_ unixSeconds: Int64?) -> String? {
        guard let unixSeconds, unixSeconds > 0 else { return nil }
        return "\(Formatting.relative(unixSeconds: unixSeconds)) · \(Formatting.timestamp(unixSeconds: unixSeconds))"
    }

    /// systemd's `Result` in words. "success" is the only value most people ever
    /// see, and the rest are worth translating rather than echoing.
    private static func result(_ raw: String?) -> String? {
        guard let raw, !raw.isEmpty else { return nil }
        switch raw {
        case "success": return "Success"
        case "exit-code": return "Exited with an error code"
        case "signal": return "Killed by a signal"
        case "timeout": return "Timed out"
        case "oom-kill": return "Killed — the server ran out of memory"
        case "core-dump": return "Crashed and dumped core"
        case "start-limit-hit": return "Restarted too often and was given up on"
        case "watchdog": return "Missed its watchdog"
        case "resources": return "Could not get the resources it needs"
        default: return raw
        }
    }

    private static func exitStatus(_ status: Int32?) -> String? {
        guard let status else { return nil }
        return status == 0 ? "0 — exited normally" : "\(status) — exited with an error"
    }

    /// Only http(s) entries become real links; everything else is shown as text.
    private static func webURL(_ entry: String) -> URL? {
        guard let url = URL(string: entry), let scheme = url.scheme?.lowercased() else { return nil }
        guard scheme == "http" || scheme == "https" else { return nil }
        return url
    }
}

// MARK: - Small helpers

extension RunPill.RunState {
    /// The state as VoiceOver should hear it inside a longer sentence.
    fileprivate var accessibilityWord: String {
        switch self {
        case .running: return "running"
        case .stopped: return "stopped"
        case .paused: return "paused"
        case .restarting: return "changing state"
        case .failed: return "failed"
        case .unknown: return "state unknown"
        }
    }
}

// MARK: - Preview

private struct ServicesPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        ServicesSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 1000, height: 640)
            .onAppear { session.connect() }
    }
}

#Preview("Services") {
    ServicesPreviewHost()
}
