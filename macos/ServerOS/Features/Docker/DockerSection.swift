//  DockerSection.swift
//  ServerOS
//
//  Docker — the screen this product is judged on.
//
//  Most people who own a Linux server today reach for `docker ps`, squint at a
//  table that wraps at 140 columns, copy a container id, and paste it into
//  `docker restart`. This screen exists to make all of that unnecessary, and it
//  is built around five decisions worth stating out loud:
//
//  * **The list is live, not fetched.** `session.containers` is kept current by
//    the stream the server detail shell already subscribed to. Re-fetching on
//    appear would produce a visible flash and a second source of truth that can
//    disagree with the header's health verdict. So this screen reads, and the
//    only thing it ever asks the agent for is what the stream does not carry:
//    the daemon's own version, images, volumes and networks.
//
//  * **Row actions are optimistic.** A restart takes several seconds on the
//    server. A UI that freezes for those seconds reads as broken, and a UI that
//    waits silently reads as ignored. So the row flips to a pending state the
//    instant the button is pressed, the call goes out, and the live stream is
//    then allowed to correct the row — which it will, because it is the same
//    stream the rest of the screen reads. If the call fails, the pending state
//    is dropped (which *is* the revert — the pill was the only thing we changed)
//    and a banner names the container and says what went wrong.
//
//  * **Grouping follows Compose.** A container called `estatify-api-1` is not a
//    thing anybody deployed; `estatify` is. Grouping by the
//    `com.docker.compose.project` label puts the row back next to its siblings
//    and lets the group header answer "is this application up?" in four words.
//
//  * **Stop and Remove are gated; Start and Restart are not.** Stopping causes
//    downtime and Removing is permanent, so both state their consequence and
//    name their target. Starting something that is already stopped cannot hurt,
//    and putting a dialog in front of it would train people to click through
//    dialogs — which is how the dangerous ones stop working.
//
//  * **Images, volumes and networks are read-only, deliberately.** Pruning
//    images is the single most common way to delete something you needed, and a
//    safe pruning UX needs to show what will go before it goes. That is real
//    design work and it is not in the MVP, so rather than ship a fast
//    `docker system prune` button with a scary label, this release shows the
//    facts and stays out of the way.

import AppKit
import Combine
import SwiftUI

/// Docker for one server: containers, images, volumes, networks, and an
/// inspector for whichever container is selected.
public struct DockerSection: View {

    /// How often the optional live-stats poll re-samples. Docker measures CPU
    /// and memory one container at a time, so this is opt-in and unhurried.
    private static let statsInterval: Duration = .seconds(5)

    /// How long an optimistic row waits for the live stream to confirm it
    /// before we stop believing the stream and ask the agent directly.
    private static let optimismTimeout: TimeInterval = 8

    /// How often that wait checks. Short enough to feel immediate, long enough
    /// not to spin the main actor.
    private static let optimismPoll: Duration = .milliseconds(400)

    /// A restart leaves a container "running" at both ends, so there is no
    /// state change to watch for. Hold the pending pill this long instead, so
    /// the user sees that their click did something.
    private static let restartDwell: Duration = .seconds(2)

    /// The grace period Docker gets to shut a container down cleanly.
    private static let defaultGraceSeconds = 10

    @Environment(\.colorScheme) private var scheme

    private let session: ServerSession
    private let navigation: NavigationModel

    // View state
    @State private var surface: DockerSurface = .containers
    @State private var searchText = ""
    @State private var runFilter: RunFilter = .all
    @State private var projectFilter: String?
    @State private var groupsByProject = true
    @State private var showsLiveStats = false

    // Selection and in-flight work
    @State private var selectedContainerID: String?
    @State private var inFlight: [String: InFlightAction] = [:]
    @State private var failure: ActionFailure?

    // Fetched, because the stream does not carry these
    @State private var info: DockerInfo?
    @State private var liveStats: [String: LiveStatsSample] = [:]
    @State private var imagesState: ScreenState<[DockerImage]> = .loading
    @State private var volumesState: ScreenState<[DockerVolume]> = .loading
    @State private var networksState: ScreenState<[DockerNetwork]> = .loading
    @State private var reloadNonce = 0

    // Confirmations and sheets
    @State private var pendingStop: PendingContainer?
    @State private var isConfirmingStop = false
    @State private var pendingRemoval: PendingContainer?
    @State private var isConfirmingRemoval = false
    @State private var logsTarget: LogsTarget?

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            header
            surfacePicker

            if surface == .containers {
                summaryStrip
            }

            if let failure {
                InlineBanner(.error, failure.message, actionTitle: "Dismiss") {
                    self.failure = nil
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.bottom, Spacing.element)
                .transition(.opacity)
            }

            Divider().overlay(Palette.divider)

            content
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .animation(Motion.appear, value: failure?.id)
        .onAppear { honourNavigationRequest() }
        .onChange(of: navigation.selectedContainerID) { _, _ in honourNavigationRequest() }
        .onChange(of: navigation.selectedProjectName) { _, _ in honourNavigationRequest() }
        .task(id: surfaceLoad) { await loadCurrentSurface() }
        .task(id: statsLoad) { await pollLiveStats() }
        .onChange(of: session.phase.isReady) { _, isReady in
            if isReady { reloadNonce += 1 }
        }
        .onChange(of: session.capabilities) { _, _ in reloadNonce += 1 }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            reloadNonce += 1
            Task { await session.refreshAll() }
        }
        .inspector(isPresented: inspectorPresentation) {
            inspectorContent
        }
        .sheet(item: $logsTarget) { target in
            ContainerLogsView(
                containerID: target.id,
                containerName: target.name,
                session: session
            )
        }
        .confirmDestructive(
            isPresented: $isConfirmingStop,
            title: pendingStop.map { "Stop \($0.name)?" } ?? "Stop this container?",
            target: pendingStop?.name ?? "",
            consequence: stopConsequence,
            // Reversible in the only sense that matters here: the container is
            // still there afterwards and one click starts it again.
            isReversible: true,
            confirmTitle: "Stop Container"
        ) {
            confirmStop()
        }
        // Removal is the one action in this screen the design system's
        // confirmation cannot express: it offers exactly one destructive
        // choice, and removing a container genuinely has two — with its
        // volumes, or without. `confirmationDialog` cannot hold a checkbox, so
        // the choice becomes two buttons, and the copy keeps the same contract
        // the modifier enforces everywhere else: name the target, state the
        // consequence, say that it cannot be undone.
        .confirmationDialog(
            pendingRemoval.map { "Remove \($0.name)?" } ?? "Remove this container?",
            isPresented: $isConfirmingRemoval,
            titleVisibility: .visible
        ) {
            Button("Remove Container", role: .destructive) { remove(includingVolumes: false) }
            Button("Remove Container and Volumes", role: .destructive) { remove(includingVolumes: true) }
            Button("Cancel", role: .cancel) { pendingRemoval = nil }
        } message: {
            Text(removalConsequence)
        }
    }

    // MARK: - Header

    private var header: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Docker")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(subtitleLine)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
                    .truncationMode(.tail)
            }

            Spacer(minLength: Spacing.group)

            if surface == .containers {
                SearchField(text: $searchText, prompt: "Search containers")
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.top, Spacing.group)
        .padding(.bottom, Spacing.element)
    }

    /// One quiet line of facts about the daemon. Facts you check occasionally,
    /// not numbers you watch.
    private var subtitleLine: String {
        guard let info else {
            return session.capabilities.docker
                ? "Reading Docker on \(session.name)…"
                : "\(session.name) hasn't reported a Docker daemon."
        }
        var parts = ["Docker \(info.version)", "API \(info.apiVersion)"]
        if let driver = info.storageDriver { parts.append(driver) }
        if let cgroup = info.cgroupVersion { parts.append("cgroup v\(cgroup)") }
        parts.append("\(Formatting.count(info.images)) image\(info.images == 1 ? "" : "s")")
        return parts.joined(separator: "  ·  ")
    }

    private var surfacePicker: some View {
        Picker("Show", selection: $surface) {
            ForEach(DockerSurface.allCases, id: \.self) { candidate in
                Text(candidate.title).tag(candidate)
            }
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(maxWidth: 440, alignment: .leading)
        .padding(.horizontal, Spacing.screen)
        .padding(.bottom, Spacing.element)
        .accessibilityLabel("Docker resource to show")
    }

    // MARK: - Summary strip

    /// Total, running, stopped and paused — as counts you can press.
    ///
    /// A count on its own is trivia. A count that filters the list below it is
    /// the fastest control on the screen, so every one of these is a button.
    private var summaryStrip: some View {
        HStack(spacing: Spacing.element) {
            ForEach(RunFilter.allCases, id: \.self) { filter in
                FilterPill(
                    title: filter.title,
                    count: DockerSection.count(scopedContainers, matching: filter),
                    tint: filter.tint,
                    isSelected: runFilter == filter
                ) {
                    withAnimation(Motion.immediate) { runFilter = filter }
                }
            }

            if let projectFilter {
                projectFilterChip(projectFilter)
            }

            Spacer(minLength: Spacing.element)

            Toggle("Group by Project", isOn: $groupsByProject)
                .toggleStyle(.checkbox)
                .controlSize(.small)
                .disabled(!hasComposeProjects)
                .help(hasComposeProjects
                      ? "Group containers by their Docker Compose project."
                      : "No container on this server carries a Compose project label.")

            Toggle("Live Stats", isOn: $showsLiveStats)
                .toggleStyle(.checkbox)
                .controlSize(.small)
                .help("Sample CPU and memory for every container every five seconds. Docker measures these one container at a time, so this costs a round trip each.")
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.bottom, Spacing.group)
    }

    private func projectFilterChip(_ name: String) -> some View {
        Button {
            withAnimation(Motion.immediate) { projectFilter = nil }
        } label: {
            HStack(spacing: Spacing.tight) {
                Image(systemName: "square.stack.3d.up")
                    .font(.system(size: 9, weight: .semibold))
                Text(name).font(Typography.metadata)
                Image(systemName: "xmark")
                    .font(.system(size: 8, weight: .bold))
            }
            .foregroundStyle(Palette.accent)
            .padding(.horizontal, Spacing.snug)
            .padding(.vertical, 3)
            .background(Palette.accentMuted, in: Capsule())
            .overlay(Capsule().strokeBorder(Palette.accent.opacity(0.25), lineWidth: 0.5))
        }
        .buttonStyle(.plain)
        .accessibilityLabel("Showing only the \(name) project. Activate to show every container.")
    }

    // MARK: - Content

    @ViewBuilder
    private var content: some View {
        if session.phase.isReady && !session.capabilities.docker {
            UnavailableState(
                subsystem: "Docker",
                reason: "\(session.name) isn't running a Docker daemon, or the agent can't reach its socket. "
                    + "ServerOS shows containers only where there is a daemon to talk to."
            )
        } else {
            switch surface {
            case .containers: containersContent
            case .images: imagesContent
            case .volumes: volumesContent
            case .networks: networksContent
            }
        }
    }

    // MARK: - Containers

    private var containersContent: some View {
        StatefulContent(containersState, retry: { Task { await session.refreshAll() } }) { groups in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: Spacing.between) {
                    ForEach(groups) { group in
                        containerGroupCard(group)
                    }
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.vertical, Spacing.group)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } empty: {
            containersEmptyState
        }
    }

    private func containerGroupCard(_ group: ContainerGroup) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            groupHeader(group)

            ForEach(group.containers) { container in
                ContainerRow(
                    container: container,
                    stats: liveStats[container.id],
                    inFlight: inFlight[container.id],
                    isSelected: selectedContainerID == container.id,
                    onSelect: { select(container) },
                    onStart: { perform(.start, on: container) },
                    onRestart: { perform(.restart, on: container) },
                    onStop: { askToStop(container, graceSeconds: DockerSection.defaultGraceSeconds) },
                    onStopAfter: { seconds in askToStop(container, graceSeconds: seconds) },
                    onPauseToggle: { perform(container.isPaused ? .unpause : .pause, on: container) },
                    onLogs: { logsTarget = LogsTarget(id: container.id, name: container.displayName) },
                    onRemove: { askToRemove(container) },
                    onCopyID: { copyToPasteboard(container.id) },
                    onCopyName: { copyToPasteboard(container.name) }
                )

                if container.id != group.containers.last?.id {
                    Divider()
                        .overlay(Palette.divider)
                        .padding(.leading, Spacing.card)
                }
            }
        }
        .padding(.vertical, Spacing.element)
        .cardSurface(scheme: scheme)
    }

    /// The group heading: what this application is called, and whether it is up.
    private func groupHeader(_ group: ContainerGroup) -> some View {
        HStack(spacing: Spacing.element) {
            Image(systemName: group.isProject ? "square.stack.3d.up" : "shippingbox")
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Palette.textMuted)
                .accessibilityHidden(true)

            Text(group.title)
                .font(Typography.sectionTitle)
                .foregroundStyle(Palette.textPrimary)

            Text(group.subtitle)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textSecondary)

            Spacer(minLength: Spacing.element)

            if group.isProject {
                Button("Open Project") { openProject(named: group.title) }
                    .buttonStyle(.rowAction)
                    .accessibilityLabel("Open the \(group.title) project")
            }
        }
        .padding(.horizontal, Spacing.card)
        .padding(.top, Spacing.snug)
        .padding(.bottom, Spacing.element)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(group.title), \(group.subtitle)")
        .accessibilityAddTraits(.isHeader)
    }

    private var containersEmptyState: some View {
        let filtered = isFiltering
        return EmptyState(
            systemImage: filtered ? "magnifyingglass" : "shippingbox",
            title: filtered ? "Nothing matches this view" : "No containers on this server",
            message: filtered
                ? "No container on \(session.name) matches \(filterDescription). Widen the search, or clear the filters."
                : "Docker is running on \(session.name) but nothing is deployed yet. Containers appear here the moment one starts.",
            actionTitle: filtered ? "Clear Search" : "Refresh",
            action: {
                if filtered {
                    clearFilters()
                } else {
                    Task { await session.refreshAll() }
                }
            }
        )
    }

    // MARK: - Images

    private var imagesContent: some View {
        StatefulContent(imagesState, retry: { reloadNonce += 1 }) { images in
            Table(images) {
                TableColumn("Image") { image in
                    Text(image.displayName)
                        .font(Typography.body)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .help(image.repoTags?.joined(separator: ", ") ?? image.displayName)
                }
                .width(min: 180, ideal: 320)

                TableColumn("ID") { image in
                    Text(image.shortID)
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textSecondary)
                        .textSelection(.enabled)
                }
                .width(min: 90, ideal: 112, max: 160)

                TableColumn("Size") { image in
                    Text(Formatting.bytes(image.sizeBytes))
                        .font(Typography.metricSmall)
                        .foregroundStyle(Palette.textPrimary)
                        .accessibilityLabel("Size")
                        .accessibilityValue(Formatting.bytes(image.sizeBytes))
                }
                .width(min: 72, ideal: 92, max: 130)

                TableColumn("Created") { image in
                    Text(Formatting.relative(unixSeconds: image.createdAt))
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(1)
                        .help(Formatting.timestamp(unixSeconds: image.createdAt))
                }
                .width(min: 100, ideal: 150, max: 220)

                TableColumn("Used By") { image in
                    // A dangling image is one nothing references any more — the
                    // usual answer to "why is /var/lib/docker full". Saying so
                    // is useful even while ServerOS will not delete it for you.
                    if image.dangling {
                        Chip("Dangling", tint: Palette.warning, systemImage: "questionmark.circle.fill")
                    } else if let count = image.containers, count > 0 {
                        Chip("\(Formatting.count(count)) container\(count == 1 ? "" : "s")", tint: Palette.healthy)
                    } else {
                        Text("—")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                    }
                }
                .width(min: 96, ideal: 128, max: 180)
            }
            .tableStyle(.inset)
            .padding(.horizontal, Spacing.card)
            .padding(.bottom, Spacing.card)
        } empty: {
            EmptyState(
                systemImage: "square.stack.3d.down.right",
                title: "No images on this server",
                message: "Docker on \(session.name) has nothing cached yet. Images appear here once something is pulled or built.",
                actionTitle: "Refresh",
                action: { reloadNonce += 1 }
            )
        }
    }

    // MARK: - Volumes

    private var volumesContent: some View {
        StatefulContent(volumesState, retry: { reloadNonce += 1 }) { volumes in
            Table(volumes) {
                TableColumn("Volume") { volume in
                    Text(volume.name)
                        .font(Typography.body)
                        .foregroundStyle(Palette.textPrimary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .width(min: 160, ideal: 260)

                TableColumn("Driver") { volume in
                    Text(volume.driver)
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                }
                .width(min: 64, ideal: 82, max: 120)

                TableColumn("Mount Point") { volume in
                    Text(volume.mountpoint)
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textMuted)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                        .help(volume.mountpoint)
                }
                .width(min: 160, ideal: 300)

                TableColumn("Size") { volume in
                    Text(Formatting.bytes(volume.sizeBytes))
                        .font(Typography.metricSmall)
                        .foregroundStyle(volume.sizeBytes == nil ? Palette.textMuted : Palette.textPrimary)
                        .accessibilityLabel("Size")
                        .accessibilityValue(volume.sizeBytes == nil ? "Not measured" : Formatting.bytes(volume.sizeBytes))
                }
                .width(min: 72, ideal: 92, max: 130)

                TableColumn("In Use") { volume in
                    // Three-valued on purpose: the agent says "unknown" when it
                    // could not ask Docker, and "unknown" must not look like
                    // "unused" on the one screen where that distinction decides
                    // whether someone deletes their database.
                    if volume.inUse == true {
                        Chip("In use", tint: Palette.healthy, systemImage: "checkmark")
                    } else if volume.inUse == false {
                        Chip("Unused", tint: Palette.inactive, systemImage: "minus")
                    } else {
                        Text("Unknown")
                            .font(Typography.metadata)
                            .foregroundStyle(Palette.textMuted)
                    }
                }
                .width(min: 86, ideal: 110, max: 150)
            }
            .tableStyle(.inset)
            .padding(.horizontal, Spacing.card)
            .padding(.bottom, Spacing.card)
        } empty: {
            EmptyState(
                systemImage: "externaldrive",
                title: "No volumes on this server",
                message: "Nothing running on \(session.name) has asked Docker for a named volume. Containers using bind mounts won't appear here.",
                actionTitle: "Refresh",
                action: { reloadNonce += 1 }
            )
        }
    }

    // MARK: - Networks

    private var networksContent: some View {
        StatefulContent(networksState, retry: { reloadNonce += 1 }) { networks in
            Table(networks) {
                TableColumn("Network") { network in
                    HStack(spacing: Spacing.snug) {
                        Text(network.name)
                            .font(Typography.body)
                            .foregroundStyle(Palette.textPrimary)
                            .lineLimit(1)
                        // Backticked because `internal` is a Swift keyword; the
                        // wire model spells the property the same way.
                        if network.`internal` {
                            Chip("Internal", tint: Palette.informational, systemImage: "lock.fill")
                        }
                    }
                }
                .width(min: 140, ideal: 220)

                TableColumn("Driver") { network in
                    Text(network.driver)
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                }
                .width(min: 64, ideal: 84, max: 120)

                TableColumn("Scope") { network in
                    Text(network.scope)
                        .font(Typography.secondary)
                        .foregroundStyle(Palette.textSecondary)
                }
                .width(min: 60, ideal: 76, max: 110)

                TableColumn("Subnet") { network in
                    Text(DockerSection.orDash(network.subnet))
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textMuted)
                        .textSelection(.enabled)
                }
                .width(min: 100, ideal: 140, max: 200)

                TableColumn("Gateway") { network in
                    Text(DockerSection.orDash(network.gateway))
                        .font(Typography.codeSmall)
                        .foregroundStyle(Palette.textMuted)
                        .textSelection(.enabled)
                }
                .width(min: 100, ideal: 140, max: 200)

                TableColumn("Containers") { network in
                    Text(network.containerCount.map { Formatting.count($0) } ?? "—")
                        .font(Typography.metricSmall)
                        .foregroundStyle(Palette.textSecondary)
                        .accessibilityLabel("Attached containers")
                        .accessibilityValue(network.containerCount.map { Formatting.count($0) } ?? "Unknown")
                }
                .width(min: 86, ideal: 104, max: 140)
            }
            .tableStyle(.inset)
            .padding(.horizontal, Spacing.card)
            .padding(.bottom, Spacing.card)
        } empty: {
            EmptyState(
                systemImage: "point.3.connected.trianglepath.dotted",
                title: "No networks on this server",
                message: "Docker normally creates a default bridge network on its own, so an empty list usually means the daemon has only just started.",
                actionTitle: "Refresh",
                action: { reloadNonce += 1 }
            )
        }
    }

    // MARK: - Inspector

    private var inspectorPresentation: Binding<Bool> {
        Binding(
            get: { selectedContainerID != nil },
            set: { isShown in if !isShown { selectedContainerID = nil } }
        )
    }

    @ViewBuilder
    private var inspectorContent: some View {
        if let id = selectedContainerID {
            ContainerInspector(
                containerID: id,
                session: session,
                onClose: { selectedContainerID = nil }
            )
            .inspectorColumnWidth(min: 320, ideal: 380, max: 520)
        }
    }

    // MARK: - Derived collections

    /// Every container, narrowed only by the project filter — the counts in the
    /// summary strip are filters themselves, so they must not filter themselves.
    private var scopedContainers: [DockerContainer] {
        guard let projectFilter else { return session.containers }
        return session.containers.filter { $0.composeProject == projectFilter }
    }

    private var visibleContainers: [DockerContainer] {
        let needle = searchText.trimmingCharacters(in: .whitespaces).lowercased()
        return scopedContainers
            .filter { container in
                guard runFilter.includes(container) else { return false }
                guard !needle.isEmpty else { return true }
                return container.name.lowercased().contains(needle)
                    || container.displayName.lowercased().contains(needle)
                    || container.image.lowercased().contains(needle)
                    || (container.composeProject?.lowercased().contains(needle) ?? false)
            }
            .sorted { $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending }
    }

    private var hasComposeProjects: Bool {
        session.containers.contains { ($0.composeProject?.isEmpty == false) }
    }

    private var containersState: ScreenState<[ContainerGroup]> {
        if session.containers.isEmpty {
            // Before the first contact this is genuinely still loading; after
            // it, the server really does have no containers.
            if session.lastContact == nil { return .loading }
            return .empty
        }
        let visible = visibleContainers
        if visible.isEmpty { return .empty }
        return .loaded(groups(from: visible))
    }

    private func groups(from containers: [DockerContainer]) -> [ContainerGroup] {
        guard groupsByProject, hasComposeProjects else {
            return [ContainerGroup(
                id: "all",
                title: "Containers",
                subtitle: DockerSection.runningLine(containers),
                isProject: false,
                containers: containers
            )]
        }

        var byProject: [String: [DockerContainer]] = [:]
        var standalone: [DockerContainer] = []
        for container in containers {
            if let project = container.composeProject, !project.isEmpty {
                byProject[project, default: []].append(container)
            } else {
                standalone.append(container)
            }
        }

        var result = byProject.keys.sorted().map { name in
            ContainerGroup(
                id: "project:\(name)",
                title: name,
                subtitle: DockerSection.runningLine(byProject[name] ?? []),
                isProject: true,
                containers: byProject[name] ?? []
            )
        }
        if !standalone.isEmpty {
            result.append(ContainerGroup(
                id: "standalone",
                title: "Not in a project",
                subtitle: DockerSection.runningLine(standalone),
                isProject: false,
                containers: standalone
            ))
        }
        return result
    }

    private static func runningLine(_ containers: [DockerContainer]) -> String {
        let running = containers.filter(\.isRunning).count
        return "\(running) of \(containers.count) running"
    }

    private static func count(_ containers: [DockerContainer], matching filter: RunFilter) -> Int {
        containers.filter { filter.includes($0) }.count
    }

    private var isFiltering: Bool {
        !searchText.trimmingCharacters(in: .whitespaces).isEmpty
            || runFilter != .all
            || projectFilter != nil
    }

    private var filterDescription: String {
        var parts: [String] = []
        let needle = searchText.trimmingCharacters(in: .whitespaces)
        if !needle.isEmpty { parts.append("“\(needle)”") }
        if runFilter != .all { parts.append("the \(runFilter.title.lowercased()) filter") }
        if let projectFilter { parts.append("the \(projectFilter) project") }
        return Formatting.list(parts)
    }

    private func clearFilters() {
        withAnimation(Motion.immediate) {
            searchText = ""
            runFilter = .all
            projectFilter = nil
        }
    }

    // MARK: - Navigation

    /// Another screen — or ⌘K — can ask this one to open something specific.
    /// The request is consumed here so returning to Docker later shows the
    /// screen as the user left it rather than re-opening an old selection.
    private func honourNavigationRequest() {
        if let requestedProject = navigation.selectedProjectName {
            surface = .containers
            projectFilter = requestedProject
            groupsByProject = true
            navigation.selectedProjectName = nil
        }

        if let requestedContainer = navigation.selectedContainerID {
            surface = .containers
            // The palette hands over a full id; a health finding may hand over a
            // name. Resolve either against what is on screen so the inspector
            // opens on the row the user is looking at.
            selectedContainerID = resolveContainerID(requestedContainer)
            navigation.selectedContainerID = nil
        }
    }

    private func resolveContainerID(_ token: String) -> String {
        if let match = session.containers.first(where: {
            $0.id == token || $0.shortID == token || $0.name == token || $0.displayName == token
        }) {
            return match.id
        }
        return token
    }

    private func select(_ container: DockerContainer) {
        withAnimation(Motion.panel) {
            selectedContainerID = (selectedContainerID == container.id) ? nil : container.id
        }
    }

    private func openProject(named name: String) {
        navigation.selectedProjectName = name
        navigation.select(section: .projects)
    }

    private func copyToPasteboard(_ value: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(value, forType: .string)
    }

    // MARK: - Container actions

    /// Run an action optimistically.
    ///
    /// The row flips to a pending chip immediately because a restart takes
    /// seconds on the server and an unresponsive row reads as a broken app. The
    /// live stream is then the authority: we wait for it to show the container
    /// in its new state and only fall back to asking the agent if it never
    /// does. On failure the pending chip is simply dropped, which restores the
    /// row exactly — it was the only thing this method changed.
    private func perform(_ action: ContainerAction, on container: DockerContainer, graceSeconds: Int? = nil) {
        guard let api = session.api else {
            failure = ActionFailure(message: failureMessage(action, container.displayName, .sshNotConnected))
            return
        }

        let id = container.id
        let name = container.displayName

        withAnimation(Motion.status) {
            inFlight[id] = InFlightAction(action: action, name: name)
            failure = nil
        }

        Task {
            do {
                try await api.performContainerAction(action, id: id, graceSeconds: graceSeconds)
                await waitForStream(toSettle: id, after: action)
            } catch let error as ServerOSError {
                failure = ActionFailure(message: failureMessage(action, name, error))
            } catch {
                failure = ActionFailure(
                    message: failureMessage(action, name, ServerOSError.transport(error, serverName: session.name))
                )
            }
            withAnimation(Motion.status) { inFlight[id] = nil }
        }
    }

    private func waitForStream(toSettle id: String, after action: ContainerAction) async {
        if action == .restart {
            // Running before, running after: there is no transition to observe,
            // so hold the pending chip long enough for the click to have
            // registered visually and let the new uptime speak for itself.
            try? await Task.sleep(for: DockerSection.restartDwell)
            return
        }

        let deadline = Date().addingTimeInterval(DockerSection.optimismTimeout)
        while Date() < deadline {
            try? await Task.sleep(for: DockerSection.optimismPoll)
            if Task.isCancelled { return }
            guard let live = session.containers.first(where: { $0.id == id }) else { return }
            if DockerSection.hasSettled(live, after: action) { return }
        }

        // The stream never confirmed it. Ask once rather than leaving a row
        // spinning on a promise nobody kept.
        await session.refreshAll()
    }

    private static func hasSettled(_ container: DockerContainer, after action: ContainerAction) -> Bool {
        switch action {
        case .start, .unpause, .restart: return container.isRunning
        case .stop: return container.isStopped
        case .pause: return container.isPaused
        }
    }

    private func failureMessage(_ action: ContainerAction, _ name: String, _ error: ServerOSError) -> String {
        "ServerOS couldn't \(DockerSection.verb(for: action)) \(name). \(error.headline)"
    }

    private static func verb(for action: ContainerAction) -> String {
        switch action {
        case .start: return "start"
        case .stop: return "stop"
        case .restart: return "restart"
        case .pause: return "pause"
        case .unpause: return "resume"
        }
    }

    // MARK: - Stop

    private func askToStop(_ container: DockerContainer, graceSeconds: Int) {
        pendingStop = PendingContainer(id: container.id, name: container.displayName, graceSeconds: graceSeconds)
        isConfirmingStop = true
    }

    private var stopConsequence: String {
        guard let pending = pendingStop else { return "" }
        let grace = pending.graceSeconds
        if grace <= 0 {
            return "ServerOS will stop \(pending.name) immediately, with no time to finish what it is doing. "
                + "Anything depending on it will fail while it is down, and you can start it again from this screen."
        }
        return "ServerOS will ask \(pending.name) to shut down and give it \(grace) second\(grace == 1 ? "" : "s") "
            + "to exit cleanly before Docker stops it. Anything depending on it will fail while it is down, "
            + "and you can start it again from this screen."
    }

    private func confirmStop() {
        guard let pending = pendingStop else { return }
        pendingStop = nil
        guard let container = session.containers.first(where: { $0.id == pending.id }) else {
            failure = ActionFailure(message: "\(pending.name) is no longer on this server, so there was nothing to stop.")
            return
        }
        perform(.stop, on: container, graceSeconds: pending.graceSeconds)
    }

    // MARK: - Remove

    private func askToRemove(_ container: DockerContainer) {
        pendingRemoval = PendingContainer(id: container.id, name: container.displayName, graceSeconds: 0)
        isConfirmingRemoval = true
    }

    private var removalConsequence: String {
        let name = pendingRemoval?.name ?? "this container"
        return "ServerOS will delete \(name) and its configuration from \(session.name). "
            + "Choosing “Remove Container and Volumes” also deletes the data in its named volumes — "
            + "databases, uploads and anything else written there.\n\nThis cannot be undone."
    }

    private func remove(includingVolumes: Bool) {
        guard let pending = pendingRemoval else { return }
        pendingRemoval = nil

        guard let api = session.api else {
            failure = ActionFailure(message: "ServerOS couldn't remove \(pending.name). \(ServerOSError.sshNotConnected.headline)")
            return
        }

        Task {
            do {
                // `force` because the confirmation already said the container
                // goes: making the user stop it first and then remove it is two
                // dialogs for one decision they have already made.
                try await api.removeContainer(id: pending.id, force: true, removeVolumes: includingVolumes)
                if selectedContainerID == pending.id { selectedContainerID = nil }
                await session.refreshAll()
            } catch let error as ServerOSError {
                failure = ActionFailure(message: "ServerOS couldn't remove \(pending.name). \(error.headline)")
            } catch {
                let wrapped = ServerOSError.transport(error, serverName: session.name)
                failure = ActionFailure(message: "ServerOS couldn't remove \(pending.name). \(wrapped.headline)")
            }
        }
    }

    // MARK: - Loading

    /// Everything that should make this screen ask the agent again.
    private struct SurfaceLoad: Equatable {
        let surface: DockerSurface
        let nonce: Int
        let isReady: Bool
        let hasDocker: Bool
    }

    private var surfaceLoad: SurfaceLoad {
        SurfaceLoad(
            surface: surface,
            nonce: reloadNonce,
            isReady: session.phase.isReady,
            hasDocker: session.capabilities.docker
        )
    }

    private struct StatsLoad: Equatable {
        let enabled: Bool
        let surface: DockerSurface
        let isReady: Bool
    }

    private var statsLoad: StatsLoad {
        StatsLoad(enabled: showsLiveStats, surface: surface, isReady: session.phase.isReady)
    }

    private func loadCurrentSurface() async {
        guard let api = session.api, session.capabilities.docker else { return }

        // The daemon line is wanted on every surface and is one cheap call.
        if info == nil {
            info = try? await api.dockerInfo()
        }

        switch surface {
        case .containers:
            // Deliberately nothing: the live stream owns this list.
            break
        case .images:
            await loadImages(api)
        case .volumes:
            await loadVolumes(api)
        case .networks:
            await loadNetworks(api)
        }
    }

    private func loadImages(_ api: AgentAPI) async {
        if imagesState.value == nil { imagesState = .loading }
        do {
            let items = try await api.images()
            imagesState = items.isEmpty ? .empty : .loaded(items)
        } catch let error as ServerOSError {
            imagesState = .failed(error)
        } catch {
            imagesState = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }

    private func loadVolumes(_ api: AgentAPI) async {
        if volumesState.value == nil { volumesState = .loading }
        do {
            let items = try await api.volumes()
            volumesState = items.isEmpty ? .empty : .loaded(items)
        } catch let error as ServerOSError {
            volumesState = .failed(error)
        } catch {
            volumesState = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }

    private func loadNetworks(_ api: AgentAPI) async {
        if networksState.value == nil { networksState = .loading }
        do {
            let items = try await api.networks()
            networksState = items.isEmpty ? .empty : .loaded(items)
        } catch let error as ServerOSError {
            networksState = .failed(error)
        } catch {
            networksState = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }

    /// Sample per-container CPU and memory while the toggle is on.
    ///
    /// Opt-in because Docker's stats endpoint is a round trip per container:
    /// on a host with forty containers, polling it by default would make the
    /// nicest screen in the app the most expensive one.
    private func pollLiveStats() async {
        guard showsLiveStats, surface == .containers, let api = session.api else {
            liveStats = [:]
            return
        }

        while !Task.isCancelled {
            if let list = try? await api.containers(all: true, stats: true) {
                var next: [String: LiveStatsSample] = [:]
                for item in list.items {
                    next[item.id] = LiveStatsSample(
                        cpuPercent: item.cpuPercent,
                        memoryBytes: item.memoryBytes
                    )
                }
                liveStats = next
            }
            try? await Task.sleep(for: DockerSection.statsInterval)
        }
    }

    // MARK: - Small helpers

    private static func orDash(_ value: String?) -> String {
        guard let value, !value.isEmpty else { return "—" }
        return value
    }
}

// MARK: - Vocabulary
//
// Everything below is file-scoped: sibling sections are being written alongside
// this one, and none of these carry a decision worth sharing across screens.

/// Which Docker resource the screen is showing.
private enum DockerSurface: String, CaseIterable, Hashable {
    case containers, images, volumes, networks

    var title: String {
        switch self {
        case .containers: return "Containers"
        case .images: return "Images"
        case .volumes: return "Volumes"
        case .networks: return "Networks"
        }
    }
}

/// The clickable counts across the top.
private enum RunFilter: String, CaseIterable, Hashable {
    case all, running, stopped, paused

    var title: String {
        switch self {
        case .all: return "Total"
        case .running: return "Running"
        case .stopped: return "Stopped"
        case .paused: return "Paused"
        }
    }

    var tint: Color {
        switch self {
        case .all: return Palette.accent
        case .running: return Palette.healthy
        case .stopped: return Palette.inactive
        case .paused: return Palette.informational
        }
    }

    /// Membership uses the model's own definitions, so a count and the list it
    /// filters can never disagree.
    func includes(_ container: DockerContainer) -> Bool {
        switch self {
        case .all: return true
        case .running: return container.isRunning
        case .stopped: return container.isStopped
        case .paused: return container.isPaused
        }
    }
}

/// One heading's worth of containers.
private struct ContainerGroup: Identifiable {
    let id: String
    let title: String
    let subtitle: String
    let isProject: Bool
    let containers: [DockerContainer]
}

/// An action that has been sent but not yet confirmed by the stream.
private struct InFlightAction: Equatable {
    let action: ContainerAction
    let name: String
}

/// A failure worth a banner. Identity is its own, so a second failure with the
/// same words still animates in as a new message.
private struct ActionFailure: Identifiable {
    let id = UUID()
    let message: String
}

/// A container a confirmation is about.
private struct PendingContainer: Equatable {
    let id: String
    let name: String
    let graceSeconds: Int
}

/// The container whose logs are open in a sheet.
private struct LogsTarget: Identifiable, Equatable {
    let id: String
    let name: String
}

/// One sample of live stats, keyed by container id.
private struct LiveStatsSample: Equatable {
    let cpuPercent: Double?
    let memoryBytes: Int64?
}

// MARK: - Filter pill

/// A count you can press.
private struct FilterPill: View {
    let title: String
    let count: Int
    let tint: Color
    let isSelected: Bool
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack(spacing: Spacing.snug) {
                Text(Formatting.count(count))
                    .font(Typography.metricSmall)
                    .foregroundStyle(isSelected ? tint : Palette.textPrimary)
                    .contentTransition(.numericText())
                Text(title)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }
            .padding(.horizontal, Spacing.element)
            .padding(.vertical, Spacing.snug)
            .background(
                isSelected ? tint.opacity(0.12) : (isHovered ? Palette.hoverFill.opacity(0.5) : Color.clear),
                in: RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
            )
            .overlay(
                RoundedRectangle(cornerRadius: Radius.medium, style: .continuous)
                    .strokeBorder(isSelected ? tint.opacity(0.45) : Palette.divider, lineWidth: isSelected ? 1 : 0.5)
            )
            .contentShape(RoundedRectangle(cornerRadius: Radius.medium, style: .continuous))
        }
        .buttonStyle(.plain)
        .onHover { hovering in
            withAnimation(Motion.immediate) { isHovered = hovering }
        }
        .animation(Motion.value, value: count)
        .accessibilityLabel(title)
        .accessibilityValue("\(Formatting.count(count)) containers")
        .accessibilityAddTraits(isSelected ? [.isButton, .isSelected] : [.isButton])
    }
}

// MARK: - Container row

/// One container: what it is, how it is, and what you can do to it.
///
/// The actions occupy their slot whether or not they are visible, so a row
/// never changes width under the pointer — the difference between "alive" and
/// "jittery". They are hidden from VoiceOver because the same actions are
/// attached to the row itself as accessibility actions, which is reachable
/// without a pointer at all.
private struct ContainerRow: View {
    let container: DockerContainer
    let stats: LiveStatsSample?
    let inFlight: InFlightAction?
    let isSelected: Bool
    let onSelect: () -> Void
    let onStart: () -> Void
    let onRestart: () -> Void
    let onStop: () -> Void
    let onStopAfter: (Int) -> Void
    let onPauseToggle: () -> Void
    let onLogs: () -> Void
    let onRemove: () -> Void
    let onCopyID: () -> Void
    let onCopyName: () -> Void

    @State private var isHovered = false

    private var isRevealed: Bool { isHovered || inFlight != nil }

    var body: some View {
        HStack(spacing: Spacing.group) {
            statusSlot
            identityView
            Spacer(minLength: Spacing.element)
            portsView
            metricsView
            uptimeView
            actionsView
        }
        .padding(.horizontal, Spacing.card)
        .padding(.vertical, Spacing.element)
        .frame(minHeight: Layout.comfortableRowHeight)
        .contentShape(Rectangle())
        .hoverHighlight(isSelected: isSelected, radius: Radius.medium)
        .onHover { hovering in
            withAnimation(Motion.immediate) { isHovered = hovering }
        }
        .onTapGesture(perform: onSelect)
        .contextMenu { contextMenuItems }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(rowAccessibilityLabel)
        .accessibilityValue(rowAccessibilityValue)
        .accessibilityAction(named: Text("Open Details"), onSelect)
        .accessibilityAction(named: Text("View Logs"), onLogs)
        .accessibilityAction(named: Text(container.isRunning ? "Restart" : "Start"), container.isRunning ? onRestart : onStart)
        .accessibilityAction(named: Text("Stop"), onStop)
    }

    // MARK: Status

    @ViewBuilder
    private var statusSlot: some View {
        Group {
            if let inFlight {
                // A pending action is a transition, not a state. `RunPill` has
                // no word for "Stopping…", and tinting the pill instead would
                // make colour carry the meaning on its own.
                Chip(
                    inFlight.action.inProgressLabel,
                    tint: Palette.warning,
                    systemImage: "arrow.triangle.2.circlepath"
                )
            } else {
                RunPill(RunPill.RunState.fromContainer(container.state))
            }
        }
        .frame(width: 104, alignment: .leading)
    }

    // MARK: Identity

    private var identityView: some View {
        VStack(alignment: .leading, spacing: 1) {
            HStack(spacing: Spacing.snug) {
                Text(container.displayName)
                    .font(Typography.body.weight(.medium))
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                healthMarker
            }
            Text(container.image)
                .font(Typography.codeSmall)
                .foregroundStyle(Palette.textMuted)
                .lineLimit(1)
                .truncationMode(.middle)
                .help(container.image)
        }
        .frame(minWidth: 140, idealWidth: 230, maxWidth: 300, alignment: .leading)
    }

    /// Docker's own health check, when the image declares one. Absent is not
    /// the same as healthy, so nothing is drawn when there is no check.
    @ViewBuilder
    private var healthMarker: some View {
        if let health = container.health, !health.isEmpty, health != "none" {
            Chip(
                ContainerRow.healthLabel(health),
                tint: ContainerRow.healthTint(health),
                systemImage: ContainerRow.healthSymbol(health)
            )
        }
    }

    private static func healthLabel(_ health: String) -> String {
        switch health {
        case "healthy": return "Healthy"
        case "unhealthy": return "Unhealthy"
        case "starting": return "Starting"
        default: return health.capitalizingFirstLetter()
        }
    }

    private static func healthTint(_ health: String) -> Color {
        switch health {
        case "healthy": return Palette.healthy
        case "unhealthy": return Palette.critical
        case "starting": return Palette.warning
        default: return Palette.inactive
        }
    }

    private static func healthSymbol(_ health: String) -> String {
        switch health {
        case "healthy": return "checkmark.seal.fill"
        case "unhealthy": return "exclamationmark.triangle.fill"
        case "starting": return "clock.fill"
        default: return "questionmark"
        }
    }

    // MARK: Ports

    @ViewBuilder
    private var portsView: some View {
        if !container.ports.isEmpty {
            HStack(spacing: Spacing.tight) {
                ForEach(container.ports.prefix(2)) { port in
                    Chip(port.describedMapping, tint: Palette.informational)
                }
                if container.ports.count > 2 {
                    Chip("+\(container.ports.count - 2)", tint: Palette.inactive)
                }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Ports")
            .accessibilityValue(container.ports.map(\.describedMapping).joined(separator: ", "))
        }
    }

    // MARK: Metrics

    private var metricsView: some View {
        HStack(spacing: Spacing.group) {
            metricColumn(value: cpuText, label: "CPU", width: 54)
            metricColumn(value: memoryText, label: "Memory", width: 72)
        }
    }

    private func metricColumn(value: String, label: String, width: CGFloat) -> some View {
        VStack(alignment: .trailing, spacing: 0) {
            Text(value)
                .font(Typography.metricSmall)
                .foregroundStyle(value == "—" ? Palette.textMuted : Palette.textPrimary)
                .contentTransition(.numericText())
            Text(label)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
        }
        .frame(width: width, alignment: .trailing)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
        .accessibilityValue(value == "—" ? "Not sampled" : value)
    }

    /// Stats sampled by the screen win over whatever the stream happened to
    /// carry, because they are the newer of the two.
    private var cpuText: String {
        Formatting.percent(stats?.cpuPercent ?? container.cpuPercent)
    }

    private var memoryText: String {
        Formatting.bytes(stats?.memoryBytes ?? container.memoryBytes)
    }

    // MARK: Uptime

    private var uptimeView: some View {
        Text(uptimeText)
            .font(Typography.metadata)
            .foregroundStyle(Palette.textMuted)
            .lineLimit(1)
            .frame(width: 110, alignment: .trailing)
            .help(Formatting.containerState(container.state, status: container.status))
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Status")
            .accessibilityValue(Formatting.containerState(container.state, status: container.status))
    }

    private var uptimeText: String {
        if container.isRunning, let started = container.startedAt, started > 0 {
            let seconds = Int(Date().timeIntervalSince1970) - Int(started)
            return seconds > 0 ? "up \(Formatting.durationCompact(seconds: seconds))" : "just started"
        }
        return Formatting.truncate(
            Formatting.containerState(container.state, status: container.status),
            to: 20
        )
    }

    // MARK: Actions

    private var actionsView: some View {
        HStack(spacing: Spacing.tight) {
            if container.isPaused {
                Button("Resume", action: onPauseToggle)
                    .buttonStyle(RowActionButtonStyle(tint: Palette.healthy))
            } else if container.isRunning {
                Button("Restart", action: onRestart)
                    .buttonStyle(.rowAction)
                Button("Stop", action: onStop)
                    .buttonStyle(RowActionButtonStyle(tint: Palette.warning))
            } else {
                Button("Start", action: onStart)
                    .buttonStyle(RowActionButtonStyle(tint: Palette.healthy))
            }
        }
        .disabled(inFlight != nil)
        .frame(width: 134, alignment: .trailing)
        .opacity(isRevealed ? 1 : 0)
        .allowsHitTesting(isRevealed)
        .animation(Motion.immediate, value: isRevealed)
        .accessibilityHidden(true)
    }

    @ViewBuilder
    private var contextMenuItems: some View {
        if container.isPaused {
            Button("Resume", action: onPauseToggle)
            Button("Stop…", action: onStop)
        } else if container.isRunning {
            Button("Restart", action: onRestart)
            Button("Stop…", action: onStop)
            // The grace period lives here rather than in the dialog, because a
            // `confirmationDialog` cannot hold a control and a stepper in a
            // menu is where people already look for "…but differently".
            Menu("Stop After") {
                Button("Immediately", action: { onStopAfter(0) })
                Button("10 Seconds", action: { onStopAfter(10) })
                Button("30 Seconds", action: { onStopAfter(30) })
                Button("60 Seconds", action: { onStopAfter(60) })
            }
            Button("Pause", action: onPauseToggle)
        } else {
            Button("Start", action: onStart)
        }

        Divider()

        Button("View Logs", action: onLogs)
        Button("Open Details", action: onSelect)
        Button("Copy Container ID", action: onCopyID)
        Button("Copy Name", action: onCopyName)

        Divider()

        Button("Remove…", role: .destructive, action: onRemove)
    }

    // MARK: Accessibility
    //
    // Named `rowAccessibility…` rather than `accessibilityLabel`: `View` already
    // has methods by those names, and a property that shadows one makes every
    // reference to it ambiguous.

    private var rowAccessibilityLabel: String {
        if let inFlight {
            return "\(container.displayName), \(inFlight.action.inProgressLabel)"
        }
        return "\(container.displayName), \(RunPill.RunState.fromContainer(container.state).label)"
    }

    private var rowAccessibilityValue: String {
        var parts = [container.image]
        if let health = container.health, !health.isEmpty, health != "none" {
            parts.append(ContainerRow.healthLabel(health))
        }
        if !container.ports.isEmpty {
            parts.append("ports \(container.ports.map(\.describedMapping).joined(separator: ", "))")
        }
        parts.append(uptimeText)
        return parts.joined(separator: ", ")
    }
}

// MARK: - Preview

private struct DockerPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        DockerSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 1100, height: 720)
            .onAppear {
                navigation.enter(serverID: session.id, section: .docker)
                session.connect()
            }
    }
}

#Preview("Docker") {
    DockerPreviewHost()
}
