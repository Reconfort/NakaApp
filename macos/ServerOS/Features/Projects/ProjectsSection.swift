//  ProjectsSection.swift
//  ServerOS
//
//  Applications, not label queries.
//
//  Docker's own mental model stops at the container. The thing a person
//  deployed, worries about and gets paged for is the *application* — the API,
//  its worker, its database and its cache, which Compose started together and
//  which fail together. ServerOS recovers that grouping from the
//  `com.docker.compose.project` label the Compose CLI writes onto every
//  container it starts, and this screen is where it lives.
//
//  Three decisions worth stating:
//
//  * **A project has one state, and "partial" is the interesting one.** Fully
//    up and fully down are both fine — somebody chose them. Some-up-some-down
//    is the state that usually means something broke quietly at 03:00, so it
//    gets its own word ("Degraded") and the warning colour, rather than being
//    rounded to "running" because most of it is.
//
//  * **Lifecycle actions for a single container stay in Docker.** This screen
//    can restart a whole project, because that is a project-shaped decision.
//    Restarting one container is a Docker-shaped decision, and implementing the
//    optimistic-row machinery a second time here would be a second thing to
//    keep correct. The row offers "Open" instead, which takes you to the place
//    that owns those actions.
//
//  * **Restart All goes one container at a time.** Restarting a Compose project
//    in parallel can take the database down while the API is still talking to
//    it, which turns a clean restart into a minute of errors. Sequential, in
//    Docker's own order, is slower and far more predictable — and the progress
//    banner names whichever container it is on, so the wait is legible.

import Combine
import SwiftUI

/// The applications running on one server.
public struct ProjectsSection: View {

    /// The grace period each container gets during a project restart. The same
    /// ten seconds Docker itself defaults to.
    private static let restartGraceSeconds = 10

    /// How many recent events the project detail shows. Enough to see what just
    /// happened, short enough to stay a glance rather than a screen.
    private static let activityLimit = 12

    @Environment(\.colorScheme) private var scheme

    private let session: ServerSession
    private let navigation: NavigationModel

    @State private var state: ScreenState<[Project]> = .loading
    @State private var selectedProject: String?
    @State private var reloadNonce = 0
    @State private var isRestarting = false
    @State private var restartProgress: String?
    @State private var failure: String?
    @State private var isConfirmingRestartAll = false

    public init(session: ServerSession, navigation: NavigationModel) {
        self.session = session
        self.navigation = navigation
    }

    public var body: some View {
        VStack(spacing: 0) {
            if let project = activeProject {
                detailHeader(project)
            } else {
                listHeader
            }

            if let restartProgress {
                InlineBanner(.info, restartProgress)
                    .padding(.horizontal, Spacing.screen)
                    .padding(.bottom, Spacing.element)
                    .transition(.opacity)
            }

            if let failure {
                InlineBanner(.error, failure, actionTitle: "Dismiss") {
                    self.failure = nil
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.bottom, Spacing.element)
                .transition(.opacity)
            }

            Divider().overlay(Palette.divider)

            if let project = activeProject {
                detailContent(project)
            } else {
                listContent
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        .animation(Motion.appear, value: restartProgress)
        // Honoured on appear only. "Open in Docker" sets this same field on its
        // way out, so watching it would make this screen re-select the project
        // it is in the middle of leaving.
        .onAppear { honourNavigationRequest() }
        .task(id: loadKey) { await load() }
        .onChange(of: session.phase.isReady) { _, isReady in
            if isReady { reloadNonce += 1 }
        }
        .onChange(of: session.capabilities) { _, _ in reloadNonce += 1 }
        .onReceive(NotificationCenter.default.publisher(for: .serverOSRefreshRequested)) { _ in
            reloadNonce += 1
            Task { await session.refreshAll() }
        }
        .confirmDestructive(
            isPresented: $isConfirmingRestartAll,
            title: activeProject.map { "Restart every container in \($0.name)?" } ?? "Restart this project?",
            target: activeProject?.name ?? "",
            consequence: restartConsequence,
            // A restart genuinely cannot be undone: the processes that were
            // running are gone, whatever they were part-way through.
            isReversible: false,
            confirmTitle: "Restart All"
        ) {
            if let project = activeProject {
                restartAll(project)
            }
        }
    }

    // MARK: - List

    private var listHeader: some View {
        HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text("Projects")
                    .font(Typography.pageTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                Text(listSubtitle)
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
                    .lineLimit(1)
            }
            Spacer(minLength: Spacing.group)
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.top, Spacing.group)
        .padding(.bottom, Spacing.element)
    }

    private var listSubtitle: String {
        guard let projects = state.value else {
            return "Looking for Compose projects on \(session.name)…"
        }
        let degraded = projects.filter(\.isPartiallyRunning).count
        let stopped = projects.filter { !$0.isFullyRunning && !$0.isPartiallyRunning }.count
        var parts = ["\(Formatting.count(projects.count)) application\(projects.count == 1 ? "" : "s") on \(session.name)"]
        if degraded > 0 { parts.append("\(degraded) degraded") }
        if stopped > 0 { parts.append("\(stopped) stopped") }
        return parts.joined(separator: "  ·  ")
    }

    private var listContent: some View {
        StatefulContent(state, retry: { reloadNonce += 1 }) { projects in
            ScrollView {
                LazyVStack(alignment: .leading, spacing: Spacing.between) {
                    ForEach(projects) { project in
                        ProjectCard(
                            project: project,
                            containers: containers(for: project),
                            onOpen: { openDetail(project) },
                            onOpenInDocker: { openInDocker(project) }
                        )
                    }
                }
                .padding(.horizontal, Spacing.screen)
                .padding(.vertical, Spacing.group)
                .frame(maxWidth: .infinity, alignment: .leading)
            }
        } empty: {
            emptyState
        }
    }

    private var emptyState: some View {
        EmptyState(
            systemImage: "square.stack.3d.up",
            title: "No projects on this server",
            message: "ServerOS recognises an application from the com.docker.compose.project label that Docker Compose "
                + "puts on every container it starts. Nothing on \(session.name) carries one, so its containers appear "
                + "in Docker on their own.",
            actionTitle: "Open Docker",
            action: { navigation.select(section: .docker) }
        )
    }

    // MARK: - Detail

    private func detailHeader(_ project: Project) -> some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            Button {
                withAnimation(Motion.panel) { selectedProject = nil }
            } label: {
                HStack(spacing: Spacing.tight) {
                    Image(systemName: "chevron.left")
                        .font(.system(size: 10, weight: .semibold))
                    Text("Projects")
                        .font(Typography.secondary)
                }
                .foregroundStyle(Palette.accent)
            }
            .buttonStyle(.plain)
            .accessibilityLabel("Back to all projects")

            HStack(alignment: .top, spacing: Spacing.group) {
                VStack(alignment: .leading, spacing: Spacing.snug) {
                    HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
                        Text(project.name)
                            .font(Typography.display)
                            .foregroundStyle(Palette.textPrimary)
                            .lineLimit(1)
                            .accessibilityAddTraits(.isHeader)
                        ProjectStatePill(project: project)
                    }

                    Text(detailSubtitle(project))
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textSecondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }

                Spacer(minLength: Spacing.group)

                Button("Open in Docker") { openInDocker(project) }
                    .buttonStyle(.secondary)

                Button("Restart All…") { isConfirmingRestartAll = true }
                    .buttonStyle(.destructive)
                    .disabled(isRestarting || containers(for: project).isEmpty)
            }
        }
        .padding(.horizontal, Spacing.screen)
        .padding(.top, Spacing.group)
        .padding(.bottom, Spacing.element)
    }

    private func detailSubtitle(_ project: Project) -> String {
        var parts = [ProjectsSection.composition(project: project, containers: containers(for: project))]
        parts.append("\(project.running) of \(project.containerCount) running")
        if let directory = project.workingDir, !directory.isEmpty {
            parts.append(directory)
        }
        return parts.joined(separator: "  ·  ")
    }

    private func detailContent(_ project: Project) -> some View {
        let members = containers(for: project)
        return ScrollView {
            VStack(alignment: .leading, spacing: Spacing.between) {
                resourcesCard(project, members)
                containersCard(project, members)
                activityCard(project, members)
            }
            .padding(.horizontal, Spacing.screen)
            .padding(.vertical, Spacing.group)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    /// What this application is costing the server, and how to reach it.
    private func resourcesCard(_ project: Project, _ members: [DockerContainer]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader("Resources")

            HStack(alignment: .top, spacing: Spacing.section) {
                MetricTile(
                    label: "CPU",
                    value: ProjectsSection.aggregateCPU(members),
                    caption: "Summed across \(Formatting.count(members.count)) container\(members.count == 1 ? "" : "s")"
                )
                MetricTile(
                    label: "Memory",
                    value: memoryPercent(ProjectsSection.aggregateMemory(members)),
                    caption: Formatting.usage(
                        used: ProjectsSection.aggregateMemory(members),
                        total: session.metrics?.memory.totalBytes
                    )
                )
                Spacer(minLength: 0)
            }

            let ports = ProjectsSection.ports(members)
            if ports.isEmpty {
                Text("None of \(project.name)'s containers expose a port, so it is reachable only from inside its own Docker network.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(alignment: .leading, spacing: Spacing.tight) {
                    Text("Ports")
                        .font(Typography.metadata)
                        .foregroundStyle(Palette.textSecondary)
                        .textCase(.uppercase)
                        .tracking(0.4)
                    LazyVGrid(
                        columns: [GridItem(.adaptive(minimum: 110), spacing: Spacing.tight, alignment: .leading)],
                        alignment: .leading,
                        spacing: Spacing.tight
                    ) {
                        ForEach(ports) { port in
                            Chip(port.describedMapping, tint: Palette.informational)
                        }
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Ports")
                .accessibilityValue(ports.map(\.describedMapping).joined(separator: ", "))
            }
        }
        .padding(Spacing.card)
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardSurface(scheme: scheme)
    }

    private func containersCard(_ project: Project, _ members: [DockerContainer]) -> some View {
        VStack(alignment: .leading, spacing: Spacing.element) {
            SectionHeader("Containers", count: members.count)
                .padding(.horizontal, Spacing.card)
                .padding(.top, Spacing.card)

            if members.isEmpty {
                Text("\(project.name) has no containers right now. Compose knows about it, but nothing from it is on this server.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, Spacing.card)
                    .padding(.bottom, Spacing.card)
            } else {
                VStack(spacing: 0) {
                    ForEach(members) { container in
                        ProjectContainerRow(container: container) {
                            openInDocker(project, container: container)
                        }
                        if container.id != members.last?.id {
                            Divider()
                                .overlay(Palette.divider)
                                .padding(.leading, Spacing.card)
                        }
                    }
                }
                .padding(.bottom, Spacing.element)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardSurface(scheme: scheme)
    }

    private func activityCard(_ project: Project, _ members: [DockerContainer]) -> some View {
        let events = activity(for: project, members: members)
        return VStack(alignment: .leading, spacing: Spacing.group) {
            SectionHeader("Recent Activity", count: events.isEmpty ? nil : events.count)

            if events.isEmpty {
                Text("Nothing has happened to \(project.name) recently. Restarts, deployments and removals appear here as the agent records them.")
                    .font(Typography.secondary)
                    .foregroundStyle(Palette.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                VStack(alignment: .leading, spacing: Spacing.element) {
                    ForEach(events) { event in
                        ProjectActivityRow(event: event)
                    }
                }
            }
        }
        .padding(Spacing.card)
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardSurface(scheme: scheme)
    }

    // MARK: - Derived data

    private var activeProject: Project? {
        guard let selectedProject, let projects = state.value else { return nil }
        return projects.first { $0.name == selectedProject }
    }

    /// The live container list wins over the one that came with the project:
    /// the stream is seconds old, the project response is however old the last
    /// fetch was.
    private func containers(for project: Project) -> [DockerContainer] {
        let live = session.containers.filter { $0.composeProject == project.name }
        let source = live.isEmpty ? (project.containers ?? []) : live
        return source.sorted { $0.displayName.localizedStandardCompare($1.displayName) == .orderedAscending }
    }

    private func activity(for project: Project, members: [DockerContainer]) -> [ActivityEvent] {
        // The agent records container events by whichever identifier the caller
        // used, so match on every name this container answers to.
        var tokens = Set<String>()
        for container in members {
            tokens.insert(container.id)
            tokens.insert(container.shortID)
            tokens.insert(container.name)
            tokens.insert(container.displayName)
        }

        let matching = session.activity.filter { event in
            if event.resourceType == "project" { return event.resourceID == project.name }
            return tokens.contains(event.resourceID)
        }
        return Array(matching.prefix(ProjectsSection.activityLimit))
    }

    private func memoryPercent(_ bytes: Int64?) -> Double? {
        guard let bytes, let total = session.metrics?.memory.totalBytes, total > 0 else { return nil }
        return Double(bytes) / Double(total) * 100
    }

    private static func aggregateCPU(_ containers: [DockerContainer]) -> Double? {
        let samples = containers.compactMap(\.cpuPercent)
        guard !samples.isEmpty else { return nil }
        return samples.reduce(0, +)
    }

    private static func aggregateMemory(_ containers: [DockerContainer]) -> Int64? {
        let samples = containers.compactMap(\.memoryBytes)
        guard !samples.isEmpty else { return nil }
        return samples.reduce(0, +)
    }

    private static func ports(_ containers: [DockerContainer]) -> [DockerPort] {
        var seen = Set<String>()
        var result: [DockerPort] = []
        for container in containers {
            for port in container.ports where seen.insert(port.id).inserted {
                result.append(port)
            }
        }
        return result
    }

    /// "3 containers · 1 database · 2 services".
    ///
    /// Databases are recognised from the image name, which is a heuristic and
    /// is meant to be: the alternative is asking every container what it is,
    /// and `postgres:16-alpine` has already answered.
    fileprivate static func composition(project: Project, containers: [DockerContainer]) -> String {
        let total = containers.isEmpty ? project.containerCount : containers.count
        let databases = containers.filter { isDatabaseImage($0.image) }.count
        let services = max(0, total - databases)

        var parts = ["\(Formatting.count(total)) container\(total == 1 ? "" : "s")"]
        if databases > 0 {
            parts.append("\(Formatting.count(databases)) database\(databases == 1 ? "" : "s")")
        }
        if services > 0 {
            parts.append("\(Formatting.count(services)) service\(services == 1 ? "" : "s")")
        }
        return parts.joined(separator: " · ")
    }

    fileprivate static func isDatabaseImage(_ image: String) -> Bool {
        let lowered = image.lowercased()
        let known = ["postgres", "mysql", "mariadb", "mongo", "redis", "valkey", "cockroach", "clickhouse", "timescale"]
        return known.contains { lowered.contains($0) }
    }

    // MARK: - Navigation

    private func honourNavigationRequest() {
        guard let requested = navigation.selectedProjectName else { return }
        selectedProject = requested
        navigation.selectedProjectName = nil
    }

    /// Named `openDetail` rather than `open`: `open` is a Swift access-level
    /// keyword, and a bare call to it at the start of a statement is one more
    /// thing for a reader — and a parser — to disambiguate.
    private func openDetail(_ project: Project) {
        withAnimation(Motion.panel) { selectedProject = project.name }
    }

    private func openInDocker(_ project: Project, container: DockerContainer? = nil) {
        navigation.selectedProjectName = project.name
        navigation.selectedContainerID = container?.id
        navigation.select(section: .docker)
    }

    // MARK: - Restart All

    private var restartConsequence: String {
        guard let project = activeProject else { return "" }
        let members = containers(for: project)
        let names = members.map(\.displayName)
        return "ServerOS will restart \(Formatting.list(names, limit: 6)), one at a time, giving each "
            + "\(ProjectsSection.restartGraceSeconds) seconds to shut down cleanly. \(project.name) will be "
            + "unavailable while they come back up, and any request in flight will fail."
    }

    private func restartAll(_ project: Project) {
        guard let api = session.api else {
            failure = "ServerOS couldn't restart \(project.name). \(ServerOSError.sshNotConnected.headline)"
            return
        }

        let members = containers(for: project)
        guard !members.isEmpty else { return }

        isRestarting = true
        failure = nil

        Task {
            var failed: [String] = []
            for (index, container) in members.enumerated() {
                restartProgress = "Restarting \(container.displayName) — \(index + 1) of \(members.count)…"
                do {
                    try await api.performContainerAction(
                        .restart,
                        id: container.id,
                        graceSeconds: ProjectsSection.restartGraceSeconds
                    )
                } catch {
                    // One container failing should not abandon the rest: a
                    // half-restarted project is worse than a fully restarted
                    // one with a named failure.
                    failed.append(container.displayName)
                }
            }

            restartProgress = nil
            isRestarting = false

            if !failed.isEmpty {
                failure = "ServerOS couldn't restart \(Formatting.list(failed)). Everything else in \(project.name) restarted."
            }

            await session.refreshAll()
            reloadNonce += 1
        }
    }

    // MARK: - Loading

    private struct ProjectsLoad: Equatable {
        let nonce: Int
        let isReady: Bool
        let hasDocker: Bool
    }

    private var loadKey: ProjectsLoad {
        ProjectsLoad(
            nonce: reloadNonce,
            isReady: session.phase.isReady,
            hasDocker: session.capabilities.docker
        )
    }

    private func load() async {
        guard let api = session.api else {
            if state.value == nil { state = .loading }
            return
        }
        guard session.capabilities.docker else {
            state = .unavailable(
                subsystem: "Projects",
                reason: "ServerOS builds projects from Docker Compose labels, and \(session.name) isn't running a "
                    + "Docker daemon that the agent can reach."
            )
            return
        }
        if state.value == nil { state = .loading }

        do {
            let list = try await api.projects()
            let sorted = list.items.sorted {
                $0.name.localizedStandardCompare($1.name) == .orderedAscending
            }
            state = sorted.isEmpty ? .empty : .loaded(sorted)
        } catch let error as ServerOSError {
            state = .failed(error)
        } catch {
            state = .failed(ServerOSError.transport(error, serverName: session.name))
        }
    }
}

// MARK: - Project state

/// Running, Degraded or Stopped.
///
/// `RunPill` has no word for "degraded" — it models things that are simply on
/// or off — and adding one to the design system for a single screen would be
/// the wrong trade. A warning-tinted `Chip` carries the word, which is what the
/// rule about never using colour alone actually asks for.
private struct ProjectStatePill: View {
    let project: Project

    var body: some View {
        if project.isFullyRunning {
            RunPill(.running)
        } else if project.isPartiallyRunning {
            Chip("Degraded", tint: Palette.warning, systemImage: "exclamationmark.triangle.fill")
        } else {
            RunPill(.stopped)
        }
    }
}

// MARK: - Project card

/// One application, as a card you can press.
private struct ProjectCard: View {
    let project: Project
    let containers: [DockerContainer]
    let onOpen: () -> Void
    let onOpenInDocker: () -> Void

    @Environment(\.colorScheme) private var scheme
    @State private var isHovered = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.group) {
            HStack(alignment: .firstTextBaseline, spacing: Spacing.group) {
                Text(project.name)
                    .font(Typography.sectionTitle)
                    .foregroundStyle(Palette.textPrimary)
                    .lineLimit(1)
                ProjectStatePill(project: project)
                Spacer(minLength: Spacing.element)
                Text("\(project.running) of \(project.containerCount) running")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textSecondary)
            }

            Text(ProjectsSection.composition(project: project, containers: containers))
                .font(Typography.secondary)
                .foregroundStyle(Palette.textSecondary)

            if !project.services.isEmpty {
                LazyVGrid(
                    columns: [GridItem(.adaptive(minimum: 84), spacing: Spacing.tight, alignment: .leading)],
                    alignment: .leading,
                    spacing: Spacing.tight
                ) {
                    ForEach(project.services, id: \.self) { service in
                        Chip(service, tint: serviceTint(service))
                    }
                }
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("Services")
                .accessibilityValue(project.services.joined(separator: ", "))
            }

            if let directory = project.workingDir, !directory.isEmpty {
                Text(directory)
                    .font(Typography.codeSmall)
                    .foregroundStyle(Palette.textMuted)
                    .lineLimit(1)
                    .truncationMode(.middle)
                    .textSelection(.enabled)
                    .accessibilityLabel("Working directory")
                    .accessibilityValue(directory)
            }

            Divider().overlay(Palette.divider)

            HStack(spacing: Spacing.element) {
                Button("Open Project", action: onOpen)
                    .buttonStyle(.secondary)
                Button("Open in Docker", action: onOpenInDocker)
                    .buttonStyle(.rowAction)
                Spacer(minLength: 0)
            }
        }
        .padding(Spacing.card)
        .frame(maxWidth: .infinity, alignment: .leading)
        .cardSurface(elevated: isHovered, scheme: scheme)
        .contentShape(RoundedRectangle(cornerRadius: Radius.large, style: .continuous))
        .onHover { hovering in
            withAnimation(Motion.immediate) { isHovered = hovering }
        }
        .onTapGesture(perform: onOpen)
        .accessibilityElement(children: .contain)
        .accessibilityAction(named: Text("Open Project"), onOpen)
    }

    /// Databases read differently from the rest of an application, and colouring
    /// them differently is the fastest way to see "this project has a database".
    private func serviceTint(_ service: String) -> Color {
        let matching = containers.first { $0.composeService == service }
        if let image = matching?.image, ProjectsSection.isDatabaseImage(image) {
            return Palette.informational
        }
        return Palette.inactive
    }
}

// MARK: - Container row

/// One container inside a project.
///
/// The same visual vocabulary as the Docker list — pill, name, image, ports,
/// metrics, uptime — but without the lifecycle actions, which live in Docker.
/// Duplicating the optimistic-action machinery here would be a second
/// implementation of the same behaviour to keep correct.
private struct ProjectContainerRow: View {
    let container: DockerContainer
    let onOpen: () -> Void

    @State private var isHovered = false

    var body: some View {
        HStack(spacing: Spacing.group) {
            RunPill(RunPill.RunState.fromContainer(container.state))
                .frame(width: 96, alignment: .leading)

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
            .frame(minWidth: 130, idealWidth: 220, maxWidth: 300, alignment: .leading)

            Spacer(minLength: Spacing.element)

            portsView

            metric(value: Formatting.percent(container.cpuPercent), label: "CPU", width: 54)
            metric(value: Formatting.bytes(container.memoryBytes), label: "Memory", width: 72)

            Text(uptimeText)
                .font(Typography.metadata)
                .foregroundStyle(Palette.textMuted)
                .lineLimit(1)
                .frame(width: 100, alignment: .trailing)

            Button("Open", action: onOpen)
                .buttonStyle(.rowAction)
                .frame(width: 64, alignment: .trailing)
                .opacity(isHovered ? 1 : 0)
                .allowsHitTesting(isHovered)
                .animation(Motion.immediate, value: isHovered)
                // The row carries the same action for VoiceOver, so a control
                // that is invisible to the eye is not also a trap for the ear.
                .accessibilityHidden(true)
        }
        .padding(.horizontal, Spacing.card)
        .padding(.vertical, Spacing.element)
        .frame(minHeight: Layout.comfortableRowHeight)
        .contentShape(Rectangle())
        .hoverHighlight(radius: Radius.medium)
        .onHover { hovering in
            withAnimation(Motion.immediate) { isHovered = hovering }
        }
        .onTapGesture(perform: onOpen)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(container.displayName), \(RunPill.RunState.fromContainer(container.state).label)")
        .accessibilityValue("\(container.image), \(uptimeText)")
        .accessibilityAction(named: Text("Open in Docker"), onOpen)
    }

    @ViewBuilder
    private var healthMarker: some View {
        if let health = container.health, !health.isEmpty, health != "none" {
            Chip(
                ProjectContainerRow.healthLabel(health),
                tint: ProjectContainerRow.healthTint(health),
                systemImage: health == "healthy" ? "checkmark.seal.fill" : "exclamationmark.triangle.fill"
            )
        }
    }

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
            .accessibilityHidden(true)
        }
    }

    private func metric(value: String, label: String, width: CGFloat) -> some View {
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

    private var uptimeText: String {
        if container.isRunning, let started = container.startedAt, started > 0 {
            let seconds = Int(Date().timeIntervalSince1970) - Int(started)
            return seconds > 0 ? "up \(Formatting.durationCompact(seconds: seconds))" : "just started"
        }
        return Formatting.truncate(
            Formatting.containerState(container.state, status: container.status),
            to: 18
        )
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
}

// MARK: - Activity row

/// One audited event, scoped to this project's containers.
private struct ProjectActivityRow: View {
    let event: ActivityEvent

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.element) {
            Image(systemName: ActivitySymbol.name(for: event.resourceType))
                .font(.system(size: 11))
                .foregroundStyle(event.succeeded ? Palette.textMuted : Palette.critical)
                .frame(width: 16)
                .accessibilityHidden(true)

            VStack(alignment: .leading, spacing: Spacing.hairline) {
                Text(event.summary)
                    .font(Typography.body)
                    .foregroundStyle(Palette.textPrimary)
                    .fixedSize(horizontal: false, vertical: true)
                Text("\(event.actor)  ·  \(Formatting.relative(event.date))")
                    .font(Typography.metadata)
                    .foregroundStyle(Palette.textMuted)
            }

            Spacer(minLength: Spacing.element)

            if !event.succeeded {
                Chip("Failed", tint: Palette.critical, systemImage: "exclamationmark.triangle.fill")
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel(event.summary)
        .accessibilityValue("\(event.succeeded ? "Succeeded" : "Failed"), \(Formatting.relative(event.date))")
    }
}

// MARK: - Preview

private struct ProjectsPreviewHost: View {
    @State private var session = ServerSession(
        demo: DemoEnvironment.shared.servers[0],
        client: DemoEnvironment.shared.client(for: DemoEnvironment.shared.servers[0].id)
            ?? DemoAgentClient(profile: DemoEnvironment.profiles[0])
    )
    @State private var navigation = NavigationModel()

    var body: some View {
        ProjectsSection(session: session, navigation: navigation)
            .background(Palette.background)
            .frame(width: 1000, height: 720)
            .onAppear {
                navigation.enter(serverID: session.id, section: .projects)
                session.connect()
            }
    }
}

#Preview("Projects") {
    ProjectsPreviewHost()
}
